// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2014 Darius Rad <darius@bluespec.com>
 * Copyright (C) 2017 SiFive
 */

#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <asm/cacheflush.h>

#include <asm/sbi.h>

#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/nacc.h>
#include <asm/page.h>
#include <asm/processor.h>

#include <asm/io.h>

extern void nacc_delegate_entry(struct pt_regs *regs,
				unsigned long kind,
				unsigned long cause);

static unsigned long nacc_fixed_agent_base(void)
{
    if (TASK_SIZE < NACC_AGENT_VA_SLOT_END)
        return 0;

    return NACC_AGENT_VA_BASE;
}

static void nacc_activate_current_mm(const char *tag)
{
    unsigned long old_state;

    if (!current->mm)
        return;

    old_state = nacc_mm_state(current->mm);

	if (!(old_state & NACC_MM_ACTIVE)) {
		nacc_mm_set_state(current->mm, NACC_MM_ACTIVE);
		nacc_debug("[Linux]: activate NaCC mm before SBI handoff (%s), mm=%px state %lx -> %lx\n",
		           tag, current->mm, old_state, nacc_mm_state(current->mm));
	}
}

static void nacc_fail_fork_child_attach(const char *reason, long err,
                                        unsigned long pid,
                                        unsigned long cid)
{
    unsigned long mm_state = current->mm ? nacc_mm_state(current->mm) : 0;

    printk(KERN_ERR "[Linux]: fatal fork child attach failure: reason=%s err=%ld"
           " pid=%lu pid_vnr=%d tgid_vnr=%d cid=%lx mm=%px flag=%lx mm_state=%lx\n",
           reason, err, pid, task_pid_vnr(current), task_tgid_vnr(current), cid,
           current->mm, current->thread.nacc_flag, mm_state);

    /*
     * Do not leave the task in a half-attached NACC_FORKED state, otherwise
     * later notify-resume hooks may retry attach and drift further.
     */
    current->thread.nacc_flag = 0;
    force_exit_sig(SIGKILL);
}

static inline bool nacc_trace_mmap_syscall(void)
{
	return current->mm &&
	       (nacc_mm_is_active(current->mm) || nacc_thread_is_inited());
}

static void nacc_log_sys_mmap(const char *tag, unsigned long addr,
			      unsigned long len, unsigned long prot,
			      unsigned long flags, unsigned long fd,
			      off_t offset, unsigned long page_shift_offset,
			      long ret)
{
	if (!nacc_trace_mmap_syscall())
		return;

	nacc_debug("[Linux]: %s pid=%d mm=%px flag=%lx mm_state=%lx "
		   "addr=%lx len=%lx prot=%lx flags=%lx fd=%lx offset=%llx "
		   "shift=%lu ret=%ld\n",
		   tag, current->pid, current->mm, current->thread.nacc_flag,
		   nacc_mm_state(current->mm), addr, len, prot, flags, fd,
		   (unsigned long long)offset, page_shift_offset, ret);
}

int nacc_reserve_agent_slot_mm(struct mm_struct *mm, const char *tag)
{
    unsigned long virt_agent;
    unsigned long virt_end;
    struct vm_area_struct *vma;
    struct vm_area_struct *conflict;
    int ret;

    virt_agent = nacc_fixed_agent_base();
    virt_end = virt_agent + NACC_AGENT_VA_SLOT_SIZE;
    if (!virt_agent || virt_end > TASK_SIZE) {
        printk(KERN_ERR "[Linux]: invalid fixed NACC agent slot (%s): [%lx, %lx) task_size=%lx\n",
               tag, virt_agent, virt_end, TASK_SIZE);
        return -EINVAL;
    }

    ret = mmap_write_lock_killable(mm);
    if (ret)
        return ret;

    conflict = find_vma_intersection(mm, virt_agent, virt_end);
    if (conflict) {
        if (conflict->vm_start == virt_agent && conflict->vm_end == virt_end &&
            (conflict->vm_flags & VM_NACC)) {
            mmap_write_unlock(mm);
            return 0;
        }

        printk(KERN_ERR "[Linux]: fixed NACC agent slot is occupied (%s): [%lx, %lx) conflicts with VMA [%lx, %lx)\n",
               tag, virt_agent, virt_end, conflict->vm_start, conflict->vm_end);
        mmap_write_unlock(mm);
        return -EEXIST;
    }

    vma = vm_area_alloc(mm);
    if (!vma) {
        printk(KERN_ERR "[Linux]: failed to allocate VMA for NACC agent (%s).\n",
               tag);
        mmap_write_unlock(mm);
        return -ENOMEM;
    }

    vma->vm_start = virt_agent;
    vma->vm_end = virt_end;

    /*
     * Reserve one full SV39 VPN[2] slot (1 GiB). OpenSBI will only map the
     * first NACC_AGENT_LINEAR_SIZE bytes with actual agent PTEs; the rest stays
     * as guard hole so ELF/mmap do not share the same top-level slot.
     */
    vm_flags_init(vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_NACC);
    vma->vm_page_prot = pgprot_noncached(PAGE_NONE);

    ret = insert_vm_struct(mm, vma);
    if (ret) {
        printk(KERN_ERR "[Linux]: failed to insert VMA for NACC agent slot (%s), ret=%d.\n",
               tag, ret);
        mmap_write_unlock(mm);
        vm_area_free(vma);
        return ret;
    }

    mmap_write_unlock(mm);

    nacc_debug("[Linux]: reserved fixed NACC agent slot (%s): [%lx, %lx), active agent range [%lx, %lx), mm state unchanged=%lx\n",
               tag, virt_agent, virt_end, virt_agent,
               virt_agent + NACC_AGENT_LINEAR_SIZE, nacc_mm_state(mm));

    return 0;
}

static int nacc_insert_agent_vma(unsigned long *virt_agent_out,
                                 const char *tag)
{
	unsigned long virt_agent;
	unsigned long slot_end;
	struct vm_area_struct *slot;
	bool slot_valid;
	int ret;

	virt_agent = nacc_fixed_agent_base();
	slot_end = virt_agent + NACC_AGENT_VA_SLOT_SIZE;
	if (!virt_agent || slot_end > TASK_SIZE)
		return -EINVAL;

	ret = nacc_reserve_agent_slot_mm(current->mm, tag);
	if (ret)
		return ret;

	mmap_read_lock(current->mm);
	slot = find_vma_intersection(current->mm, virt_agent, slot_end);
	slot_valid = slot && slot->vm_start == virt_agent &&
		     slot->vm_end == slot_end && (slot->vm_flags & VM_NACC);
	mmap_read_unlock(current->mm);

	if (!slot_valid) {
		printk(KERN_ERR "[Linux]: fixed NACC agent slot missing or malformed (%s): expected [%lx, %lx)\n",
		       tag, virt_agent, slot_end);
		return -ENOMEM;
	}

	*virt_agent_out = virt_agent;
	return 0;
}

static void __nacc_invoke_full(unsigned long sbi_fid, const char *tag)
{
    unsigned long pid = current->pid;
    unsigned long current_gp = 0;
    unsigned long virt_agent = 0;
    struct pt_regs *regs = task_pt_regs(current);

    /*
     * Full invoke path:
     * - insert a fresh VM_NACC VMA in the new mm
     * - enter OpenSBI with complete host/trap context so agent-side
     *   state gets refreshed before the next user trap
     */
    current->thread.nacc_flag = NACC_INITED;

    if (nacc_insert_agent_vma(&virt_agent, tag))
        return;

    nacc_debug("[Linux]: %s using virt_agent %lx\n", tag, virt_agent);

    nacc_activate_current_mm(tag);
    if (nacc_detach_user_leaf_pages(current->mm, tag))
        return;

    /*
     * RISC-V ELF startup treats entry a0 as rtld_fini. At this point the
     * execve syscall frame still carries the pre-dispatch -ENOSYS sentinel;
     * clear it before the direct agent-to-user entry.
     */
    regs->a0 = 0;

    asm volatile("mv %0, gp" : "=r"(current_gp));

    sbi_ecall(SBI_EXT_NACC, sbi_fid, virt_agent, pid, (unsigned long) regs,
              (unsigned long) nacc_delegate_entry,
              current_gp, 0);
}


static long riscv_sys_mmap(unsigned long addr, unsigned long len,
			   unsigned long prot, unsigned long flags,
			   unsigned long fd, off_t offset,
			   unsigned long page_shift_offset)
{
	long ret;

	nacc_log_sys_mmap("riscv_sys_mmap: enter", addr, len, prot, flags, fd,
			  offset, page_shift_offset, 0);

	if (unlikely(offset & (~PAGE_MASK >> page_shift_offset))) {
		nacc_log_sys_mmap("riscv_sys_mmap: bad offset", addr, len, prot,
				  flags, fd, offset, page_shift_offset,
				  -EINVAL);
		return -EINVAL;
	}

	ret = ksys_mmap_pgoff(addr, len, prot, flags, fd,
			     offset >> (PAGE_SHIFT - page_shift_offset));
	nacc_log_sys_mmap("riscv_sys_mmap: return", addr, len, prot, flags, fd,
			  offset, page_shift_offset, ret);
	return ret;
}

#ifdef CONFIG_64BIT
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
{
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 0);
}
#endif

#if defined(CONFIG_32BIT) || defined(CONFIG_COMPAT)
SYSCALL_DEFINE6(mmap2, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
{
	/*
	 * Note that the shift for mmap2 is constant (12),
	 * regardless of PAGE_SIZE
	 */
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 12);
}
#endif

/*
 * Allows the instruction cache to be flushed from userspace.  Despite RISC-V
 * having a direct 'fence.i' instruction available to userspace (which we
 * can't trap!), that's not actually viable when running on Linux because the
 * kernel might schedule a process on another hart.  There is no way for
 * userspace to handle this without invoking the kernel (as it doesn't know the
 * thread->hart mappings), so we've defined a RISC-V specific system call to
 * flush the instruction cache.
 *
 * sys_riscv_flush_icache() is defined to flush the instruction cache over an
 * address range, with the flush applying to either all threads or just the
 * caller.  We don't currently do anything with the address range, that's just
 * in there for forwards compatibility.
 */
SYSCALL_DEFINE3(riscv_flush_icache, uintptr_t, start, uintptr_t, end,
	uintptr_t, flags)
{
	/* Check the reserved flags. */
	if (unlikely(flags & ~SYS_RISCV_FLUSH_ICACHE_ALL))
		return -EINVAL;

	flush_icache_mm(current->mm, flags & SYS_RISCV_FLUSH_ICACHE_LOCAL);

	return 0;
}

void nacc_invoke(void)
{
    nacc_debug("[Linux]: start_thread is invoked for NACC process. \n");
    __nacc_invoke_full(SBI_EXT_NACC_INVOKE, "nacc_invoke");
}

void nacc_exec(void)
{
    unsigned long pid = current->pid;
    unsigned long virt_agent = 0;
    struct pt_regs *regs = task_pt_regs(current);
    struct sbiret ret;

    /*
     * Exec attach is shared by same-PID re-exec and fork+exec after the
     * fresh exec mm has been built by Linux:
     * - install a fresh VM_NACC VMA for the new mm
     * - hand the new user pt_regs to OpenSBI
     * Trap-context refresh inside agent/OpenSBI is handled separately.
     */
    nacc_debug("[Linux]: NACC_EXEC preparing minimal reattach path.\n");

    if (nacc_insert_agent_vma(&virt_agent, "nacc_exec"))
        return;

    nacc_debug("[Linux]: nacc_exec using virt_agent %lx\n", virt_agent);

    /*
     * Re-exec now follows the same "non-returning" shape as nacc_invoke():
     * OpenSBI enters the agent and the agent returns directly to userspace.
     * Set INITED before the SBI transition so later kernel entries don't keep
     * seeing the transient REEXEC flag forever.
     */
    nacc_activate_current_mm("nacc_exec");
    current->thread.nacc_flag = NACC_INITED;
    if (nacc_detach_user_leaf_pages(current->mm, "nacc_exec")) {
        current->thread.nacc_flag = NACC_EXEC;
        return;
    }
    /* Same RISC-V exec-entry a0 contract as the initial invoke path. */
    regs->a0 = 0;

    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REEXEC, virt_agent, pid,
                    (unsigned long) regs, 0, 0, 0);

    if (ret.error) {
        current->thread.nacc_flag = NACC_EXEC;
        printk(KERN_ERR "[Linux]: nacc_exec SBI returned unexpectedly with error %ld\n",
               ret.error);
    }
}

void nacc_invoke_child(void)
{
    /*
     * For fork + exec cases only.
     * Linux already built the fresh child exec mm using secure non-leaf PTPs.
     * We only need to:
     * 1. Register child PID with parent's CID (done in OpenSBI)
     * 2. Let OpenSBI validate that secure user PTP build and refresh metadata
     * 3. Map agent region into child's address space (done in OpenSBI)
     * No agent jump needed — child stays in Linux.
     */
    unsigned long pid = current->pid;
    unsigned long virt_agent = 0;
    unsigned long cid = current->thread.nacc_cid;
    struct pt_regs *regs = task_pt_regs(current);

    nacc_debug("[Linux]: NaCC re-attach process, pid=%lu, cid=%lx\n",
               pid, cid);

    if (nacc_insert_agent_vma(&virt_agent, "nacc_invoke_child"))
        return;

    nacc_debug("[Linux]: Child re-attach uses fixed virt_agent %lx\n",
               virt_agent);

    /* Call into OpenSBI to register child, validate secure user PTPs, and map agent.
     * We pass the cid explicitly to allow OpenSBI to register this child properly.
     * The remaining args are unused since we don't jump into agent. */
    nacc_activate_current_mm("nacc_invoke_child");
    if (nacc_detach_user_leaf_pages(current->mm, "nacc_invoke_child"))
        return;
    /* Same RISC-V exec-entry a0 contract as the initial invoke path. */
    regs->a0 = 0;
    sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE_CHILD, virt_agent, pid,
              cid, 0, 0, 0);

    /*
     * Mark as INITED only after OpenSBI re-attach completes and NACC_STATE
     * has been switched to LINUX in M-mode.
     */
    current->thread.nacc_flag = NACC_INITED;

    nacc_debug("[Linux]: nacc_invoke_child done, child continues in Linux.\n");
}

void nacc_attach_forked_child_if_needed(void)
{
    unsigned long pid;
    unsigned long cid;
    unsigned long virt_agent = 0;
    unsigned long user_pt_regs = 0;
    int vma_ret;
    int detach_ret;
    struct sbiret ret;

    if (current->thread.nacc_flag != NACC_FORKED)
        return;

    if (!current->mm) {
        printk(KERN_ERR "[Linux]: skip fork child attach without mm, pid=%d flag=%lx\n",
               current->pid, current->thread.nacc_flag);
        nacc_fail_fork_child_attach("missing-mm", -EINVAL, current->pid,
                                    current->thread.nacc_cid);
        return;
    }

    pid = current->pid;
    cid = current->thread.nacc_cid;
    user_pt_regs = (unsigned long)task_pt_regs(current);

    nacc_debug("[Linux]: first user return attaches fork child, pid=%lu cid=%lx nacc_flag=%lx mm=%px regs=%px state=%lx epc=%lx sp=%lx ra=%lx tp=%lx a0=%lx a1=%lx a2=%lx a3=%lx a0_is_zero=%s\n",
               pid, cid, current->thread.nacc_flag, current->mm,
               (void *)user_pt_regs, nacc_mm_state(current->mm),
               task_pt_regs(current)->epc, task_pt_regs(current)->sp,
               task_pt_regs(current)->ra, task_pt_regs(current)->tp,
               task_pt_regs(current)->a0, task_pt_regs(current)->a1,
               task_pt_regs(current)->a2, task_pt_regs(current)->a3,
               task_pt_regs(current)->a0 == 0 ? "yes" : "no");

    vma_ret = nacc_insert_agent_vma(&virt_agent, "nacc_attach_forked_child");
    if (vma_ret) {
        printk(KERN_ERR "[Linux]: failed to insert VM_NACC slot for fork child pid=%lu\n",
               pid);
        nacc_fail_fork_child_attach("insert-agent-vma", vma_ret, pid, cid);
        return;
    }

    nacc_activate_current_mm("nacc_attach_forked_child");
    /*
     * Child attach now follows the same non-returning lightweight agent shape
     * as exec attach: OpenSBI enters the agent and the agent returns directly
     * to userspace after refreshing the trap contract for this child.
     */
    current->thread.nacc_flag = NACC_INITED;
    detach_ret = nacc_detach_user_leaf_pages(current->mm,
                                             "nacc_attach_forked_child");
    if (detach_ret) {
        current->thread.nacc_flag = NACC_FORKED;
        nacc_fail_fork_child_attach("detach-user-leaves", detach_ret, pid, cid);
        return;
    }

    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_ATTACH_FORKED_CHILD,
                    virt_agent, pid, cid, user_pt_regs, 0, 0);
    if (ret.error) {
        current->thread.nacc_flag = NACC_FORKED;
        printk(KERN_ERR "[Linux]: fork child attach SBI failed, pid=%lu cid=%lx err=%ld\n",
               pid, cid, ret.error);
        nacc_fail_fork_child_attach("sbi-attach", ret.error, pid, cid);
        return;
    }

    current->thread.nacc_flag = NACC_FORKED;
    printk(KERN_ERR "[Linux]: fork child attach unexpectedly returned, pid=%lu cid=%lx virt_agent=%lx\n",
           pid, cid, virt_agent);
    nacc_fail_fork_child_attach("sbi-attach-return", -EIO, pid, cid);
}

void nacc_register_forked_child_pid(unsigned long child_pid)
{
    unsigned long cid = current->thread.nacc_cid;
    struct sbiret ret;

    if (!(current->thread.nacc_flag & NACC_INITED))
        return;

    if (!cid || !child_pid) {
        printk(KERN_ERR "[Linux]: skip fork child pid registration: parent pid=%d child_pid=%lu cid=%lx flag=%lx\n",
               current->pid, child_pid, cid, current->thread.nacc_flag);
        return;
    }

    nacc_debug("[Linux]: register fork child pid early, parent pid=%d child_pid=%lu cid=%lx\n",
               current->pid, child_pid, cid);

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGISTER, cid, child_pid,
			0, 0, 0, 0);
    if (ret.error) {
        printk(KERN_ERR "[Linux]: early fork child pid registration failed: parent pid=%d child_pid=%lu cid=%lx err=%ld val=%ld\n",
               current->pid, child_pid, cid, ret.error, ret.value);
    }
}

void nacc_unregister_current_pid(void)
{
    unsigned long pid = task_pid_nr(current);
    struct sbiret ret;

	if (!current->thread.nacc_cid || !pid) {
		return;
	}

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UNREGISTER, pid,
			0, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc unregister failed: pid=%lu cid=%lx err=%ld val=%ld\n",
		       pid, current->thread.nacc_cid, ret.error, ret.value);
		return;
	}

	nacc_debug("[Linux]: nacc unregister pid=%lu cid=%lx\n",
		   pid, current->thread.nacc_cid);
}

void nacc_import_user_leaf_sbi(unsigned long ptep_pa,
			       unsigned long source_pteval,
			       unsigned long destination_pfn,
			       unsigned long start_va,
			       unsigned long root_pgd_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_SET_PTES, ptep_pa,
			source_pteval, 1, start_va, root_pgd_pa,
			destination_pfn);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_import_user_leaf_sbi failed: ptep_pa=%lx source_pteval=%lx destination_pfn=%lx start_va=%lx root=%lx err=%ld val=%ld\n",
		       ptep_pa, source_pteval, destination_pfn, start_va,
		       root_pgd_pa, ret.error, ret.value);
		panic("NaCC secure user leaf import protocol failure");
	}
}

void nacc_fresh_zero_leaf_sbi(unsigned long ptep_pa, unsigned long pteval,
			      unsigned long start_va,
			      unsigned long root_pgd_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_FRESH_ZERO_LEAF,
			ptep_pa, pteval, start_va, root_pgd_pa, 0, 0);
	if (ret.error) {
		pr_err("[Linux]: fresh-zero leaf SBI failed: ptep_pa=%lx pteval=%lx start_va=%lx root=%lx err=%ld val=%ld\n",
		       ptep_pa, pteval, start_va, root_pgd_pa, ret.error,
		       ret.value);
		panic("NaCC fresh-zero leaf transaction failed");
	}
}

int nacc_detach_agent_slot_sbi(unsigned long root_pgd_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC,
			SBI_EXT_NACC_RECLAIM_AGENT_REGION,
			root_pgd_pa, 0, 0, 0, 0, 0);
	if (ret.error) {
		if (ret.error == SBI_ERR_ALREADY_AVAILABLE)
			return -EAGAIN;
		printk(KERN_ERR "[Linux]: fixed Agent-slot detach failed: root=%lx err=%ld val=%ld\n",
		       root_pgd_pa, ret.error, ret.value);
		panic("NaCC fixed Agent-slot detach failed");
	}

	return 0;
}

void nacc_flush_and_drain_sbi(struct mm_struct *mm)
{
	struct sbiret ret;
	unsigned long root_pgd_pa;

	if (!mm || !nacc_mm_root_tagged(mm))
		panic("NaCC gather drain requested for untagged mm");

	root_pgd_pa = virt_to_phys(mm->pgd);
	do {
		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_FLUSH_AND_DRAIN,
				root_pgd_pa, 0, 0, 0, 0, 0);
		if (ret.error == SBI_ERR_ALREADY_AVAILABLE)
			cpu_relax();
	} while (ret.error == SBI_ERR_ALREADY_AVAILABLE);

	if (ret.error) {
		printk(KERN_ERR "[Linux]: legacy Agent gather flush/drain failed: root=%lx err=%ld val=%ld\n",
		       root_pgd_pa, ret.error, ret.value);
		panic("NaCC legacy Agent gather flush/drain failed");
	}
}

unsigned long nacc_update_pte_sbi(unsigned long op, unsigned long ptep_pa,
				  unsigned long operand, unsigned long start_va,
				  unsigned long root_pgd_pa,
				  unsigned long flags)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UPDATE_PTE, op, ptep_pa,
			operand, start_va, root_pgd_pa, flags);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_update_pte_sbi failed: op=%lu ptep_pa=%lx operand=%lx start_va=%lx root=%lx flags=%lx err=%ld val=%ld\n",
		       op, ptep_pa, operand, start_va, root_pgd_pa, flags,
		       ret.error, ret.value);
		panic("NaCC secure PTE update ecall failed");
	}

	return ret.value;
}

int nacc_record_vvar_sbi(unsigned long root_pgd_pa, unsigned long addr,
			 unsigned long pfn)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RECORD_VVAR,
			root_pgd_pa, addr, pfn, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_record_vvar_sbi failed: root=%lx addr=%lx pfn=%lx err=%ld val=%ld\n",
		       root_pgd_pa, addr, pfn, ret.error, ret.value);
		return -EIO;
	}

	nacc_debug("[Linux]: nacc_record_vvar_sbi ok: root=%lx addr=%lx pfn=%lx val=%ld\n",
		   root_pgd_pa, addr, pfn, ret.value);
	return 0;
}

int nacc_adopt_vdso_sbi(unsigned long root_pgd_pa, unsigned long addr,
			unsigned long nr_pages, unsigned long source_pfns_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_ADOPT_VDSO,
			root_pgd_pa, addr, nr_pages, source_pfns_pa, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_adopt_vdso_sbi failed: root=%lx addr=%lx nr_pages=%lx pfns_pa=%lx err=%ld val=%ld\n",
		       root_pgd_pa, addr, nr_pages, source_pfns_pa,
		       ret.error, ret.value);
		return -EIO;
	}

	return 0;
}

int nacc_tag_root_sbi(unsigned long pgd_pa, unsigned long cid)
{
	struct sbiret ret;

	if (!pgd_pa || !cid)
		return -EINVAL;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_TAG_ROOT, pgd_pa,
			cid, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_tag_root_sbi failed: pgd_pa=%lx cid=%lx err=%ld val=%ld\n",
		       pgd_pa, cid, ret.error, ret.value);
		return -EIO;
	}

	return 0;
}

int nacc_fork_window_check_sbi(void)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_FORK_WINDOW_CHECK,
			0, 0, 0, 0, 0, 0);
	return ret.error ? -EOPNOTSUPP : 0;
}

int nacc_fork_select_child_root_sbi(unsigned long pgd_pa)
{
	struct sbiret ret;

	if (!pgd_pa)
		return -EINVAL;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_FORK_SELECT_CHILD,
			pgd_pa, 0, 0, 0, 0, 0);
	if (ret.error) {
		nacc_debug("[Linux]: fork child root selection denied: pgd_pa=%lx err=%ld val=%ld\n",
			   pgd_pa, ret.error, ret.value);
		return -EIO;
	}
	return 0;
}

void nacc_retire_root_sbi(unsigned long pgd_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RETIRE_ROOT, pgd_pa,
			0, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_retire_root_sbi failed: pgd_pa=%lx err=%ld val=%ld\n",
		       pgd_pa, ret.error, ret.value);
		panic("NaCC ROOT_L0 retirement protocol failure");
	}

}

int nacc_acquire_private_pfn_sbi(unsigned long pfn)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_ACQUIRE_PRIVATE_PFN,
			pfn, 0, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_acquire_private_pfn_sbi failed: pfn=%lx err=%ld val=%ld\n",
		       pfn, ret.error, ret.value);
		return -EIO;
	}

	return ret.value;
}

int nacc_release_private_pfn_sbi(unsigned long pfn)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RETIRE_PRIVATE_PFN,
			pfn, 0, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacc_release_private_pfn_sbi failed: pfn=%lx err=%ld val=%ld\n",
		       pfn, ret.error, ret.value);
		return -EIO;
	}

	return ret.value;
}

int nacc_retire_private_pfn_sbi(unsigned long pfn)
{
	return nacc_release_private_pfn_sbi(pfn);
}

/* Not defined using SYSCALL_DEFINE0 to avoid error injection */
asmlinkage long __riscv_sys_ni_syscall(const struct pt_regs *__unused)
{
	return -ENOSYS;
}
