// SPDX-License-Identifier: GPL-2.0-only
#include <linux/binfmts.h>
#include <linux/entry-common.h>
#include <linux/mm.h>
#include <linux/irqflags.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <asm/nacc.h>
#include <asm/nacre_registration.h>
#include <asm/nacre_ptp.h>
#include <asm/sbi.h>
#include <asm/csr.h>
#include <asm/unistd.h>

#define NACRE_VMA_FLAGS (VM_IO | VM_PFNMAP | VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP)

/* Distinguish our reservation from an unrelated inaccessible mapping. */
static const struct vm_operations_struct nacre_reservation_ops;

SYSCALL_DEFINE1(nacre_register, unsigned long, cid)
{
	if (!cid || cid >> 48 || !current->mm ||
	    TASK_SIZE < NACC_AGENT_VA_SLOT_END || (csr_read(CSR_SATP) >> 60) != 8)
		return -EINVAL;
	if (current->thread.nacre_flag != NACRE_IDLE ||
	    current->thread.nacc_flag || current->thread.nacc_cid)
		return -EBUSY;
	if (current->ptrace || signal_pending(current))
		return -EOPNOTSUPP;
	BUG_ON(!user_mode(current_pt_regs()) || current->thread.nacre_cid ||
	       current->thread.nacre_entry);
	current->thread.nacre_cid = cid;
	current->thread.nacre_flag = NACRE_REQUESTED;
	asm volatile(".global nacre_register_requested\n"
		     "nacre_register_requested: nop" ::: "memory");
	return 0;
}

int nacre_exec_reserve(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	int ret;

	if (current->thread.nacre_flag == NACRE_IDLE)
		return 0;
	BUG_ON(current->thread.nacre_flag != NACRE_REQUESTED || mm == current->mm);
	ret = mmap_write_lock_killable(mm);
	if (ret)
		return ret;
	if (find_vma_intersection(mm, NACC_AGENT_VA_BASE, NACC_AGENT_VA_SLOT_END))
		panic("NACRE reservation conflict");
	vma = vm_area_alloc(mm);
	if (!vma) {
		ret = -ENOMEM;
		goto unlock;
	}
	vma->vm_start = NACC_AGENT_VA_BASE;
	vma->vm_end = NACC_AGENT_VA_SLOT_END;
	vm_flags_init(vma, NACRE_VMA_FLAGS);
	vma->vm_page_prot = PAGE_NONE;
	vma->vm_ops = &nacre_reservation_ops;
	ret = insert_vm_struct(mm, vma);
	if (ret) {
		vm_area_free(vma);
		goto unlock;
	}
	vm_stat_account(mm, vma->vm_flags, vma_pages(vma));
unlock:
	mmap_write_unlock(mm);
	return ret;
}

void nacre_exec_cancel(void)
{
	if (current->thread.nacre_flag == NACRE_IDLE)
		return;
	BUG_ON(current->thread.nacre_flag != NACRE_REQUESTED);
	current->thread.nacre_cid = 0;
	current->thread.nacre_entry = 0;
	current->thread.nacre_flag = NACRE_IDLE;
}

/* Called by exec after the binary handler has committed mm and start_thread(). */
void nacre_exec_prepare(struct linux_binprm *bprm)
{
	struct mm_struct *mm = current->mm;
	struct pt_regs *regs = current_pt_regs();
	struct vm_area_struct *vma;
	struct sbiret sbi_ret;
	unsigned long flags;

	if (current->thread.nacre_flag == NACRE_IDLE)
		return;
	BUG_ON(current->thread.nacre_flag != NACRE_REQUESTED ||
	       !bprm->point_of_no_return || bprm->mm || !mm ||
	       !nacre_mm_managed(mm) || mm->context.nacre_cid != current->thread.nacre_cid ||
	       current->active_mm != mm ||
	       !user_mode(regs) || current->ptrace);
	/* Materialize the successful exec return value in the initial app frame. */
	regs->a0 = 0;
	mmap_read_lock(mm);
	asm volatile(".global nacre_exec_check_reservation\n"
		     "nacre_exec_check_reservation: nop" ::: "memory");
	vma = find_vma_intersection(mm, NACC_AGENT_VA_BASE, NACC_AGENT_VA_SLOT_END);
	if (!vma || vma->vm_start != NACC_AGENT_VA_BASE ||
	    vma->vm_end != NACC_AGENT_VA_SLOT_END || vma->vm_flags != NACRE_VMA_FLAGS ||
	    vma->vm_ops != &nacre_reservation_ops || vma->vm_file ||
	    pgprot_val(vma->vm_page_prot) != pgprot_val(PAGE_NONE))
		panic("NACRE exec reservation changed");
	/* PREPARE uses only the committed live root, after the initial frame is ready. */
	local_irq_save(flags);
	sbi_ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_SBI_PREPARE,
			    0, 0, 0, 0, 0, 0);
	if (sbi_ret.error || sbi_ret.value < NACC_AGENT_VA_BASE ||
	    sbi_ret.value >= NACC_AGENT_VA_SLOT_END || (sbi_ret.value & 3))
		panic("NACRE prepare failed: error=%ld entry=%lx",
		      sbi_ret.error, sbi_ret.value);
	current->thread.nacre_entry = sbi_ret.value;
	current->thread.nacre_flag = NACRE_PREPARED;
	asm volatile(".global nacre_exec_prepared\n"
		     "nacre_exec_prepared: nop" ::: "memory");
	local_irq_restore(flags);
	mmap_read_unlock(mm);
}

/* Exec has released bprm and filename before taking this continuation. */
void noinstr __noreturn nacre_exec_handoff(void)
{
	struct pt_regs *regs = current_pt_regs();

	instrumentation_begin();
	BUG_ON(current->thread.nacre_flag != NACRE_PREPARED ||
	       current->ptrace ||
	       regs->cause != EXC_SYSCALL || regs->a0 || !user_mode(regs));
	instrumentation_end();
	/* Pending signals are normal exec races; the native exit path consumes them. */
	syscall_exit_to_user_mode(regs);
	asm volatile("mv a0, %0\n"
		     "j nacre_exec_handoff_asm"
		     : : "r"(regs) : "a0", "memory");
	__builtin_unreachable();
}

/* Exec itself handles its failures; a filtered syscall never entered exec. */
void nacre_user_return_prepare(struct pt_regs *regs)
{
	if (current->thread.nacre_flag == NACRE_REQUESTED &&
	    regs->cause == EXC_SYSCALL &&
	    (regs->a7 == __NR_execve || regs->a7 == __NR_execveat)) {
		BUG_ON((long)regs->a0 >= 0);
		nacre_exec_cancel();
	}
	if (current->thread.nacre_flag == NACRE_PREPARED)
		BUG_ON(current->ptrace ||
		       regs->a0 || !user_mode(regs));
}
