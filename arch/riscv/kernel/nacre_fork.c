// SPDX-License-Identifier: GPL-2.0-only
/* Native task/mm ownership with private copy and child context owned by M/AS. */
#include <linux/entry-common.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <asm/nacc.h>
#include <asm/nacre_registration.h>
#include <asm/nacre_ptp.h>
#include <asm/sbi.h>
#include <asm/uaccess.h>

void nacre_activate(void)
{
    BUG_ON(sbi_ecall(NACRE_SBI_REGISTER_EXT, 24, task_pid_vnr(current), 0, 0, 0, 0, 0).error);
}

int nacre_fork_mm_prepare(struct mm_struct *mm)
{
    unsigned long address, capacity;
    int rc = nacre_exec_reserve(mm);
    if (rc) return rc;
    rc = nacre_buffer_fork_prepare(mm, &address, &capacity);
    if (rc) return rc;
    /* vDSO/VVAR records cannot be inherited from a different root-instance. */
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, mm, 0);
    mmap_write_lock(mm);
    for_each_vma(vmi, vma) {
        if (!nacc_vma_is_vdso_text(vma)) continue;
        rc = nacc_adopt_vdso_text(vma);
        break;
    }
    mmap_write_unlock(mm);
    return rc;
}

void nacre_fork_publish(struct task_struct *child)
{
    struct mm_struct *mm = child->mm;
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, mm, 0);
    unsigned long address = 0, capacity = 0, limit = 0, flags;
    bool thread = mm == current->mm;
    if (thread) nacre_buffer_thread_prepare(child);
    mmap_read_lock(mm);
    for_each_vma(vmi, vma)
        if (nacre_buffer_vma(vma) && (!thread || vma->vm_start == child->thread.nacre_buffer)) {
            address = vma->vm_start;
            capacity = nacre_buffer_capacity(vma);
            limit = vma->vm_end - vma->vm_start;
            break;
        }
    BUG_ON(!address || !capacity || !nacre_mm_private(mm));
    local_irq_save(flags);
    unsigned long entry = current->thread.nacre_entry;
    if (!thread) {
        struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 0x41, __pa(mm->pgd),
                                      address, capacity, task_pid_vnr(child), limit, 0);
        BUG_ON(ret.error);
        entry = ret.value;
        mm->context.nacre_prepared = 1;
    }
    child->thread.nacre_buffer = address;
    child->thread.nacre_cid = current->thread.nacre_cid;
    child->thread.nacre_entry = entry;
    child->thread.nacre_flag = NACRE_FORK_CHILD;
    unsigned long descriptor[5] = {child->pid, (unsigned long)task_pt_regs(child),
                                   (unsigned long)child, __pa(mm->pgd), task_pid_vnr(child)};
    /* Ordinary fork inherits the VA; shared-mm threads own distinct leases. */
    address = current->thread.nacre_buffer;
    /* IRQs are disabled; the resident parent buffer must already be writable. */
    BUG_ON(copy_to_user_nofault((void __user *)address, descriptor, sizeof(descriptor)));
    nacre_activate();
    nacre_fork_asm(current->thread.nacre_cid, current->pid, current_pt_regs());
    local_irq_restore(flags);
    mmap_read_unlock(mm);
    asm volatile(".global nacre_fork_published\nnacre_fork_published: nop" ::: "memory");
}

/* ret_from_fork owns a public, synthetic U frame; AS owns the actual child PC/GPRs. */
void noinstr nacre_fork_child_return(void)
{
    if (current->thread.nacre_flag != NACRE_FORK_CHILD) return;
    struct pt_regs *regs = current_pt_regs();
    syscall_exit_to_user_mode(regs);
    asm volatile("mv a0, %0\nj nacre_exec_handoff_asm" : : "r"(regs) : "a0", "memory");
    __builtin_unreachable();
}
