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
    BUG_ON(sbi_ecall(NACRE_SBI_REGISTER_EXT, 24, 0, 0, 0, 0, 0, 0).error);
}

int nacre_fork_mm_prepare(struct mm_struct *mm)
{
    unsigned long address, capacity;
    int rc = nacre_exec_reserve(mm);
    if (rc) return rc;
    rc = nacre_buffer_fork_pin(mm, &address, &capacity);
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
    unsigned long address = 0, capacity = 0, flags;
    mmap_read_lock(mm);
    for_each_vma(vmi, vma)
        if (nacre_buffer_vma(vma)) {
            address = vma->vm_start;
            capacity = vma->vm_end - vma->vm_start;
            break;
        }
    BUG_ON(!address || !capacity || !nacre_mm_private(mm));
    local_irq_save(flags);
    struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 0x41, __pa(mm->pgd),
                                  address, capacity, task_pid_vnr(child), 0, 0);
    BUG_ON(ret.error);
    mm->context.nacre_prepared = 1;
    child->thread.nacre_cid = current->thread.nacre_cid;
    child->thread.nacre_entry = ret.value;
    child->thread.nacre_flag = NACRE_FORK_CHILD;
    unsigned long descriptor[4] = {child->pid, (unsigned long)task_pt_regs(child),
                                   (unsigned long)child, __pa(mm->pgd)};
    /* The child inherits the same buffer VA and has independent ordinary PFNs. */
    BUG_ON(copy_to_user((void __user *)address, descriptor, sizeof(descriptor)));
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
    instrumentation_begin();
    nacre_activate();
    instrumentation_end();
    syscall_exit_to_user_mode(regs);
    asm volatile("mv a0, %0\nj nacre_exec_handoff_asm" : : "r"(regs) : "a0", "memory");
    __builtin_unreachable();
}
