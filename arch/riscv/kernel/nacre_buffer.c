// SPDX-License-Identifier: GPL-2.0-only
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <asm/nacre_registration.h>
#include <asm/sbi.h>
#include <asm/nacc.h>
#include <asm/vdso.h>

/* Fixed for each exec; pages need not be physically contiguous. */
static unsigned long buffer_pages = 256;
module_param_named(nacre_buffer_pages, buffer_pages, ulong, 0400);

struct nacre_buffer {
    unsigned long count;
    struct page *pages[];
};

static void buffer_close(struct vm_area_struct *vma)
{
    struct nacre_buffer *buffer = vma->vm_private_data;
    for (unsigned long i = 0; i < buffer->count; i++)
        unpin_user_page(buffer->pages[i]);
    kfree(buffer);
}
static void buffer_open(struct vm_area_struct *vma)
{
    /* dup_mmap copied the VMA, not its pin ownership. */
    struct nacre_buffer *buffer = kzalloc(struct_size(buffer, pages, buffer_pages), GFP_KERNEL);
    BUG_ON(!buffer || vma->vm_mm == current->mm);
    vma->vm_private_data = buffer;
}
static const struct vm_operations_struct buffer_ops = { .open = buffer_open, .close = buffer_close };

bool nacre_buffer_vma(const struct vm_area_struct *vma)
{
    return vma->vm_ops == &buffer_ops;
}

int nacre_buffer_prepare(unsigned long *address, unsigned long *capacity)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;
    struct nacre_buffer *buffer;
    unsigned long base, size;
    long count;
    if (!buffer_pages || buffer_pages > 4096) return -EINVAL;
    size = buffer_pages * PAGE_SIZE;
    buffer = kzalloc(struct_size(buffer, pages, buffer_pages), GFP_KERNEL);
    if (!buffer) return -ENOMEM;
    base = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, 0);
    if (IS_ERR_VALUE(base)) { kfree(buffer); return base; }
    /* pin_user_pages() requires the caller to hold mmap_lock. */
    mmap_read_lock(mm);
    count = pin_user_pages(base, buffer_pages, FOLL_WRITE | FOLL_LONGTERM, buffer->pages);
    mmap_read_unlock(mm);
    if (count != buffer_pages) {
        if (count > 0)
            for (long i = 0; i < count; i++) unpin_user_page(buffer->pages[i]);
        vm_munmap(base, size);
        kfree(buffer);
        return count < 0 ? count : -ENOMEM;
    }
    buffer->count = count;
    mmap_write_lock(mm);
    vma = find_vma(mm, base);
    BUG_ON(!vma || vma->vm_start != base || vma->vm_end != base + size || vma->vm_ops);
    vma->vm_ops = &buffer_ops;
    vma->vm_private_data = buffer;
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
    mmap_write_unlock(mm);
    *address = base;
    *capacity = size;
    return 0;
}

int nacre_bind_initial(unsigned long buffer, unsigned long capacity)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, mm, 0);
    struct sbiret ret;
    void *snapshot;
    for_each_vma(vmi, vma) {
        unsigned long perm = ((vma->vm_flags & VM_READ) ? 2 : 0) |
            ((vma->vm_flags & VM_WRITE) ? 4 : 0) | ((vma->vm_flags & VM_EXEC) ? 8 : 0);
        if (vma->vm_start == NACC_AGENT_VA_BASE || nacre_buffer_vma(vma)) continue;
        ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 18, __pa(mm->pgd),
                        vma->vm_start, vma->vm_end, perm,
                        (vma->vm_flags & (VM_IO | VM_PFNMAP | VM_MIXEDMAP)) ? 0 :
                        vma->vm_file ? 2 : 1, 0);
        if (ret.error) return -EACCES;
    }
    /* Kernel stacks may be vmalloc-backed; only this copy has a direct-map PA. */
    snapshot = kmemdup(current_pt_regs(), 33 * sizeof(unsigned long), GFP_KERNEL);
    if (!snapshot) return -ENOMEM;
    ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 19, __pa(snapshot),
                    buffer, capacity, task_pid_vnr(current), mm->brk, (unsigned long)VDSO_SYMBOL(mm->context.vdso, rt_sigreturn));
    kfree(snapshot);
    return ret.error ? -EACCES : 0;
}

int nacre_buffer_fork_pin(struct mm_struct *mm, unsigned long *address, unsigned long *capacity)
{
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, mm, 0);
    int rc = -EINVAL;
    mmap_read_lock(mm);
    for_each_vma(vmi, vma) {
        if (!nacre_buffer_vma(vma)) continue;
        struct nacre_buffer *buffer = vma->vm_private_data;
        BUG_ON(buffer->count || vma->vm_end - vma->vm_start != buffer_pages * PAGE_SIZE);
        long count = pin_user_pages_remote(mm, vma->vm_start, buffer_pages,
            FOLL_WRITE | FOLL_LONGTERM, buffer->pages, NULL);
        if (count > 0) buffer->count = count;
        if (count != buffer_pages) { rc = count < 0 ? count : -ENOMEM; break; }
        *address = vma->vm_start;
        *capacity = vma->vm_end - vma->vm_start;
        rc = 0;
        break;
    }
    mmap_read_unlock(mm);
    return rc;
}
