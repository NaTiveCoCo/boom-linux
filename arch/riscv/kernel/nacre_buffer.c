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
static const struct vm_operations_struct buffer_ops = { .close = buffer_close };

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
    count = pin_user_pages(base, buffer_pages, FOLL_WRITE | FOLL_LONGTERM, buffer->pages);
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
    vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP);
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
                    buffer, capacity, task_pid_vnr(current), 0, 0);
    kfree(snapshot);
    return ret.error ? -EACCES : 0;
}
