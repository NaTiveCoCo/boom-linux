// SPDX-License-Identifier: GPL-2.0-only
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <asm/nacre_registration.h>
#include <asm/sbi.h>
#include <asm/nacc.h>
#include <asm/vdso.h>

/* Maximum VA window; only the first page is claimed at exec/fork. */
static unsigned long buffer_pages = 256;
module_param_named(nacre_buffer_pages, buffer_pages, ulong, 0400);

struct buffer_pool {
    struct list_head link, free;
    unsigned long cid, users;
};
struct nacre_buffer {
    struct buffer_pool *pool;
    unsigned long count;
    struct page **pages;
};
static LIST_HEAD(pools);
static DEFINE_MUTEX(pool_lock);

static struct buffer_pool *pool_get(unsigned long cid)
{
    struct buffer_pool *pool;
    mutex_lock(&pool_lock);
    list_for_each_entry(pool, &pools, link)
        if (pool->cid == cid) goto found;
    pool = kzalloc(sizeof(*pool), GFP_KERNEL);
    if (!pool) { mutex_unlock(&pool_lock); return NULL; }
    pool->cid = cid;
    INIT_LIST_HEAD(&pool->free);
    list_add(&pool->link, &pools);
found:
    pool->users++;
    mutex_unlock(&pool_lock);
    return pool;
}

static void buffer_close(struct vm_area_struct *vma)
{
    struct nacre_buffer *buffer = vma->vm_private_data;
    struct buffer_pool *pool = buffer->pool;
    struct page *page, *next;
    /* Native unmap has revoked all PTEs before close returns the lease. */
    mutex_lock(&pool_lock);
    for (unsigned long i = 0; i < buffer->count; i++) {
        page = buffer->pages[i];
        BUG_ON(folio_mapcount(page_folio(page)));
        list_add(&page->lru, &pool->free);
    }
    BUG_ON(!pool->users);
    if (!--pool->users) {
        list_for_each_entry_safe(page, next, &pool->free, lru) {
            list_del(&page->lru);
            __free_page(page);
        }
        list_del(&pool->link);
        kfree(pool);
    }
    mutex_unlock(&pool_lock);
    kfree(buffer->pages);
    kfree(buffer);
}

static void buffer_open(struct vm_area_struct *vma)
{
    struct nacre_buffer *parent = vma->vm_private_data;
    struct nacre_buffer *buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
    BUG_ON(!buffer || vma->vm_mm == current->mm);
    buffer->pool = pool_get(parent->pool->cid);
    BUG_ON(!buffer->pool);
    vma->vm_private_data = buffer;
}

static int buffer_split(struct vm_area_struct *vma, unsigned long address)
{
    return -EINVAL;
}
static int buffer_mremap(struct vm_area_struct *vma) { return -EINVAL; }
static vm_fault_t buffer_fault(struct vm_fault *vmf) { return VM_FAULT_SIGBUS; }
static const struct vm_operations_struct buffer_ops = {
    .open = buffer_open, .close = buffer_close, .may_split = buffer_split,
    .mremap = buffer_mremap, .fault = buffer_fault,
};

bool nacre_buffer_vma(const struct vm_area_struct *vma)
{
    return vma->vm_ops == &buffer_ops;
}

unsigned long nacre_buffer_capacity(const struct vm_area_struct *vma)
{
    const struct nacre_buffer *buffer = vma->vm_private_data;
    BUG_ON(!nacre_buffer_vma(vma));
    return buffer->count * PAGE_SIZE;
}

/* Caller holds mmap_write_lock. Pool ownership keeps every mapped page resident. */
static void buffer_claim(struct vm_area_struct *vma, unsigned long count)
{
    struct nacre_buffer *buffer = vma->vm_private_data;
    BUG_ON(count < buffer->count);
    struct page **pages = krealloc_array(buffer->pages, count, sizeof(*pages), GFP_KERNEL);
    if (!pages) return;
    buffer->pages = pages;
    while (buffer->count < count) {
        struct page *page = NULL;
        mutex_lock(&pool_lock);
        if (!list_empty(&buffer->pool->free)) {
            page = list_first_entry(&buffer->pool->free, struct page, lru);
            list_del_init(&page->lru);
        }
        mutex_unlock(&pool_lock);
        if (!page) page = alloc_page(GFP_KERNEL);
        if (!page) break;
        clear_highpage(page);
        if (vm_insert_page(vma, vma->vm_start + buffer->count * PAGE_SIZE, page)) {
            __free_page(page);
            break;
        }
        buffer->pages[buffer->count++] = page;
    }
}

static int buffer_prepare(struct task_struct *child, unsigned long *address, unsigned long *capacity)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma;
    struct nacre_buffer *buffer;
    unsigned long base, size, populate;
    if (!buffer_pages || buffer_pages > 4096) return -EINVAL;
    size = buffer_pages * PAGE_SIZE;
    /* VM_SPECIAL must be present before mmap_region considers merging with
     * adjacent anonymous mappings; installing vm_ops afterwards is too late. */
    mmap_write_lock(mm);
    base = do_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   VM_DONTEXPAND | VM_DONTDUMP | VM_WIPEONFORK | VM_MIXEDMAP,
                   0, &populate, NULL);
    mmap_write_unlock(mm);
    if (IS_ERR_VALUE(base)) return base;
    BUG_ON(populate);
    buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
    if (!buffer) { vm_munmap(base, size); return -ENOMEM; }
    buffer->pool = pool_get(mm->context.nacre_cid);
    if (!buffer->pool) { kfree(buffer); vm_munmap(base, size); return -ENOMEM; }
    mmap_write_lock(mm);
    vma = find_vma(mm, base);
    BUG_ON(!vma || vma->vm_start != base || vma->vm_end != base + size || vma->vm_ops);
    vma->vm_page_prot = PAGE_SHARED;
    vma->vm_ops = &buffer_ops;
    vma->vm_private_data = buffer;
    /* Dedicated non-anonymous backing; fork copies only this VA window. */
    /* The dedicated flags were installed before insertion into the VMA tree. */
    if (child) {
        struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_THREAD_ADMIT,
                                     base, size, task_pid_vnr(child), task_pid_vnr(current), 0, 0);
        BUG_ON(ret.error);
    }
    buffer_claim(vma, 1);
    *address = base;
    *capacity = nacre_buffer_capacity(vma);
    mmap_write_unlock(mm);
    if (!*capacity) { vm_munmap(base, size); return -ENOMEM; }
    return 0;
}

int nacre_buffer_prepare(unsigned long *address, unsigned long *capacity)
{
    int rc = buffer_prepare(NULL, address, capacity);
    if (!rc) current->thread.nacre_buffer = *address;
    return rc;
}

void nacre_buffer_thread_prepare(struct task_struct *child)
{
    unsigned long address, capacity;
    BUG_ON(child->mm != current->mm);
    BUG_ON(buffer_prepare(child, &address, &capacity));
    BUG_ON(capacity != PAGE_SIZE);
    child->thread.nacre_buffer = address;
    BUG_ON(sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_THREAD_SEAL,
                     task_pid_vnr(child), task_pid_vnr(current), 0, 0, 0, 0).error);
}

/* The M task is already revoked; siblings retain their own VMA leases. */
void nacre_buffer_release_locked(void)
{
    struct mm_struct *mm = current->mm;
    unsigned long address = current->thread.nacre_buffer, size;
    mmap_assert_write_locked(mm);
    BUG_ON(!address);
    struct vm_area_struct *vma = find_vma(mm, address);
    BUG_ON(!vma || vma->vm_start != address || !nacre_buffer_vma(vma));
    size = vma->vm_end - address;
    BUG_ON(do_munmap(mm, address, size, NULL));
    current->thread.nacre_buffer = 0;
    BUG_ON(sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_TASK_DETACH,
                     task_pid_vnr(current), 0, 0, 0, 0, 0).error);
}

void nacre_buffer_release(void)
{
    /* Exit must finish revoking the lease even when exit_group has queued
     * a fatal signal. vm_munmap() takes a killable lock and can return EINTR. */
    mmap_write_lock(current->mm);
    nacre_buffer_release_locked();
    mmap_write_unlock(current->mm);
}

int nacre_bind_initial(unsigned long buffer, unsigned long capacity)
{
    struct mm_struct *mm = current->mm;
    struct sbiret ret;
    void *snapshot;
    /* Kernel stacks may be vmalloc-backed; only this copy has a direct-map PA. */
    snapshot = kmemdup(current_pt_regs(), 33 * sizeof(unsigned long), GFP_KERNEL);
    if (!snapshot) return -ENOMEM;
    ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 19, __pa(snapshot),
                    buffer, capacity, task_pid_vnr(current), (unsigned long)VDSO_SYMBOL(mm->context.vdso, rt_sigreturn), buffer_pages * PAGE_SIZE);
    kfree(snapshot);
    return ret.error ? -EACCES : 0;
}

int nacre_buffer_fork_prepare(struct mm_struct *mm, unsigned long *address, unsigned long *capacity)
{
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, mm, 0);
    int rc = -EINVAL;
    mmap_write_lock(mm);
    for_each_vma(vmi, vma) {
        if (!nacre_buffer_vma(vma)) continue;
        struct nacre_buffer *buffer = vma->vm_private_data;
        BUG_ON(buffer->count || buffer->pool->cid != mm->context.nacre_cid);
        buffer_claim(vma, 1);
        *address = vma->vm_start;
        *capacity = nacre_buffer_capacity(vma);
        rc = *capacity ? 0 : -ENOMEM;
        break;
    }
    mmap_write_unlock(mm);
    return rc;
}

long nacre_buffer_grow(unsigned long capacity)
{
    struct mm_struct *mm = current->mm;
    unsigned long address = current->thread.nacre_buffer;
    long result = -EINVAL;
    mmap_write_lock(mm);
    struct vm_area_struct *vma = find_vma(mm, address);
    BUG_ON(!address || !vma || vma->vm_start != address || !nacre_buffer_vma(vma));
    if (capacity && !(capacity & ~PAGE_MASK) && capacity <= vma->vm_end - address) {
        buffer_claim(vma, capacity / PAGE_SIZE);
        result = nacre_buffer_capacity(vma);
    }
    mmap_write_unlock(mm);
    return result;
}
