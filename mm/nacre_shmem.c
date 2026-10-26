// SPDX-License-Identifier: GPL-2.0-only
/* Linux owns inode/folio lifetime; the Monitor owns contents and protection. */
#include <linux/nacre_shmem.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <asm/nacre_ptp.h>
#include <asm/nacre_registration.h>
#include <asm/sbi.h>

#define SHARED_RUN 0x48
#define SHARED_CREATE 0x49
#define SHARED_PAGE 0x4a
#define SHARED_RELEASE 0x4b
#define SHARED_RUN_LIVE 0x4c
#define LEAF_OBJECT_MAP 6

struct nacre_shmem {
    struct list_head link;
    struct inode *inode;
    unsigned long run, handle;
    bool eligible, dead;
};
static LIST_HEAD(objects);
/* Serializes claim against content admission and ordinary mapping admission. */
static DEFINE_MUTEX(objects_lock);
static const struct vm_operations_struct protected_ops;

static struct sbiret call(unsigned long op, unsigned long a, unsigned long b,
                          unsigned long c, unsigned long d)
{
    return sbi_ecall(NACRE_SBI_REGISTER_EXT, op, a, b, c, d, 0, 0);
}

unsigned long nacre_shmem_run(struct mm_struct *mm)
{
    struct sbiret r = call(SHARED_RUN, __pa(mm->pgd), 0, 0, 0);
    BUG_ON(r.error);
    return r.value;
}

int nacre_shmem_create(struct inode *inode)
{
    struct nacre_shmem *o;
    if (!current->mm || !nacre_mm_private(current->mm) || !S_ISREG(inode->i_mode))
        return 0;
    o = kzalloc(sizeof(*o), GFP_KERNEL);
    if (!o) return -ENOMEM;
    o->run = nacre_shmem_run(current->mm);
    BUG_ON(!o->run);
    o->inode = inode;
    o->eligible = true;
    mutex_lock(&objects_lock);
    SHMEM_I(inode)->nacre = o;
    list_add(&o->link, &objects);
    mutex_unlock(&objects_lock);
    return 0;
}

bool nacre_shmem_protected(struct inode *inode)
{
    struct nacre_shmem *o = SHMEM_I(inode)->nacre;
    return o && READ_ONCE(o->handle);
}

int nacre_shmem_io(struct inode *inode)
{
    struct nacre_shmem *o = SHMEM_I(inode)->nacre;
    int rc = 0;
    if (!o) return 0;
    mutex_lock(&objects_lock);
    if (o->handle) rc = -EPERM;
    else o->eligible = false;
    mutex_unlock(&objects_lock);
    return rc;
}

/* Called under i_rwsem, as is mmap admission below. Candidate sizing is allowed. */
int nacre_shmem_resize(struct inode *inode)
{
    return nacre_shmem_protected(inode) ? -EPERM : 0;
}

bool nacre_shmem_vma(struct vm_area_struct *vma)
{
    return vma->vm_ops == &protected_ops;
}

int nacre_shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct inode *inode = file_inode(file);
    struct nacre_shmem *o = SHMEM_I(inode)->nacre;
    unsigned long run;
    int rc = 0;
    /* MAP_SHARED on an O_RDONLY file retains VM_MAYSHARE, not VM_SHARED. */
    if (!o) return nacre_mm_private(vma->vm_mm) && (vma->vm_flags & VM_MAYSHARE) ? -EOPNOTSUPP : 0;
    inode_lock(inode);
    mutex_lock(&objects_lock);
    if (!nacre_mm_private(vma->vm_mm) || !(vma->vm_flags & VM_MAYSHARE)) {
        if (o->handle) rc = -EPERM;
        else o->eligible = false;
        goto out;
    }
    run = nacre_shmem_run(vma->vm_mm);
    if (o->dead || !run || run != o->run || !o->eligible ||
        !(vma->vm_flags & VM_MAYSHARE) || (vma->vm_flags & VM_EXEC) ||
        i_size_read(inode) <= 0 || i_size_read(inode) > (1UL << 38) ||
        vma->vm_pgoff >= DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE) ||
        vma_pages(vma) > DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE) - vma->vm_pgoff) {
        rc = -EPERM;
        goto out;
    }
    if (!o->handle) {
        struct sbiret r;
        BUG_ON(inode->i_mapping->nrpages || mapping_mapped(inode->i_mapping));
        r = call(SHARED_CREATE, __pa(vma->vm_mm->pgd), i_size_read(inode), 0, 0);
        if (r.error) {
            BUG_ON(r.error != -1004);
            rc = -ENOMEM;
            goto out;
        }
        o->handle = r.value;
        mapping_set_unevictable(inode->i_mapping);
    }
    vma->vm_ops = &protected_ops;
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
    vm_flags_clear(vma, VM_MAYEXEC);
    rc = 1;
out:
    mutex_unlock(&objects_lock);
    inode_unlock(inode);
    return rc;
}

static vm_fault_t protected_fault(struct vm_fault *vmf)
{
    struct inode *inode = file_inode(vmf->vma->vm_file);
    struct nacre_shmem *o = SHMEM_I(inode)->nacre;
    struct folio *folio = NULL;
    struct sbiret r;
    int rc;
    mutex_lock(&objects_lock);
    if (o->dead || o->run != nacre_shmem_run(vmf->vma->vm_mm)) {
        mutex_unlock(&objects_lock);
        return VM_FAULT_SIGBUS;
    }
    mutex_unlock(&objects_lock);
    rc = shmem_nacre_get_folio(vmf, &folio);
    if (rc) goto out;
    BUG_ON(!folio || folio_test_large(folio));
    if (!PageNacre(&folio->page)) {
        r = call(SHARED_PAGE, __pa(vmf->vma->vm_mm->pgd), o->handle,
                 vmf->pgoff, page_to_phys(&folio->page));
        if (r.error) {
            BUG_ON(r.error != -1004);
            folio_unlock(folio);
            folio_put(folio);
            rc = -ENOMEM;
            goto out;
        }
        get_page(&folio->page);
        SetPageNacre(&folio->page);
    }
    vmf->page = &folio->page;
out:
    return rc ? vmf_error(rc) : VM_FAULT_LOCKED;
}

static const struct vm_operations_struct protected_ops = {
    .fault = protected_fault,
};

/* The folio is locked by the fault handler, the empty PTE by native MM. */
void nacre_shmem_map(struct vm_fault *vmf, unsigned long value)
{
    struct nacre_shmem *o = SHMEM_I(file_inode(vmf->vma->vm_file))->nacre;
    struct sbiret r = sbi_ecall(NACRE_SBI_REGISTER_EXT, 13,
        __pa(vmf->vma->vm_mm->pgd), __pa(vmf->pte), value,
        o->handle, LEAF_OBJECT_MAP, vmf->pgoff);
    BUG_ON(r.error || r.value);
}

/* M already scrubbed and fenced the object hold before Linux releases PFNs. */
static void release_object_pages(struct nacre_shmem *o)
{
    struct folio *folio;
    pgoff_t index;
    xa_for_each(&o->inode->i_mapping->i_pages, index, folio) {
        BUG_ON(xa_is_value(folio) || folio_test_large(folio));
        if (PageNacre(&folio->page)) {
            BUG_ON(folio_mapped(folio));
            ClearPageNacre(&folio->page);
            put_page(&folio->page);
        }
    }
    shmem_truncate_range(o->inode, 0, -1);
}

/* pgd_free may run in finish_task_switch with preemption disabled. M has
 * already invalidated handles and scrubbed data; only Linux reclaim may sleep. */
static void cleanup_ended_runs(struct work_struct *work)
{
    struct nacre_shmem *o;
    (void)work;
    mutex_lock(&objects_lock);
    list_for_each_entry(o, &objects, link) {
        struct sbiret r;
        if (o->dead) continue;
        r = call(SHARED_RUN_LIVE, o->run, 0, 0, 0);
        BUG_ON(r.error);
        if (r.value) continue;
        o->dead = true;
        o->eligible = false;
        if (o->handle) release_object_pages(o);
    }
    mutex_unlock(&objects_lock);
}
static DECLARE_WORK(cleanup_work, cleanup_ended_runs);

void nacre_shmem_run_cleanup(unsigned long run)
{
    struct sbiret r;
    if (!run) return;
    r = call(SHARED_RUN_LIVE, run, 0, 0, 0);
    BUG_ON(r.error);
    if (!r.value) schedule_work(&cleanup_work);
}

void nacre_shmem_evict(struct inode *inode)
{
    struct nacre_shmem *o = SHMEM_I(inode)->nacre;
    if (!o) return;
    mutex_lock(&objects_lock);
    if (o->handle) {
        BUG_ON(call(SHARED_RELEASE, o->handle, 0, 0, 0).error);
        release_object_pages(o);
    }
    list_del(&o->link);
    SHMEM_I(inode)->nacre = NULL;
    mutex_unlock(&objects_lock);
    kfree(o);
}

long nacre_shmem_precheck(unsigned long fd, unsigned long second, bool two)
{
    struct fd f = fdget(fd);
    long rc;
    if (!fd_file(f)) return -EBADF;
    rc = shmem_file(fd_file(f)) ? nacre_shmem_io(file_inode(fd_file(f))) : 0;
    fdput(f);
    if (!rc && two) rc = nacre_shmem_precheck(second, 0, false);
    return rc;
}
