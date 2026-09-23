// SPDX-License-Identifier: GPL-2.0-only
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/csr.h>
#include <asm/nacc.h>
#include <asm/nacre_registration.h>
#include <asm/nacre_ptp.h>
#include <asm/sbi.h>

#define PTP_ALLOC 3
#define PTP_CANCEL 4
#define PTP_LINK 5
#define PTP_UNLINK 6
#define PTP_FREE 7
#define PTP_UPDATE 8
#define PTP_POOL_BASE 9
#define PTP_POOL_END 10
#define PTP_ENOMEM SBI_ERR_NO_SHMEM

/* The firmware's reserved PTP interval is fixed for this boot: [base, end). */
static unsigned long pool_base, pool_end;

static struct sbiret call(unsigned long fid, unsigned long root,
                          unsigned long b, unsigned long c, unsigned long d)
{
	return sbi_ecall(NACRE_SBI_REGISTER_EXT, fid, root, b, c, d, 0, 0);
}

static unsigned long checked(unsigned long fid, unsigned long root,
                             unsigned long b, unsigned long c, unsigned long d)
{
	struct sbiret ret = call(fid, root, b, c, d);
	if (ret.error)
		panic("NACRE PTP protocol fid=%lu error=%ld", fid, ret.error);
	return ret.value;
}

bool nacre_mm_constructing(struct mm_struct *mm)
{
	return mm && mm->context.nacre_cid;
}

void nacre_mm_init(struct mm_struct *mm)
{
	if (current->thread.nacre_flag == NACRE_IDLE)
		return;
	BUG_ON(current->thread.nacre_flag != NACRE_REQUESTED || mm == current->mm ||
	       mm->context.nacre_cid || mm->context.nacc_state ||
	       !current->thread.nacre_cid || (csr_read(CSR_SATP) >> 60) != 8);
	/* Query once on first NACRE construction, then reuse across mm lifetimes. */
	if (!pool_base) {
		pool_base = checked(PTP_POOL_BASE, 0, 0, 0, 0);
		pool_end = checked(PTP_POOL_END, 0, 0, 0, 0);
		BUG_ON(!pool_base || pool_end <= pool_base ||
		       (pool_base | pool_end) & (PAGE_SIZE - 1));
	}
	/* The target mm selects PTP services; M learns its root at allocation. */
	mm->context.nacre_cid = current->thread.nacre_cid;
	asm volatile(".global nacre_mm_started\nnacre_mm_started: nop" ::: "memory");
}

/*
 * Classify locally without an SBI call or an mm argument in generic helpers.
 * This selects the service path; M still validates ownership and lifecycle.
 */
bool nacre_ptp_contains(const void *ptr)
{
	unsigned long addr;
	if (!pool_base)
		return false;
	addr = __pa(ptr);
	return addr >= pool_base && addr < pool_end;
}

struct ptdesc *nacre_ptp_alloc(struct mm_struct *mm, unsigned int level)
{
	struct sbiret ret;
	struct ptdesc *ptdesc;
	BUG_ON(!nacre_mm_constructing(mm) || level > 1);
	ret = call(PTP_ALLOC, __pa(mm->pgd), level, 0, 0);
	if (ret.error == PTP_ENOMEM)
		return NULL;
	if (ret.error)
		panic("NACRE PTP allocation failed: %ld", ret.error);
	BUG_ON((ret.value << PAGE_SHIFT) < pool_base ||
	       (ret.value << PAGE_SHIFT) >= pool_end);
	ptdesc = page_ptdesc(pfn_to_page(ret.value));
	BUG_ON(!PageReserved(ptdesc_page(ptdesc)) || ptdesc->pt_mm);
	if (!(level ? pagetable_pmd_ctor(ptdesc) : pagetable_pte_ctor(ptdesc))) {
		checked(PTP_CANCEL, __pa(mm->pgd), ret.value, 0, 0);
		return NULL;
	}
	/* Generic leaf helpers without an mm recover the target from its descriptor. */
	ptdesc->pt_mm = mm;
	return ptdesc;
}

static unsigned long nacre_ptdesc_raw_ptl(struct ptdesc *ptdesc)
{
	return READ_ONCE(*(unsigned long *)&ptdesc->ptl);
}

void nacre_ptp_dtor(struct ptdesc *ptdesc, unsigned long pfn,
		    unsigned int level, const char *tag)
{
	unsigned long old_ptl = nacre_ptdesc_raw_ptl(ptdesc);

	if (level == 1)
		pagetable_pmd_dtor(ptdesc);
	else
		pagetable_pte_dtor(ptdesc);

	/*
	 * Pool-backed PTPs skip buddy free, so they never get prep_new_page().
	 * Reset the split-ptlock storage explicitly to make the next ctor
	 * observe the same zero state that the allocator would have provided.
	 */
	WRITE_ONCE(*(unsigned long *)&ptdesc->ptl, 0);
	nacc_debug("[Linux]: %s: reclaimed pfn=%lx level=%u old_ptl=%lx new_ptl=%lx\n",
		   tag, pfn, level, old_ptl,
		   nacre_ptdesc_raw_ptl(ptdesc));
}
EXPORT_SYMBOL(nacre_ptp_dtor);

bool nacre_ptp_release(struct mm_struct *mm, struct ptdesc *ptdesc,
                        unsigned int level, bool installed)
{
	unsigned long pfn = page_to_pfn(ptdesc_page(ptdesc));
	if (!nacre_ptp_contains(ptdesc_address(ptdesc)))
		return false;
	BUG_ON(!nacre_mm_constructing(mm) || ptdesc->pt_mm != mm || level > 1);
	nacre_ptp_dtor(ptdesc, pfn, level, "nacre_ptp_release");
	ptdesc->pt_mm = NULL;
	checked(installed ? PTP_FREE : PTP_CANCEL, __pa(mm->pgd), pfn, 0, 0);
	return true;
}

bool nacre_ptp_populate(struct mm_struct *mm, void *slot, unsigned long pfn)
{
	if (!nacre_ptp_contains(pfn_to_virt(pfn)))
		return false;
	BUG_ON(!nacre_mm_constructing(mm) || page_ptdesc(pfn_to_page(pfn))->pt_mm != mm);
	checked(PTP_LINK, __pa(mm->pgd), __pa(slot), pfn, 0);
	return true;
}

void nacre_ptp_unlink(struct mm_struct *mm, void *slot, unsigned long pfn)
{
	BUG_ON(!nacre_mm_constructing(mm));
	checked(PTP_UNLINK, __pa(mm->pgd), __pa(slot), pfn, 0);
}

unsigned long nacre_ptp_update(void *slot, unsigned long value, unsigned long op)
{
	struct mm_struct *mm = virt_to_ptdesc(slot)->pt_mm;
	BUG_ON(!nacre_ptp_contains(slot) || !nacre_mm_constructing(mm));
	return checked(PTP_UPDATE, __pa(mm->pgd), __pa(slot), value, op);
}
