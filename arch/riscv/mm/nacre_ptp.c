// SPDX-License-Identifier: GPL-2.0-only
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/csr.h>
#include <asm/nacre.h>
#include <asm/nacre_registration.h>
#include <asm/nacre_ptp.h>
#include <linux/nacre_shmem.h>
#include <asm/sbi.h>

#define PTP_ALLOC 3
#define PTP_CANCEL 4
#define PTP_LINK 5
#define PTP_UNLINK 6
#define PTP_FREE 7
#define PTP_UPDATE 8
#define PTP_POOL_BASE 9
#define PTP_POOL_END 10
#define ROOT_RETIRE 11
#define ROOT_READ 12
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

bool nacre_mm_private(struct mm_struct *mm)
{
	return mm && mm->context.nacre_private;
}

bool nacre_mm_managed(struct mm_struct *mm)
{
	return mm && mm->context.nacre_cid;
}

static noinline void nacre_mm_started(void)
{
    asm volatile("nop" ::: "memory");
}

void nacre_mm_init(struct mm_struct *mm, bool fork)
{
	if (current->thread.nacre_flag == NACRE_IDLE)
		return;
	BUG_ON((current->thread.nacre_flag != NACRE_REQUESTED && current->thread.nacre_flag != NACRE_HANDOFF) || mm == current->mm ||
	       mm->context.nacre_cid ||
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
    if (current->thread.nacre_flag == NACRE_HANDOFF) {
        BUG_ON(sbi_ecall(NACRE_SBI_REGISTER_EXT, fork ? 0x40 : 0x43,
                        __pa(mm->pgd), fork ? 0 : task_pid_vnr(current), 0, 0, 0, 0).error);
        /* Exec constructs new public ELF pages, then seals them before AS entry. */
        mm->context.nacre_private = fork;
    }
    nacre_mm_started();
}

void nacre_mm_discard(struct mm_struct *mm)
{
    BUG_ON(!nacre_mm_managed(mm) || mm->context.nacre_prepared);
    /* All PTPs have returned before pgd_free; also covers construction without a PTP. */
    unsigned long run = nacre_shmem_run(mm);
    BUG_ON(sbi_ecall(NACRE_SBI_REGISTER_EXT, 0x42, __pa(mm->pgd), 0, 0, 0, 0, 0).error);
    nacre_shmem_run_cleanup(run);
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
	BUG_ON(!nacre_mm_managed(mm) || level > 1);
	ret = call(PTP_ALLOC, __pa(mm->pgd), level, mm->context.nacre_cid, 0);
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
	nacre_debug("[Linux]: %s: reclaimed pfn=%lx level=%u old_ptl=%lx new_ptl=%lx\n",
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
	BUG_ON(!nacre_mm_managed(mm) || ptdesc->pt_mm != mm || level > 1);
	nacre_ptp_dtor(ptdesc, pfn, level, "nacre_ptp_release");
	ptdesc->pt_mm = NULL;
	checked(installed ? PTP_FREE : PTP_CANCEL, __pa(mm->pgd), pfn, 0, 0);
	return true;
}

bool nacre_ptp_populate(struct mm_struct *mm, void *slot, unsigned long pfn)
{
	if (!nacre_ptp_contains(pfn_to_virt(pfn)))
		return false;
	BUG_ON(!nacre_mm_managed(mm) || page_ptdesc(pfn_to_page(pfn))->pt_mm != mm);
	checked(PTP_LINK, __pa(mm->pgd), __pa(slot), pfn, 0);
	return true;
}

void nacre_ptp_unlink(struct mm_struct *mm, void *slot, unsigned long pfn)
{
	BUG_ON(!nacre_mm_managed(mm));
	checked(PTP_UNLINK, __pa(mm->pgd), __pa(slot), pfn, 0);
}

unsigned long nacre_ptp_update(void *slot, unsigned long value, unsigned long op)
{
	struct mm_struct *mm = virt_to_ptdesc(slot)->pt_mm;
	BUG_ON(!nacre_ptp_contains(slot) || !nacre_mm_managed(mm));
	/* Leaf PTPs are readable in S; the caller holds the native PTE lock. */
	unsigned long old = READ_ONCE(*(unsigned long *)slot);
	unsigned long retired = checked(PTP_UPDATE, __pa(mm->pgd), __pa(slot), value, op);
	if (!op && !value && pte_nacre(__pte(old)))
		nacre_private_released(old, retired);
	else
		BUG_ON(retired);
	if (op == 2)
		return 0;
	return old;
}

/* One hart, with IRQs and preemption disabled throughout collection/publication.
 * Each input fits wholly inside one ordinary, physically contiguous BSS page. */
static struct nacre_ptp_fork_batch fork_batch __aligned(PAGE_SIZE);
static struct nacre_ptp_zap_batch zap_batch __aligned(PAGE_SIZE);
static_assert(sizeof(fork_batch) <= PAGE_SIZE && sizeof(zap_batch) <= PAGE_SIZE);
static_assert(NACRE_PTP_BATCH_MAX == BITS_PER_LONG);
static struct mm_struct *fork_mm;
static void *fork_l0;
static unsigned long fork_irq_flags;
static bool fork_active, zap_active;

void nacre_ptp_fork_begin(struct mm_struct *mm, void *l0)
{
	unsigned long flags;
	BUG_ON(!in_atomic() || !nacre_mm_managed(mm) || mm->context.nacre_prepared ||
	       !nacre_ptp_contains(l0));
	local_irq_save(flags);
	BUG_ON(fork_active);
	fork_active = true;
	fork_irq_flags = flags;
	fork_mm = mm;
	fork_l0 = (void *)((unsigned long)l0 & PAGE_MASK);
	BUG_ON(virt_to_ptdesc(l0)->pt_mm != mm || fork_batch.count);
}

void nacre_ptp_fork_flush(void)
{
	BUG_ON(!fork_active || !irqs_disabled());
	if (!fork_batch.count) return;
	checked(NACRE_PTP_FORK_BATCH, __pa(fork_mm->pgd), __pa(fork_l0),
		__pa(&fork_batch), fork_batch.count);
	fork_batch.count = 0;
}

void nacre_ptp_fork_end(void)
{
	nacre_ptp_fork_flush();
	fork_active = false;
	fork_mm = NULL;
	fork_l0 = NULL;
	local_irq_restore(fork_irq_flags);
}

void nacre_ptp_fork_add(struct mm_struct *mm, unsigned long addr, void *slot,
			unsigned long value)
{
	pte_t pte = __pte(value);
	unsigned long idx = ((unsigned long)slot & ~PAGE_MASK) / sizeof(pte_t);
	BUG_ON(!fork_active || !irqs_disabled() || mm != fork_mm ||
	       ((unsigned long)slot & PAGE_MASK) != (unsigned long)fork_l0 ||
	       !pte_none(ptep_get(slot)) || !pte_present(pte) || !pte_nacre(pte) || pte_special(pte));
	BUG_ON(fork_batch.count && idx <= fork_batch.indices[fork_batch.count - 1]);
	page_table_check_ptes_set(mm, slot, pte, 1);
	if (pte_exec(pte)) flush_icache_pte(mm, pte);
	fork_batch.indices[fork_batch.count] = idx;
	fork_batch.entries_pte[fork_batch.count++] = value;
	if (fork_batch.count == NACRE_PTP_BATCH_MAX) nacre_ptp_fork_flush();
	(void)addr;
}

unsigned long nacre_ptp_zap_batch(struct mm_struct *mm, void *l0,
				 const unsigned short *indices, unsigned long count)
{
	unsigned long flags, retired;
	BUG_ON(!in_atomic() || !nacre_mm_managed(mm) || !nacre_ptp_contains(l0) ||
	       virt_to_ptdesc(l0)->pt_mm != mm || !count || count > NACRE_PTP_BATCH_MAX);
	local_irq_save(flags);
	BUG_ON(zap_active);
	zap_active = true;
	zap_batch.count = count;
	memcpy(zap_batch.indices, indices, count * sizeof(*indices));
	retired = checked(NACRE_PTP_ZAP_BATCH, __pa(mm->pgd), __pa(l0) & PAGE_MASK,
			  __pa(&zap_batch), count);
	BUG_ON(count < BITS_PER_LONG && (retired >> count));
	zap_active = false;
	local_irq_restore(flags);
	return retired;
}

/* Test the root slot, not a VMA identity: free_pgtables may merge ranges. */
bool nacre_agent_slot(struct mm_struct *mm, unsigned long addr)
{
	return mm->context.nacre_prepared &&
	       addr >= NACRE_AGENT_VA_BASE && addr < NACRE_AGENT_VA_SLOT_END;
}

void nacre_root_retire(struct mm_struct *mm)
{
	BUG_ON(!nacre_mm_managed(mm) || !mm->context.nacre_prepared);
	unsigned long run = nacre_shmem_run(mm);
	checked(ROOT_RETIRE, __pa(mm->pgd), 0, 0, 0);
	nacre_shmem_run_cleanup(run);
	mm->context.nacre_prepared = 0;
	asm volatile(".global nacre_root_retired\nnacre_root_retired: nop" ::: "memory");
}

/* An exiting task may borrow a different active_mm after a normal reschedule. */
unsigned long nacre_root_entry(struct mm_struct *mm, unsigned long addr)
{
	BUG_ON(!nacre_mm_managed(mm) || !mm->context.nacre_prepared ||
	       pgtable_l4_enabled || pgtable_l5_enabled || addr >= (1UL << 38));
	return checked(ROOT_READ, __pa(mm->pgd), addr >> 30, 0, 0);
}
