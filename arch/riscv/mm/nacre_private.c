// SPDX-License-Identifier: GPL-2.0-only
/* Linux owns allocation/accounting; M owns private data and PTE commits. */
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/pagewalk.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <asm/nacc.h>
#include <asm/nacre_ptp.h>
#include <asm/nacre_registration.h>
#include <asm/sbi.h>

int nacre_protnone_reserve(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 16,
				     __pa(mm->pgd), start, end, 0, 0, 0);
	if (ret.error == SBI_ERR_NO_SHMEM)
		return -ENOMEM;
	BUG_ON(ret.error);
	return 0;
}

void nacre_protnone_finish(struct mm_struct *mm, unsigned long start,
			   unsigned long end, bool abort)
{
	struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 17,
				     __pa(mm->pgd), start, end, abort, 0, 0);
	BUG_ON(ret.error);
}

void nacre_private_claim(struct mm_struct *mm, void *slot, unsigned long value,
			 unsigned long source, unsigned long op)
{
	struct page *page = pfn_to_page(pte_pfn(__pte(value)));
	struct sbiret ret;
	BUG_ON(!nacre_mm_managed(mm) || !nacre_ptp_contains(slot) ||
	       PageNacre(page) || PageCompound(page) || PageReserved(page) ||
	       is_zero_pfn(page_to_pfn(page)));
	/* The extra reference also defeats refcount-based migration freeze. */
	get_page(page);
	SetPageNacre(page);
	ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 13, __pa(mm->pgd), __pa(slot),
			value, source, op, 0);
	if (ret.error) {
		ClearPageNacre(page);
		put_page(page);
		panic("NACRE private claim protocol error=%ld", ret.error);
	}
}

struct takeover {
	pte_t *slot;
	pte_t pte;
	unsigned long addr;
	struct page *page;
};

static bool resident_protnone(pte_t pte)
{
	/* Generic pte_protnone() is a NUMA-balancing stub in this non-NUMA config. */
	return (pte_val(pte) & (_PAGE_PRESENT | _PAGE_PROT_NONE)) == _PAGE_PROT_NONE;
}

/* Capture one candidate under its PTE lock, then allocate outside that lock. */
static int candidate(pte_t *slot, unsigned long addr, unsigned long end,
		     struct mm_walk *walk)
{
	struct takeover *t = walk->private;
	pte_t pte = ptep_get(slot);
	if (pte_none(pte) || pte_nacc(pte))
		return 0;
	if (!pte_present(pte) || (!pte_user(pte) && !resident_protnone(pte)) || pte_devmap(pte))
		return -EOPNOTSUPP;
	if (pte_special(pte) && !is_zero_pfn(pte_pfn(pte)))
		return -EOPNOTSUPP;
	*t = (struct takeover){ .slot = slot, .pte = pte, .addr = addr };
	if (!is_zero_pfn(pte_pfn(pte))) {
		t->page = pte_page(pte);
		get_page(t->page);
	}
	return 1;
}

static int take_vma(struct vm_area_struct *vma)
{
	const struct mm_walk_ops ops = { .pte_entry = candidate, .walk_lock = PGWALK_WRLOCK };
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr = vma->vm_start;
	int rc;
	if (anon_vma_prepare(vma))
		return -ENOMEM;
	while (addr < vma->vm_end) {
		struct takeover t = {0};
		struct folio *fresh = NULL, *old = NULL;
		spinlock_t *ptl;
		pte_t value;
		bool keep = false;
		rc = walk_page_range(mm, addr, vma->vm_end, &ops, &t);
		if (rc <= 0)
			return rc;
		if (t.page) {
			old = page_folio(t.page);
			folio_lock(old);
			keep = !folio_test_large(old) && folio_test_anon(old) &&
			       PageAnonExclusive(t.page) && folio_mapcount(old) == 1 &&
			       !folio_test_swapcache(old);
		}
		if (!keep) {
			fresh = vma_alloc_folio(GFP_HIGHUSER_MOVABLE, 0, vma, t.addr, false);
			if (!fresh || mem_cgroup_charge(fresh, mm, GFP_KERNEL)) {
				if (fresh) folio_put(fresh);
				if (old) { folio_unlock(old); put_page(t.page); }
				return -ENOMEM;
			}
		}
		ptl = pte_lockptr(mm, pmd_off(mm, t.addr));
		spin_lock(ptl);
		if (!pte_same(ptep_get(t.slot), t.pte)) {
			spin_unlock(ptl);
			if (fresh) folio_put(fresh);
			if (old) { folio_unlock(old); put_page(t.page); }
			continue;
		}
		value = t.pte;
		if (resident_protnone(value))
			value = pfn_pte(pte_pfn(value), PAGE_READ);
		if (keep) {
			nacre_private_claim(mm, t.slot, pte_val(value), 0, 0);
		} else {
			value = pfn_pte(folio_pfn(fresh), __pgprot(pte_val(value) & 0xff));
			__folio_mark_uptodate(fresh);
			folio_add_new_anon_rmap(fresh, vma, t.addr, RMAP_EXCLUSIVE);
			nacre_private_claim(mm, t.slot, pte_val(value),
					    old ? page_to_phys(t.page) : 0, old ? 2 : 1);
			folio_add_lru_vma(fresh, vma);
			if (old) {
				folio_remove_rmap_pte(old, t.page, vma);
				dec_mm_counter(mm, mm_counter(old));
				put_page(t.page);
			}
			inc_mm_counter(mm, MM_ANONPAGES);
		}
		/* Preserve resident PROT_NONE without exposing a normal-tag alias. */
		rc = 0;
		if (resident_protnone(t.pte)) {
			rc = nacre_protnone_reserve(mm, t.addr, t.addr + PAGE_SIZE);
			if (!rc) {
				value = pte_modify(ptep_get(t.slot),
						   __pgprot(pte_val(t.pte) & 0xff));
				set_pte_at(mm, t.addr, t.slot, value);
				nacre_protnone_finish(mm, t.addr, t.addr + PAGE_SIZE, false);
			}
		}
		spin_unlock(ptl);
		if (old) { folio_unlock(old); put_page(t.page); }
		if (rc)
			return rc;
		addr = t.addr + PAGE_SIZE;
	}
	return 0;
}

int nacre_private_prepare(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);
	int rc = mmap_write_lock_killable(mm);
	if (rc)
		return rc;
	BUG_ON(mm->context.nacre_private);
	mm->context.nacre_private = 1;
	for_each_vma(vmi, vma) {
		if (vma->vm_start == NACC_AGENT_VA_BASE || nacre_buffer_vma(vma))
			continue;
		if (nacc_vma_is_vdso_text(vma)) {
			/* Drop any old normal mapping through native rmap/RSS accounting. */
			zap_page_range_single(vma, vma->vm_start,
					      vma->vm_end - vma->vm_start, NULL);
			vm_flags_set(vma, VM_MIXEDMAP);
			rc = nacc_adopt_vdso_text(vma);
		} else if (nacc_vma_is_vvar_abi_data(vma)) {
			/* Re-fault public ABI pages with a record after PTE allocation. */
			zap_page_range_single(vma, vma->vm_start,
					      vma->vm_end - vma->vm_start, NULL);
			rc = 0;
		} else if (vma->vm_flags & (VM_SHARED | VM_MAYSHARE | VM_IO | VM_PFNMAP | VM_MIXEDMAP)) {
			rc = -EOPNOTSUPP;
		} else {
			vm_flags_set(vma, VM_NACC_APP);
			rc = take_vma(vma);
		}
		if (rc)
			break;
	}
	mmap_write_unlock(mm);
	return rc;
}
