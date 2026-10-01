// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2004 Benjamin Herrenschmidt, IBM Corp.
 *                    <benh@kernel.crashing.org>
 * Copyright (C) 2012 ARM Limited
 * Copyright (C) 2015 Regents of the University of California
 */

#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include <linux/err.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/vdso.h>
#include <asm/nacc.h>
#include <asm/nacre_ptp.h>
#include <asm/tlbflush.h>
#include <linux/time_namespace.h>
#include <vdso/datapage.h>
#include <vdso/vsyscall.h>

enum vvar_pages {
	VVAR_DATA_PAGE_OFFSET,
	VVAR_TIMENS_PAGE_OFFSET,
	VVAR_NR_PAGES,
};

enum rv_vdso_map {
	RV_VDSO_MAP_VVAR,
	RV_VDSO_MAP_VDSO,
};

#define VVAR_SIZE  (VVAR_NR_PAGES << PAGE_SHIFT)

static union vdso_data_store vdso_data_store __page_aligned_data;
struct vdso_data *vdso_data = vdso_data_store.data;

struct __vdso_info {
	const char *name;
	const char *vdso_code_start;
	const char *vdso_code_end;
	unsigned long vdso_pages;
	/* Data Mapping */
	struct vm_special_mapping *dm;
	/* Code Mapping */
	struct vm_special_mapping *cm;
};

static struct __vdso_info vdso_info;
#ifdef CONFIG_COMPAT
static struct __vdso_info compat_vdso_info;
#endif

bool nacc_vma_is_vvar_abi_data(const struct vm_area_struct *vma)
{
	if (vma_is_special_mapping(vma, vdso_info.dm))
		return true;
#ifdef CONFIG_COMPAT
	if (vma_is_special_mapping(vma, compat_vdso_info.dm))
		return true;
#endif

	return false;
}

static struct __vdso_info *nacc_vdso_info_for_text_vma(
	const struct vm_area_struct *vma)
{
	if (!vma)
		return NULL;

	if (vma_is_special_mapping(vma, vdso_info.cm))
		return &vdso_info;
#ifdef CONFIG_COMPAT
	if (vma_is_special_mapping(vma, compat_vdso_info.cm))
		return &compat_vdso_info;
#endif

	return NULL;
}

bool nacc_vma_is_vdso_text(const struct vm_area_struct *vma)
{
	return !!nacc_vdso_info_for_text_vma(vma);
}

static int nacc_vdso_prepare_pte_slots(struct mm_struct *mm,
				       unsigned long start,
				       unsigned long nr_pages)
{
	for (unsigned long i = 0; i < nr_pages; i++) {
		spinlock_t *ptl;
		pte_t *ptep;

		ptep = get_locked_pte(mm, start + i * PAGE_SIZE, &ptl);
		if (!ptep)
			return -ENOMEM;
		pte_unmap_unlock(ptep, ptl);
	}

	return 0;
}

static void nacc_vdso_log_pte_slots(struct mm_struct *mm, unsigned long start,
				    unsigned long nr_pages, const char *tag)
{
	for (unsigned long i = 0; i < nr_pages; i++) {
		unsigned long addr = start + i * PAGE_SIZE;
		spinlock_t *ptl;
		pte_t *ptep;
		pte_t pte;

		ptep = get_locked_pte(mm, addr, &ptl);
		if (!ptep) {
			nacc_debug("[NACC][vdso-adopt] %s pid=%d comm=%s mm=%px addr=%lx pte_slot=missing\n",
				   tag, current->pid, current->comm, mm, addr);
			continue;
		}

		pte = ptep_get(ptep);
		nacc_debug("[NACC][vdso-adopt] %s pid=%d comm=%s mm=%px addr=%lx pte=%lx pfn=%lx present=%d special=%d nacc=%d\n",
			   tag, current->pid, current->comm, mm, addr, pte_val(pte),
			   pte_pfn(pte), pte_present(pte), pte_special(pte),
			   pte_nacc(pte));
		pte_unmap_unlock(ptep, ptl);
	}
}

static int nacc_vdso_adopt_fail(struct vm_area_struct *vma, int ret,
				const char *reason, unsigned long nr_pages)
{
	struct mm_struct *mm = vma ? vma->vm_mm : NULL;

	printk(KERN_ERR "[NACC][vdso-adopt] reject pid=%d comm=%s mm=%px root=%lx reason=%s ret=%d vma=%px start=%lx end=%lx flags=%lx context_vdso=%px nr_pages=%lu\n",
	       current->pid, current->comm, mm, mm ? __pa(mm->pgd) : 0,
	       reason, ret, vma, vma ? vma->vm_start : 0,
	       vma ? vma->vm_end : 0, vma ? vma->vm_flags : 0,
	       mm ? mm->context.vdso : NULL, nr_pages);

	return ret;
}

int nacc_adopt_vdso_text(struct vm_area_struct *vma)
{
	struct __vdso_info *info;
	struct mm_struct *mm;
	unsigned long nr_pages;
	unsigned long text_len;
	unsigned long *source_pfns;
	int ret = 0;

	if (!vma || !vma->vm_mm)
		return nacc_vdso_adopt_fail(vma, -EINVAL, "missing-vma-mm", 0);

	mm = vma->vm_mm;
	if (!nacre_mm_private(mm))
		return 0;

	info = nacc_vdso_info_for_text_vma(vma);
	if (!info || !info->cm || !info->cm->pages)
		return nacc_vdso_adopt_fail(vma, -EINVAL, "not-vdso-text", 0);

	nr_pages = info->vdso_pages;
	if (!nr_pages || nr_pages > NACC_SEMANTIC_MAX_PFNS)
		return nacc_vdso_adopt_fail(vma, -E2BIG, "bad-page-count",
					    nr_pages);
	if (nr_pages > (ULONG_MAX >> PAGE_SHIFT))
		return nacc_vdso_adopt_fail(vma, -EOVERFLOW, "page-count-overflow",
					    nr_pages);

	nacc_debug("[NACC][vdso-adopt] enter pid=%d comm=%s mm=%px root=%lx vma=[%lx,%lx) flags=%lx context_vdso=%px nr_pages=%lu\n",
		   current->pid, current->comm, mm, __pa(mm->pgd), vma->vm_start,
		   vma->vm_end, vma->vm_flags, mm->context.vdso, nr_pages);

	text_len = nr_pages << PAGE_SHIFT;
	if (vma->vm_end - vma->vm_start != text_len)
		return nacc_vdso_adopt_fail(vma, -EINVAL, "length-mismatch",
					    nr_pages);
	if (mm->context.vdso != (void *)vma->vm_start)
		return nacc_vdso_adopt_fail(vma, -EINVAL, "context-vdso-mismatch",
					    nr_pages);
	if ((vma->vm_flags & (VM_READ | VM_EXEC)) != (VM_READ | VM_EXEC))
		return nacc_vdso_adopt_fail(vma, -EACCES, "missing-rx",
					    nr_pages);
	if (vma->vm_flags & VM_WRITE)
		return nacc_vdso_adopt_fail(vma, -EACCES, "writable-vdso",
					    nr_pages);
	if ((vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP)) != VM_MIXEDMAP)
		return nacc_vdso_adopt_fail(vma, -EINVAL, "bad-pfnmap-mixedmap",
					    nr_pages);

	source_pfns = kcalloc(nr_pages, sizeof(*source_pfns), GFP_KERNEL);
	if (!source_pfns)
		return nacc_vdso_adopt_fail(vma, -ENOMEM, "source-pfn-alloc",
					    nr_pages);

	for (unsigned long i = 0; i < nr_pages; i++) {
		if (!info->cm->pages[i]) {
			ret = -EINVAL;
			printk(KERN_ERR "[NACC][vdso-adopt] reject pid=%d comm=%s mm=%px root=%lx reason=missing-source-page index=%lu nr_pages=%lu\n",
			       current->pid, current->comm, mm, __pa(mm->pgd),
			       i, nr_pages);
			goto out_free;
		}
		source_pfns[i] = page_to_pfn(info->cm->pages[i]);
		nacc_debug("[NACC][vdso-adopt] source pid=%d comm=%s root=%lx index=%lu pfn=%lx\n",
			   current->pid, current->comm, __pa(mm->pgd), i,
			   source_pfns[i]);
	}

	ret = nacc_vdso_prepare_pte_slots(mm, vma->vm_start, nr_pages);
	if (ret) {
		printk(KERN_ERR "[NACC][vdso-adopt] reject pid=%d comm=%s mm=%px root=%lx reason=prepare-pte-slots ret=%d nr_pages=%lu\n",
		       current->pid, current->comm, mm, __pa(mm->pgd), ret,
		       nr_pages);
		goto out_free;
	}

	nacc_vdso_log_pte_slots(mm, vma->vm_start, nr_pages, "before-sbi");

	ret = nacc_adopt_vdso_sbi(__pa(mm->pgd), vma->vm_start, nr_pages,
				  __pa(source_pfns));
	nacc_debug("[NACC][vdso-adopt] sbi-return pid=%d comm=%s mm=%px root=%lx ret=%d\n",
		   current->pid, current->comm, mm, __pa(mm->pgd), ret);
	nacc_vdso_log_pte_slots(mm, vma->vm_start, nr_pages, "after-sbi");
	if (!ret) {
		flush_tlb_range(vma, vma->vm_start, vma->vm_end);
		nacc_debug("[NACC][vdso-adopt] success pid=%d comm=%s mm=%px root=%lx vma=[%lx,%lx) nr_pages=%lu\n",
			   current->pid, current->comm, mm, __pa(mm->pgd),
			   vma->vm_start, vma->vm_end, nr_pages);
	}

out_free:
	kfree(source_pfns);
	return ret;
}

static int vdso_mremap(const struct vm_special_mapping *sm,
		       struct vm_area_struct *new_vma)
{
	if (nacre_mm_private(current->mm))
		return -EPERM;

	current->mm->context.vdso = (void *)new_vma->vm_start;

	return 0;
}

static void __init __vdso_init(struct __vdso_info *vdso_info)
{
	unsigned int i;
	struct page **vdso_pagelist;
	unsigned long pfn;

	if (memcmp(vdso_info->vdso_code_start, "\177ELF", 4))
		panic("vDSO is not a valid ELF object!\n");

	vdso_info->vdso_pages = (
		vdso_info->vdso_code_end -
		vdso_info->vdso_code_start) >>
		PAGE_SHIFT;

	vdso_pagelist = kcalloc(vdso_info->vdso_pages,
				sizeof(struct page *),
				GFP_KERNEL);
	if (vdso_pagelist == NULL)
		panic("vDSO kcalloc failed!\n");

	/* Grab the vDSO code pages. */
	pfn = sym_to_pfn(vdso_info->vdso_code_start);

	for (i = 0; i < vdso_info->vdso_pages; i++)
		vdso_pagelist[i] = pfn_to_page(pfn + i);

	vdso_info->cm->pages = vdso_pagelist;
}

#ifdef CONFIG_TIME_NS
struct vdso_data *arch_get_vdso_data(void *vvar_page)
{
	return (struct vdso_data *)(vvar_page);
}

/*
 * The vvar mapping contains data for a specific time namespace, so when a task
 * changes namespace we must unmap its vvar data for the old namespace.
 * Subsequent faults will map in data for the new namespace.
 *
 * For more details see timens_setup_vdso_data().
 */
int vdso_join_timens(struct task_struct *task, struct time_namespace *ns)
{
	struct mm_struct *mm = task->mm;
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);

	mmap_read_lock(mm);

	for_each_vma(vmi, vma) {
		if (vma_is_special_mapping(vma, vdso_info.dm))
			zap_vma_pages(vma);
#ifdef CONFIG_COMPAT
		if (vma_is_special_mapping(vma, compat_vdso_info.dm))
			zap_vma_pages(vma);
#endif
	}

	mmap_read_unlock(mm);
	return 0;
}
#endif

static vm_fault_t vvar_fault(const struct vm_special_mapping *sm,
			     struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *timens_page = find_timens_vvar_page(vma);
	unsigned long pfn;

	switch (vmf->pgoff) {
	case VVAR_DATA_PAGE_OFFSET:
		if (timens_page)
			pfn = page_to_pfn(timens_page);
		else
			pfn = sym_to_pfn(vdso_data);
		break;
#ifdef CONFIG_TIME_NS
	case VVAR_TIMENS_PAGE_OFFSET:
		/*
		 * If a task belongs to a time namespace then a namespace
		 * specific VVAR is mapped with the VVAR_DATA_PAGE_OFFSET and
		 * the real VVAR page is mapped with the VVAR_TIMENS_PAGE_OFFSET
		 * offset.
		 * See also the comment near timens_setup_vdso_data().
		 */
		if (!timens_page)
			return VM_FAULT_SIGBUS;
		pfn = sym_to_pfn(vdso_data);
		break;
#endif /* CONFIG_TIME_NS */
	default:
		return VM_FAULT_SIGBUS;
	}

	return vmf_insert_pfn(vma, vmf->address, pfn);
}

static vm_fault_t vdso_fault(const struct vm_special_mapping *sm,
			     struct vm_area_struct *vma, struct vm_fault *vmf)
{
	pgoff_t pgoff;
	struct page **pages;
	int ret;

	if (vma->vm_mm && nacre_mm_private(vma->vm_mm)) {
		nacc_debug("[NACC][vdso-fault] enter pid=%d comm=%s mm=%px root=%lx addr=%lx pgoff=%lx vma=[%lx,%lx) flags=%lx mixed=%d pfnmap=%d\n",
			   current->pid, current->comm, vma->vm_mm,
			   __pa(vma->vm_mm->pgd), vmf->address, vmf->pgoff,
			   vma->vm_start, vma->vm_end, vma->vm_flags,
			   !!(vma->vm_flags & VM_MIXEDMAP),
			   !!(vma->vm_flags & VM_PFNMAP));
		ret = nacc_adopt_vdso_text(vma);
		if (ret) {
			printk(KERN_ERR "[NACC][vdso-fault] return=SIGBUS pid=%d comm=%s mm=%px addr=%lx ret=%d flags=%lx\n",
			       current->pid, current->comm, vma->vm_mm,
			       vmf->address, ret, vma->vm_flags);
			return VM_FAULT_SIGBUS;
		}
		flush_tlb_page(vma, vmf->address);
		nacc_debug("[NACC][vdso-fault] return=NOPAGE pid=%d comm=%s mm=%px addr=%lx flags=%lx\n",
			   current->pid, current->comm, vma->vm_mm, vmf->address,
			   vma->vm_flags);
		return VM_FAULT_NOPAGE;
	}

	pages = sm->pages;
	for (pgoff = vmf->pgoff; pgoff && *pages; ++pages)
		pgoff--;

	if (*pages) {
		get_page(*pages);
		vmf->page = *pages;
		return 0;
	}

	return VM_FAULT_SIGBUS;
}

static struct vm_special_mapping rv_vdso_maps[] __ro_after_init = {
	[RV_VDSO_MAP_VVAR] = {
		.name   = "[vvar]",
		.fault = vvar_fault,
	},
	[RV_VDSO_MAP_VDSO] = {
		.name   = "[vdso]",
		.fault = vdso_fault,
		.mremap = vdso_mremap,
	},
};

static struct __vdso_info vdso_info __ro_after_init = {
	.name = "vdso",
	.vdso_code_start = vdso_start,
	.vdso_code_end = vdso_end,
	.dm = &rv_vdso_maps[RV_VDSO_MAP_VVAR],
	.cm = &rv_vdso_maps[RV_VDSO_MAP_VDSO],
};

#ifdef CONFIG_COMPAT
static struct vm_special_mapping rv_compat_vdso_maps[] __ro_after_init = {
	[RV_VDSO_MAP_VVAR] = {
		.name   = "[vvar]",
		.fault = vvar_fault,
	},
	[RV_VDSO_MAP_VDSO] = {
		.name   = "[vdso]",
		.fault = vdso_fault,
		.mremap = vdso_mremap,
	},
};

static struct __vdso_info compat_vdso_info __ro_after_init = {
	.name = "compat_vdso",
	.vdso_code_start = compat_vdso_start,
	.vdso_code_end = compat_vdso_end,
	.dm = &rv_compat_vdso_maps[RV_VDSO_MAP_VVAR],
	.cm = &rv_compat_vdso_maps[RV_VDSO_MAP_VDSO],
};
#endif

static int __init vdso_init(void)
{
	__vdso_init(&vdso_info);
#ifdef CONFIG_COMPAT
	__vdso_init(&compat_vdso_info);
#endif

	return 0;
}
arch_initcall(vdso_init);

static int __setup_additional_pages(struct mm_struct *mm,
				    struct linux_binprm *bprm,
				    int uses_interp,
				    struct __vdso_info *vdso_info)
{
	unsigned long vdso_base, vdso_text_len, vdso_mapping_len;
	void *ret;

	BUILD_BUG_ON(VVAR_NR_PAGES != __VVAR_PAGES);

	vdso_text_len = vdso_info->vdso_pages << PAGE_SHIFT;
	/* Be sure to map the data page */
	vdso_mapping_len = vdso_text_len + VVAR_SIZE;

	vdso_base = get_unmapped_area(NULL, 0, vdso_mapping_len, 0, 0);
	if (IS_ERR_VALUE(vdso_base)) {
		ret = ERR_PTR(vdso_base);
		goto up_fail;
	}

	ret = _install_special_mapping(mm, vdso_base, VVAR_SIZE,
		(VM_READ | VM_MAYREAD | VM_PFNMAP), vdso_info->dm);
	if (IS_ERR(ret))
		goto up_fail;

	vdso_base += VVAR_SIZE;
	mm->context.vdso = (void *)vdso_base;

	ret =
	   _install_special_mapping(mm, vdso_base, vdso_text_len,
		(VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC),
		vdso_info->cm);

	if (IS_ERR(ret))
		goto up_fail;

	return 0;

up_fail:
	mm->context.vdso = NULL;
	return PTR_ERR(ret);
}

#ifdef CONFIG_COMPAT
int compat_arch_setup_additional_pages(struct linux_binprm *bprm,
				       int uses_interp)
{
	struct mm_struct *mm = current->mm;
	int ret;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	ret = __setup_additional_pages(mm, bprm, uses_interp,
							&compat_vdso_info);
	mmap_write_unlock(mm);

	return ret;
}
#endif

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	struct mm_struct *mm = current->mm;
	int ret;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	ret = __setup_additional_pages(mm, bprm, uses_interp, &vdso_info);
	mmap_write_unlock(mm);

	return ret;
}
