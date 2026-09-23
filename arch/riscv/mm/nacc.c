#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/panic.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/page_ref.h>
#include <linux/string.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/csr.h>
#include <asm/tlbflush.h>


unsigned long nacc_mm_state(struct mm_struct *mm)
{
	if (!mm)
		return 0;

	return READ_ONCE(mm->context.nacc_state);
}
EXPORT_SYMBOL(nacc_mm_state);

void nacc_mm_set_state(struct mm_struct *mm, unsigned long mask)
{
	unsigned long state;

	if (!mm)
		return;

	state = READ_ONCE(mm->context.nacc_state);
	WRITE_ONCE(mm->context.nacc_state, state | mask);
}
EXPORT_SYMBOL(nacc_mm_set_state);

bool nacc_mm_is_active(struct mm_struct *mm)
{
	return !!(nacc_mm_state(mm) & NACC_MM_ACTIVE);
}
EXPORT_SYMBOL(nacc_mm_is_active);

#ifdef NACC_LOG_DEBUG
static const char *nacc_copy_user_highpage_result_name(long result)
{
	switch (result) {
	case NACC_COPY_USER_HIGHPAGE_NOT_HANDLED:
		return "not_handled";
	case NACC_COPY_USER_HIGHPAGE_HANDLED:
		return "handled";
	default:
		return "unknown";
	}
}
#endif

static void nacc_log_copy_user_highpage_context(const char *stage,
						struct page *to,
						struct page *from,
						unsigned long vaddr,
						struct vm_area_struct *vma,
						unsigned long root_pgd_pa,
						unsigned long from_pfn,
						unsigned long to_pfn,
						long result,
						void *caller)
{
#ifndef NACC_LOG_DEBUG
	(void)stage;
	(void)to;
	(void)from;
	(void)vaddr;
	(void)vma;
	(void)root_pgd_pa;
	(void)from_pfn;
	(void)to_pfn;
	(void)result;
	(void)caller;
#else
	struct mm_struct *mm = vma ? vma->vm_mm : NULL;
	unsigned long vm_start = vma ? vma->vm_start : 0;
	unsigned long vm_end = vma ? vma->vm_end : 0;
	unsigned long vm_flags = vma ? READ_ONCE(vma->vm_flags) : 0;
	unsigned long vm_pgoff = vma ? vma->vm_pgoff : 0;
	unsigned long mm_state = mm ? nacc_mm_state(mm) : 0;
	int from_map;
	int to_map;

	from_map = atomic_read(&from->_mapcount);
	from_map = page_mapcount_is_type(from_map) ? 0 : from_map + 1;
	to_map = atomic_read(&to->_mapcount);
	to_map = page_mapcount_is_type(to_map) ? 0 : to_map + 1;

	nacc_debug("[NACC][copy-user-highpage] linux %s comm=%s pid=%d tgid=%d caller=%pS mm=%px mm_state=%lx vaddr=%lx root=%lx vma=[%lx,%lx) vm_flags=%lx vm_pgoff=%lx has_file=%u from_pfn=%lx from_ref=%d from_map=%d to_pfn=%lx to_ref=%d to_map=%d result=%s(%ld)\n",
		   stage, current->comm, current->pid, current->tgid, caller,
		   mm, mm_state, vaddr, root_pgd_pa, vm_start, vm_end,
		   vm_flags, vm_pgoff, vma && vma->vm_file, from_pfn,
		   page_ref_count(from), from_map, to_pfn, page_ref_count(to),
		   to_map,
		   nacc_copy_user_highpage_result_name(result), result);
#endif
}

bool nacc_copy_mc_user_highpage_sbi(struct page *to, struct page *from,
				    unsigned long vaddr,
				    struct vm_area_struct *vma)
{
	struct sbiret ret;
	unsigned long from_pfn;
	unsigned long to_pfn;
	unsigned long root_pgd_pa;
	void *caller = __builtin_return_address(0);

	if (!vma || !vma->vm_mm || !nacc_mm_is_active(vma->vm_mm))
		return false;

	from_pfn = page_to_pfn(from);
	to_pfn = page_to_pfn(to);
	root_pgd_pa = __pa(vma->vm_mm->pgd);

	nacc_log_copy_user_highpage_context("enter", to, from, vaddr, vma,
					    root_pgd_pa, from_pfn, to_pfn,
					    -1, caller);

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_COPY_USER_HIGHPAGE,
			from_pfn, to_pfn, vaddr, root_pgd_pa,
			current->pid, 0);
	if (ret.error) {
		printk(KERN_ERR "[NACC][copy-user-highpage] linux ecall failed comm=%s pid=%d caller=%pS vaddr=%lx root=%lx from_pfn=%lx to_pfn=%lx err=%ld val=%ld\n",
		       current->comm, current->pid, caller, vaddr, root_pgd_pa,
		       from_pfn, to_pfn, ret.error, ret.value);
		panic("NaCC copy_user_highpage ecall failed");
	}

	nacc_log_copy_user_highpage_context("result", to, from, vaddr, vma,
					    root_pgd_pa, from_pfn, to_pfn,
					    ret.value, caller);

	switch (ret.value) {
	case NACC_COPY_USER_HIGHPAGE_NOT_HANDLED:
		return false;
	case NACC_COPY_USER_HIGHPAGE_HANDLED:
		return true;
	default:
		panic("NaCC copy_user_highpage ecall returned unknown result");
	}
}
EXPORT_SYMBOL(nacc_copy_mc_user_highpage_sbi);

void nacc_cow_replace_sbi(unsigned long ptep_pa,
			  unsigned long expected_old_pte,
			  unsigned long requested_pte,
			  unsigned long vaddr,
			  unsigned long root_pgd_pa,
			  unsigned long destination_pfn)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_COW_REPLACE,
			ptep_pa, expected_old_pte, requested_pte, vaddr,
			root_pgd_pa, destination_pfn);
	if (ret.error) {
		pr_err("[NACC][cow-replace] rejected ptep_pa=%lx old=%lx requested=%lx va=%lx root=%lx destination_pfn=%lx err=%ld\n",
		       ptep_pa, expected_old_pte, requested_pte, vaddr,
		       root_pgd_pa, destination_pfn, ret.error);
		panic("NaCC COW_REPLACE failed");
	}
}
EXPORT_SYMBOL(nacc_cow_replace_sbi);

void nacc_fork_copy_install_sbi(unsigned long ptep_pa,
				unsigned long expected_parent_pte,
				unsigned long requested_child_pte,
				unsigned long vaddr,
				unsigned long child_root_pgd_pa,
				unsigned long destination_pfn)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_FORK_COPY_INSTALL,
			ptep_pa, expected_parent_pte, requested_child_pte,
			vaddr, child_root_pgd_pa, destination_pfn);
	if (ret.error) {
		pr_err("[NACC][fork-copy-install] rejected ptep_pa=%lx parent=%lx requested=%lx va=%lx child_root=%lx destination_pfn=%lx err=%ld\n",
		       ptep_pa, expected_parent_pte, requested_child_pte, vaddr,
		       child_root_pgd_pa, destination_pfn, ret.error);
		panic("NaCC FORK_COPY_INSTALL failed");
	}
}
EXPORT_SYMBOL(nacc_fork_copy_install_sbi);

struct nacc_leaf_detach_stats {
	unsigned long vmas;
	unsigned long private_hint_vmas;
	unsigned long resident_ptes;
	unsigned long resident_skipped_ptes;
	unsigned long already_nacc_ptes;
	unsigned long special_ptes;
	unsigned long vdso_text_vmas;
	unsigned long vdso_text_adopted;
	unsigned long non_user_ptes;
	unsigned long empty_ptes;
};

static bool nacc_vma_private_anon_hint(struct vm_area_struct *vma)
{
	if (!vma)
		return false;
	if (vma->vm_file)
		return false;
	if (vma->vm_flags & (VM_NACC | VM_IO | VM_PFNMAP | VM_MIXEDMAP))
		return false;
	if (vma->vm_flags & (VM_SHARED | VM_MAYSHARE))
		return false;

	return vma_is_anonymous(vma);
}

static bool nacc_pte_is_linux_special_leaf(pte_t pte)
{
	if (pte_special(pte))
		return true;
#ifdef CONFIG_ARCH_HAS_PTE_DEVMAP
	if (pte_devmap(pte))
		return true;
#endif
	return false;
}

static int nacc_detach_pre_vma(unsigned long start, unsigned long end,
			       struct mm_walk *walk)
{
	struct nacc_leaf_detach_stats *stats = walk->private;

	if (walk->vma) {
		stats->vmas++;
		if (nacc_vma_is_vdso_text(walk->vma)) {
			bool had_mixedmap;
			unsigned long flags_before;
			int ret;

			stats->vdso_text_vmas++;
			if (walk->vma->vm_flags & VM_PFNMAP)
				return -EINVAL;
			flags_before = walk->vma->vm_flags;
			had_mixedmap = walk->vma->vm_flags & VM_MIXEDMAP;
			nacc_debug("[NACC][vdso-detach] enter pid=%d comm=%s mm=%px root=%lx vma=[%lx,%lx) flags=%lx had_mixedmap=%d\n",
				   current->pid, current->comm, walk->mm,
				   walk->mm ? __pa(walk->mm->pgd) : 0,
				   walk->vma->vm_start, walk->vma->vm_end,
				   flags_before, had_mixedmap);
			if (!had_mixedmap)
				vm_flags_set(walk->vma, VM_MIXEDMAP);
			ret = nacc_adopt_vdso_text(walk->vma);
			nacc_debug("[NACC][vdso-detach] adopt-return pid=%d comm=%s mm=%px root=%lx vma=[%lx,%lx) flags_before=%lx flags_after=%lx ret=%d\n",
				   current->pid, current->comm, walk->mm,
				   walk->mm ? __pa(walk->mm->pgd) : 0,
				   walk->vma->vm_start, walk->vma->vm_end,
				   flags_before, walk->vma->vm_flags, ret);
			if (ret) {
				if (!had_mixedmap)
					vm_flags_clear(walk->vma, VM_MIXEDMAP);
				nacc_debug("[NACC][vdso-detach] rollback pid=%d comm=%s mm=%px root=%lx vma=[%lx,%lx) flags_now=%lx ret=%d\n",
					   current->pid, current->comm, walk->mm,
					   walk->mm ? __pa(walk->mm->pgd) : 0,
					   walk->vma->vm_start, walk->vma->vm_end,
					   walk->vma->vm_flags, ret);
				return ret;
			}
			stats->vdso_text_adopted++;
		}
		if (nacc_vma_private_anon_hint(walk->vma)) {
			vm_flags_set(walk->vma, VM_NACC_APP);
			stats->private_hint_vmas++;
		}
	}

	return 0;
}

static int nacc_detach_pte_entry(pte_t *ptep, unsigned long addr,
				 unsigned long next, struct mm_walk *walk)
{
	struct nacc_leaf_detach_stats *stats = walk->private;
	pte_t oldpte;

	oldpte = ptep_get(ptep);
	if (!pte_present(oldpte)) {
		stats->empty_ptes++;
		return 0;
	}

	if (!pte_user(oldpte)) {
		stats->non_user_ptes++;
		return 0;
	}

	if (pte_nacc(oldpte))
		stats->already_nacc_ptes++;
	else if (!nacc_vma_private_anon_hint(walk->vma))
		stats->resident_skipped_ptes++;
	else if (nacc_pte_is_linux_special_leaf(oldpte)) {
		stats->special_ptes++;
		if (nacc_vma_is_vvar_abi_data(walk->vma) &&
		    nacc_record_vvar_sbi(__pa(walk->mm->pgd), addr,
					 pte_pfn(oldpte)))
			return -EIO;
	} else {
		nacc_update_pte_sbi(NACC_UPDATE_PTE_XCHG_ONE, __pa(ptep),
				    pte_val(pte_mknacc(oldpte)), addr,
				    __pa(walk->mm->pgd), 0);
		stats->resident_ptes++;
	}

	return 0;
}

int nacc_detach_user_leaf_pages(struct mm_struct *mm, const char *tag)
{
	static const struct mm_walk_ops nacc_detach_walk_ops = {
		.pre_vma = nacc_detach_pre_vma,
		.pte_entry = nacc_detach_pte_entry,
		.walk_lock = PGWALK_WRLOCK,
	};
	struct nacc_leaf_detach_stats stats = { 0 };
	unsigned long end;
	int ret;

	if (!mm)
		return -EINVAL;

	end = min_t(unsigned long, TASK_SIZE, NACC_USER_VPN2_PROTECTED_END);

	ret = mmap_write_lock_killable(mm);
	if (ret) {
		printk(KERN_ERR "[Linux]: nacc_detach_user_leaf_pages: mmap lock failed tag=%s mm=%px err=%d\n",
		       tag, mm, ret);
		return ret;
	}

	ret = walk_page_range(mm, 0, end, &nacc_detach_walk_ops, &stats);
	mmap_write_unlock(mm);

	if (!ret)
		flush_tlb_mm(mm);

	nacc_debug("[Linux]: nacc_detach_user_leaf_pages tag=%s mm=%px ret=%d range=[0,%lx) vmas=%lu private_hint_vmas=%lu tagged_resident_ptes=%lu resident_skipped=%lu already_nacc=%lu special=%lu non_user=%lu empty=%lu\n",
		   tag, mm, ret, end, stats.vmas, stats.private_hint_vmas,
		   stats.resident_ptes, stats.resident_skipped_ptes,
		   stats.already_nacc_ptes, stats.special_ptes,
		   stats.non_user_ptes, stats.empty_ptes);
	nacc_debug("[Linux]: nacc_detach_user_leaf_pages vdso tag=%s mm=%px vdso_text_vmas=%lu vdso_text_adopted=%lu\n",
		   tag, mm, stats.vdso_text_vmas, stats.vdso_text_adopted);

	return ret;
}
EXPORT_SYMBOL(nacc_detach_user_leaf_pages);

static const char *nacc_uaccess_scope_class_name(enum nacc_uaccess_scope_class scope_class)
{
	switch (scope_class) {
	case NACC_UACCESS_SCOPE_STRING_READ:
		return "string_read";
	case NACC_UACCESS_SCOPE_CLASS_UNKNOWN:
	default:
		return "unknown";
	}
}

static const char *nacc_uaccess_scope_direction_name(enum nacc_uaccess_scope_direction direction)
{
	switch (direction) {
	case NACC_UACCESS_SCOPE_DIR_FROM_USER:
		return "from_user";
	case NACC_UACCESS_SCOPE_DIR_TO_USER:
		return "to_user";
	case NACC_UACCESS_SCOPE_DIR_UNKNOWN:
	default:
		return "unknown";
	}
}

static unsigned long nacc_user_access_save_enable(void)
{
	unsigned long status = csr_read(CSR_STATUS);

	if (!(status & SR_SUM))
		csr_set(CSR_STATUS, SR_SUM);
	return status;
}

static void nacc_user_access_restore(unsigned long status)
{
	if (!(status & SR_SUM))
		csr_clear(CSR_STATUS, SR_SUM);
}

bool nacc_uaccess_scope_begin(enum nacc_uaccess_scope_class scope_class,
			      enum nacc_uaccess_scope_direction direction,
			      unsigned long user_va,
			      unsigned long bytes,
			      unsigned long caller_pc)
{
	struct sbiret ret;
	unsigned long status;

	if (!current->mm || !current->mm->pgd)
		return true;
	if (!current->thread.nacc_cid)
		return true;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return true;
	if (!bytes)
		return false;

	status = nacc_user_access_save_enable();
	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_BEGIN,
			scope_class, direction, user_va, bytes, 0,
			current->pid);
	nacc_user_access_restore(status);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[NACC][uaccess-scope-begin-failed] pid=%d comm=%s cid=%lx class=%s direction=%s user_va=%lx bytes=%lu caller=%lx err=%ld val=%ld\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid,
				   nacc_uaccess_scope_class_name(scope_class),
				   nacc_uaccess_scope_direction_name(direction),
				   user_va, bytes, caller_pc, ret.error,
				   ret.value);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(nacc_uaccess_scope_begin);

int nacc_uaccess_string_read_begin(unsigned long user_va,
				   unsigned long bytes,
				   struct nacc_uaccess_string_read_desc *desc)
{
	struct sbiret ret;
	unsigned long status;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!current->thread.nacc_cid)
		return 0;
	if (current->thread.nacc_flag & NACC_EXEC)
		return 0;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return 0;
	if (!bytes || !desc)
		return -EFAULT;
	if (desc->version != NACC_UACCESS_STRING_READ_DESC_VERSION)
		return -EFAULT;

	status = nacc_user_access_save_enable();
	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_BEGIN,
			NACC_UACCESS_SCOPE_STRING_READ,
			NACC_UACCESS_SCOPE_DIR_FROM_USER,
			user_va, bytes, (unsigned long)desc, current->pid);
	nacc_user_access_restore(status);
	if (!ret.error)
		return 1;
	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		return 0;

	printk_ratelimited(KERN_ERR "[NACC][uaccess-string-read-begin-failed] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu op=%lu buffer_va=%lx buffer_bytes=%lu caller=%lx err=%ld val=%ld\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   user_va, bytes, desc->op, desc->buffer_va,
			   desc->buffer_bytes, desc->caller_pc, ret.error,
			   ret.value);
	return -EFAULT;
}
EXPORT_SYMBOL(nacc_uaccess_string_read_begin);

bool nacc_uaccess_scope_end(enum nacc_uaccess_scope_class scope_class,
			    enum nacc_uaccess_scope_direction direction,
			    unsigned long user_va,
			    unsigned long bytes,
			    long result)
{
	struct sbiret ret;

	if (!current->mm || !current->mm->pgd)
		return true;
	if (!current->thread.nacc_cid)
		return true;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return true;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_END,
			scope_class, direction, user_va, bytes,
			(unsigned long)result, current->pid);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[NACC][uaccess-scope-end-failed] pid=%d comm=%s cid=%lx class=%s direction=%s user_va=%lx bytes=%lu result=%ld err=%ld val=%ld\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid,
				   nacc_uaccess_scope_class_name(scope_class),
				   nacc_uaccess_scope_direction_name(direction),
				   user_va, bytes, result, ret.error,
				   ret.value);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(nacc_uaccess_scope_end);

int nacc_private_data_get_user_read(unsigned long user_va,
				    unsigned long bytes,
				    unsigned long *value)
{
	struct sbiret ret;

	if (value)
		*value = 0;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!current->thread.nacc_cid)
		return 0;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return 0;
	if (!value)
		return -EFAULT;
	if ((bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
	    bytes > sizeof(unsigned long))
		return 0;

	ret = sbi_ecall(SBI_EXT_NACC,
			SBI_EXT_NACC_UACCESS_PRIVATE_GET_USER_READ,
			user_va, bytes, 0, 0, 0, 0);
	if (!ret.error) {
		*value = ret.value;
		return 1;
	}

	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		return 0;

	printk_ratelimited(KERN_ERR "[NACC][private-get-user-read-denied] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu err=%ld val=%ld\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   user_va, bytes, ret.error, ret.value);
	return -EFAULT;
}
EXPORT_SYMBOL(nacc_private_data_get_user_read);

static int nacc_private_data_fault_in_writeable(unsigned long user_va,
						unsigned long bytes)
{
	unsigned long status;
	size_t left;

	status = csr_read(CSR_STATUS);
	if (status & SR_SUM)
		csr_clear(CSR_STATUS, SR_SUM);

	left = fault_in_safe_writeable((const char __user *)user_va, bytes);

	if (status & SR_SUM)
		csr_set(CSR_STATUS, SR_SUM);

	return left ? -EFAULT : 0;
}

static int nacc_private_data_fault_in_readable(unsigned long user_va,
					       unsigned long bytes)
{
	unsigned long start = user_va;
	unsigned long end;
	struct mm_struct *mm = current->mm;
	bool unlocked = false;
	int ret = 0;

	if (!mm)
		return -EFAULT;
	if (!bytes)
		return 0;

	end = PAGE_ALIGN(start + bytes);
	if (end < start)
		return -EFAULT;

	mmap_read_lock(mm);
	do {
		ret = fixup_user_fault(mm, start, 0, &unlocked);
		if (ret)
			break;
		start = (start + PAGE_SIZE) & PAGE_MASK;
	} while (start != end);
	mmap_read_unlock(mm);

	return ret;
}

int nacc_private_data_put_user_write(unsigned long user_va,
				     const void *value,
				     unsigned long bytes)
{
	struct sbiret ret;
	bool cow_retried = false;
	u64 raw = 0;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!value)
		return -EFAULT;
	if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
		return 0;

	memcpy(&raw, value, bytes);
retry:
	ret = sbi_ecall(SBI_EXT_NACC,
			SBI_EXT_NACC_UACCESS_PRIVATE_PUT_USER_WRITE,
			user_va, (unsigned long)raw,
			(unsigned long)(raw >> 32), bytes, 0,
			current->pid);
	if (!ret.error)
		return 1;
	/* NaCC uses DENIED_LOCKED as private put_user COW-needed. */
	if (ret.error == SBI_ERR_DENIED_LOCKED && !cow_retried) {
		int fault_ret;

		cow_retried = true;
		fault_ret = nacc_private_data_fault_in_writeable(user_va,
								 bytes);
		if (!fault_ret)
			goto retry;

		printk_ratelimited(KERN_ERR "[NACC][private-put-user-cow-failed] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu err=%d\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid, user_va, bytes,
				   fault_ret);
		return -EFAULT;
	}
	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		return 0;

	printk_ratelimited(KERN_ERR "[NACC][private-put-user-write-denied] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu err=%ld val=%ld\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   user_va, bytes, ret.error, ret.value);
	return -EFAULT;
}
EXPORT_SYMBOL(nacc_private_data_put_user_write);

int nacc_private_data_copy_to_user(unsigned long user_va,
				   unsigned long kernel_va,
				   unsigned long bytes,
				   unsigned long caller_pc,
				   unsigned long *left)
{
	unsigned long copied = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}

	while (copied < bytes) {
		unsigned long dst = user_va + copied;
		unsigned long src = kernel_va + copied;
		unsigned long chunk = bytes - copied;
		unsigned long page_left;
		struct sbiret ret;
		bool write_fault_retried = false;

		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;
		page_left = PAGE_SIZE - (src & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

retry:
		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_UACCESS_PRIVATE_COPY_TO_USER,
				dst, src, chunk, caller_pc, current->pid, 0);
		if ((ret.error == SBI_ERR_NOT_SUPPORTED ||
		     ret.error == SBI_ERR_DENIED_LOCKED) &&
		    !write_fault_retried) {
			int fault_ret;

			write_fault_retried = true;
			fault_ret = nacc_private_data_fault_in_writeable(dst,
									 chunk);
			if (!fault_ret)
				goto retry;

			printk_ratelimited(KERN_ERR "[NACC][private-copy-to-user-prefault-failed] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx bytes=%lu dst=%lx src=%lx chunk=%lu copied=%lu sbi_err=%ld err=%d\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   user_va, kernel_va, bytes, dst,
					   src, chunk, copied, ret.error,
					   fault_ret);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			/*
			 * After one successful write-prefault, preserve the
			 * existing fallback contract for non-private/unhandled
			 * destinations.
			 */
			if (!copied)
				return 0;
			*left = bytes - copied;
			return 1;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-to-user-denied] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   user_va, kernel_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-to-user-bad-result] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   dst, src, chunk, copied,
					   ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}

		copied += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacc_private_data_copy_to_user);

int nacc_private_data_copy_from_user(unsigned long kernel_va,
				     unsigned long user_va,
				     unsigned long bytes,
				     unsigned long caller_pc,
				     unsigned long *left)
{
	unsigned long copied = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}

	while (copied < bytes) {
		unsigned long dst = kernel_va + copied;
		unsigned long src = user_va + copied;
		unsigned long chunk = bytes - copied;
		unsigned long page_left;
		struct sbiret ret;
		bool read_fault_retried = false;

		page_left = PAGE_SIZE - (src & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;
		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

	retry:
		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_UACCESS_PRIVATE_COPY_FROM_USER,
				src, dst, chunk, caller_pc, current->pid, 0);
		if (ret.error == SBI_ERR_NOT_SUPPORTED &&
		    !read_fault_retried) {
			int fault_ret;

			/*
			 * A missing leaf can become private while normal uaccess
			 * faults it in. Prefault first so M-mode can handle the retry.
			 */
			read_fault_retried = true;
			fault_ret = nacc_private_data_fault_in_readable(src,
								chunk);
			if (!fault_ret)
				goto retry;

			printk_ratelimited(KERN_ERR "[NACC][private-copy-from-user-prefault-failed] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx bytes=%lu dst=%lx src=%lx chunk=%lu copied=%lu err=%d\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   kernel_va, user_va, bytes, dst, src,
					   chunk, copied, fault_ret);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			if (!copied)
				return 0;
			*left = bytes - copied;
			return 1;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-from-user-denied] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   kernel_va, user_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-from-user-bad-result] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   dst, src, chunk, copied,
					   ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}

		copied += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacc_private_data_copy_from_user);

int nacc_private_data_copy_kernel_alias(unsigned long destination_kernel_va,
					unsigned long source_kernel_va,
					unsigned long bytes,
					unsigned long caller_pc,
					unsigned long *left)
{
	unsigned long copied = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}

	while (copied < bytes) {
		unsigned long dst = destination_kernel_va + copied;
		unsigned long src = source_kernel_va + copied;
		unsigned long chunk = bytes - copied;
		unsigned long page_left;
		unsigned long status;
		struct sbiret ret;

		page_left = PAGE_SIZE - (src & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;
		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

		status = nacc_user_access_save_enable();
		ret = sbi_ecall(
			SBI_EXT_NACC,
			SBI_EXT_NACC_UACCESS_PRIVATE_COPY_KERNEL_ALIAS,
			src, dst, chunk, caller_pc, current->pid, 0);
		nacc_user_access_restore(status);

		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			if (!copied)
				return 0;
			*left = bytes - copied;
			return 1;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACC][private-kernel-alias-copy-denied] pid=%d comm=%s cid=%lx dst=%lx src=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   destination_kernel_va,
					   source_kernel_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACC][private-kernel-alias-copy-bad-result] pid=%d comm=%s cid=%lx dst=%lx src=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid, dst, src,
					   chunk, copied, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}

		copied += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacc_private_data_copy_kernel_alias);

int nacc_private_data_clear_user(unsigned long user_va,
				 unsigned long bytes,
				 unsigned long caller_pc,
				 unsigned long *left)
{
	unsigned long cleared = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}

	while (cleared < bytes) {
		unsigned long dst = user_va + cleared;
		unsigned long chunk = bytes - cleared;
		unsigned long page_left;
		unsigned long status;
		struct sbiret ret;

		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

		status = csr_read(CSR_STATUS);
		if (!(status & SR_SUM))
			csr_set(CSR_STATUS, SR_SUM);
		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_UACCESS_PRIVATE_CLEAR_USER,
				dst, chunk, caller_pc, current->pid, 0, 0);
		if (!(status & SR_SUM))
			csr_clear(CSR_STATUS, SR_SUM);

		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			if (!cleared)
				return 0;
			*left = bytes - cleared;
			return 1;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACC][private-clear-user-denied] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu cleared=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   user_va, bytes, cleared,
					   ret.error, ret.value);
			*left = bytes - cleared;
			return cleared ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACC][private-clear-user-bad-result] pid=%d comm=%s cid=%lx user_va=%lx chunk=%lu cleared=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   dst, chunk, cleared,
					   ret.value);
			*left = bytes - cleared;
			return cleared ? 1 : -EFAULT;
		}

		cleared += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacc_private_data_clear_user);

void pgtbl_debug(unsigned long pgd)
{
#ifdef NACC_LOG_DEBUG
    struct sbiret ret;

    nacc_debug("[Linux]: calling pgtbl_debug SBI call pgd=%lx\n", pgd);
    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_DEBUG,
                    pgd, 0,
                    0, 0, 0, 0);
    nacc_debug("[Linux]: pgtbl_debug SBI returned error=%ld value=%ld\n",
               ret.error, ret.value);
#else
    (void)pgd;
#endif
}
