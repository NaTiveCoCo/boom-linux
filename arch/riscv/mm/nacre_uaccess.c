#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/panic.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/page_ref.h>
#include <linux/string.h>
#include <asm/nacre.h>
#include <asm/nacre_registration.h>

#include <asm/sbi.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/csr.h>
#include <asm/tlbflush.h>


bool nacre_copy_mc_user_highpage_sbi(struct page *to, struct page *from,
				    unsigned long vaddr,
				    struct vm_area_struct *vma)
{
	unsigned long left;
	void *caller = __builtin_return_address(0);
	int handled;

	(void)vaddr;
	if (!PageNacre(from) && !PageNacre(to))
		return false;

	BUG_ON(!vma || !nacre_private_data_uaccess_active() ||
	       vma->vm_mm != current->mm);
	handled = nacre_private_data_copy_kernel_alias(
		(unsigned long)page_address(to),
		(unsigned long)page_address(from), PAGE_SIZE,
		(unsigned long)caller, &left);
	BUG_ON(handled != 1 || left);
	return true;
}
EXPORT_SYMBOL(nacre_copy_mc_user_highpage_sbi);

static const char *nacre_uaccess_scope_class_name(enum nacre_uaccess_scope_class scope_class)
{
	switch (scope_class) {
	case NACRE_UACCESS_SCOPE_STRING_READ:
		return "string_read";
	case NACRE_UACCESS_SCOPE_CLASS_UNKNOWN:
	default:
		return "unknown";
	}
}

static const char *nacre_uaccess_scope_direction_name(enum nacre_uaccess_scope_direction direction)
{
	switch (direction) {
	case NACRE_UACCESS_SCOPE_DIR_FROM_USER:
		return "from_user";
	case NACRE_UACCESS_SCOPE_DIR_TO_USER:
		return "to_user";
	case NACRE_UACCESS_SCOPE_DIR_UNKNOWN:
	default:
		return "unknown";
	}
}

static unsigned long nacre_user_access_save_enable(void)
{
	unsigned long status = csr_read(CSR_STATUS);

	if (!(status & SR_SUM))
		csr_set(CSR_STATUS, SR_SUM);
	return status;
}

static void nacre_user_access_restore(unsigned long status)
{
	if (!(status & SR_SUM))
		csr_clear(CSR_STATUS, SR_SUM);
}

bool nacre_uaccess_scope_begin(enum nacre_uaccess_scope_class scope_class,
			      enum nacre_uaccess_scope_direction direction,
			      unsigned long user_va,
			      unsigned long bytes,
			      unsigned long caller_pc)
{
	struct sbiret ret;
	unsigned long status;

	if (!current->mm || !current->mm->pgd)
		return true;
	if (!nacre_private_data_uaccess_active())
		return true;
	if (!bytes)
		return false;

	status = nacre_user_access_save_enable();
	ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_UACCESS_SCOPE_BEGIN,
			scope_class, direction, user_va, bytes, 0,
			current->pid);
	nacre_user_access_restore(status);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[NACRE][uaccess-scope-begin-failed] pid=%d comm=%s cid=%lx class=%s direction=%s user_va=%lx bytes=%lu caller=%lx err=%ld val=%ld\n",
				   current->pid, current->comm,
				   current->thread.nacre_cid,
				   nacre_uaccess_scope_class_name(scope_class),
				   nacre_uaccess_scope_direction_name(direction),
				   user_va, bytes, caller_pc, ret.error,
				   ret.value);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(nacre_uaccess_scope_begin);

int nacre_uaccess_string_read_begin(unsigned long user_va,
				   unsigned long bytes,
				   struct nacre_uaccess_string_read_desc *desc)
{
	struct sbiret ret;
	unsigned long status;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacre_private_data_uaccess_active())
		return 0;
	if (!bytes || !desc)
		return -EFAULT;
	if (desc->version != NACRE_UACCESS_STRING_READ_DESC_VERSION)
		return -EFAULT;

	status = nacre_user_access_save_enable();
	ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_UACCESS_SCOPE_BEGIN,
			NACRE_UACCESS_SCOPE_STRING_READ,
			NACRE_UACCESS_SCOPE_DIR_FROM_USER,
			user_va, bytes, (unsigned long)desc, current->pid);
	nacre_user_access_restore(status);
	if (!ret.error)
		return 1;
	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		return 0;

	printk_ratelimited(KERN_ERR "[NACRE][uaccess-string-read-begin-failed] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu op=%lu buffer_va=%lx buffer_bytes=%lu caller=%lx err=%ld val=%ld\n",
			   current->pid, current->comm, current->thread.nacre_cid,
			   user_va, bytes, desc->op, desc->buffer_va,
			   desc->buffer_bytes, desc->caller_pc, ret.error,
			   ret.value);
	return -EFAULT;
}
EXPORT_SYMBOL(nacre_uaccess_string_read_begin);

bool nacre_uaccess_scope_end(enum nacre_uaccess_scope_class scope_class,
			    enum nacre_uaccess_scope_direction direction,
			    unsigned long user_va,
			    unsigned long bytes,
			    long result)
{
	struct sbiret ret;

	if (!current->mm || !current->mm->pgd)
		return true;
	if (!nacre_private_data_uaccess_active())
		return true;

	ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_UACCESS_SCOPE_END,
			scope_class, direction, user_va, bytes,
			(unsigned long)result, current->pid);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[NACRE][uaccess-scope-end-failed] pid=%d comm=%s cid=%lx class=%s direction=%s user_va=%lx bytes=%lu result=%ld err=%ld val=%ld\n",
				   current->pid, current->comm,
				   current->thread.nacre_cid,
				   nacre_uaccess_scope_class_name(scope_class),
				   nacre_uaccess_scope_direction_name(direction),
				   user_va, bytes, result, ret.error,
				   ret.value);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(nacre_uaccess_scope_end);

static int nacre_private_data_fault_in_readable(unsigned long user_va, unsigned long bytes);
static int nacre_private_data_fault_in_writeable(unsigned long user_va, unsigned long bytes);

int nacre_private_data_get_user_read(unsigned long user_va,
				    unsigned long bytes, unsigned long *value)
{
	unsigned long done = 0, raw = 0;
	bool split = (user_va & (PAGE_SIZE - 1)) + bytes > PAGE_SIZE;
	if (!nacre_private_data_uaccess_active())
		return 0;
	BUG_ON(!value || (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8));
	*value = 0;
	while (done < bytes) {
		unsigned long chunk = split ? 1 : bytes;
		struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT,
			NACRE_UACCESS_PRIVATE_GET_USER_READ, user_va + done, chunk, 0, 0, 0, 0);
		if (ret.error == SBI_ERR_NOT_SUPPORTED &&
		    !nacre_private_data_fault_in_readable(user_va + done, chunk))
			ret = sbi_ecall(NACRE_SBI_REGISTER_EXT,
				NACRE_UACCESS_PRIVATE_GET_USER_READ, user_va + done, chunk, 0, 0, 0, 0);
		if (ret.error)
			return -EFAULT;
		raw |= (split ? (ret.value & 0xff) : ret.value) << (8 * done);
		done += chunk;
	}
	/* Match lb/lh/lw sign extension before the caller's C conversion. */
	*value = bytes == 1 ? (long)(s8)raw : bytes == 2 ? (long)(s16)raw :
		 bytes == 4 ? (long)(s32)raw : raw;
	return 1;
}
EXPORT_SYMBOL(nacre_private_data_get_user_read);

static int nacre_private_data_fault_in_writeable(unsigned long user_va,
						unsigned long bytes)
{
	unsigned long status;
	size_t left;

	if (pagefault_disabled() || in_atomic())
		return -EFAULT;
	status = csr_read(CSR_STATUS);
	if (status & SR_SUM)
		csr_clear(CSR_STATUS, SR_SUM);

	left = fault_in_safe_writeable((const char __user *)user_va, bytes);

	if (status & SR_SUM)
		csr_set(CSR_STATUS, SR_SUM);

	return left ? -EFAULT : 0;
}

static int nacre_private_data_fault_in_readable(unsigned long user_va,
					       unsigned long bytes)
{
	unsigned long start = user_va;
	unsigned long end;
	struct mm_struct *mm = current->mm;
	bool unlocked = false;
	int ret = 0;

	if (!mm || pagefault_disabled() || in_atomic())
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

int nacre_private_data_put_user_write(unsigned long user_va,
				     const void *value, unsigned long bytes)
{
	unsigned long done = 0;
	bool split = (user_va & (PAGE_SIZE - 1)) + bytes > PAGE_SIZE;
	u64 raw = 0;
	if (!nacre_private_data_uaccess_active())
		return 0;
	BUG_ON(!value || (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8));
	memcpy(&raw, value, bytes);
	while (done < bytes) {
		unsigned long chunk = split ? 1 : bytes;
		u64 part = raw >> (8 * done);
		struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT,
			NACRE_UACCESS_PRIVATE_PUT_USER_WRITE, user_va + done,
			part, part >> 32, chunk, 0, current->pid);
		if ((ret.error == SBI_ERR_NOT_SUPPORTED || ret.error == SBI_ERR_DENIED_LOCKED) &&
		    !nacre_private_data_fault_in_writeable(user_va + done, chunk))
			ret = sbi_ecall(NACRE_SBI_REGISTER_EXT,
				NACRE_UACCESS_PRIVATE_PUT_USER_WRITE, user_va + done,
				part, part >> 32, chunk, 0, current->pid);
		if (ret.error)
			return -EFAULT;
		done += chunk;
	}
	return 1;
}
EXPORT_SYMBOL(nacre_private_data_put_user_write);

int nacre_private_data_copy_to_user(unsigned long user_va,
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
	if (!nacre_private_data_uaccess_active())
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
		ret = sbi_ecall(NACRE_SBI_REGISTER_EXT,
				NACRE_UACCESS_PRIVATE_COPY_TO_USER,
				dst, src, chunk, caller_pc, current->pid, 0);
		if ((ret.error == SBI_ERR_NOT_SUPPORTED ||
		     ret.error == SBI_ERR_DENIED_LOCKED) &&
		    !write_fault_retried) {
			int fault_ret;

			write_fault_retried = true;
			fault_ret = nacre_private_data_fault_in_writeable(dst,
									 chunk);
			if (!fault_ret)
				goto retry;

			printk_ratelimited(KERN_ERR "[NACRE][private-copy-to-user-prefault-failed] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx bytes=%lu dst=%lx src=%lx chunk=%lu copied=%lu sbi_err=%ld err=%d\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
					   user_va, kernel_va, bytes, dst,
					   src, chunk, copied, ret.error,
					   fault_ret);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACRE][private-copy-to-user-denied] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
					   user_va, kernel_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACRE][private-copy-to-user-bad-result] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
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
EXPORT_SYMBOL(nacre_private_data_copy_to_user);

int nacre_private_data_copy_from_user(unsigned long kernel_va,
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
	if (!nacre_private_data_uaccess_active())
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
		ret = sbi_ecall(NACRE_SBI_REGISTER_EXT,
				NACRE_UACCESS_PRIVATE_COPY_FROM_USER,
				src, dst, chunk, caller_pc, current->pid, 0);
		if (ret.error == SBI_ERR_NOT_SUPPORTED &&
		    !read_fault_retried) {
			int fault_ret;

			/*
			 * A missing leaf can become private while normal uaccess
			 * faults it in. Prefault first so M-mode can handle the retry.
			 */
			read_fault_retried = true;
			fault_ret = nacre_private_data_fault_in_readable(src,
								chunk);
			if (!fault_ret)
				goto retry;

			printk_ratelimited(KERN_ERR "[NACRE][private-copy-from-user-prefault-failed] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx bytes=%lu dst=%lx src=%lx chunk=%lu copied=%lu err=%d\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
					   kernel_va, user_va, bytes, dst, src,
					   chunk, copied, fault_ret);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACRE][private-copy-from-user-denied] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
					   kernel_va, user_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACRE][private-copy-from-user-bad-result] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
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
EXPORT_SYMBOL(nacre_private_data_copy_from_user);

int nacre_private_data_copy_kernel_alias(unsigned long destination_kernel_va,
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
	if (!nacre_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}
	if (bytes > ULONG_MAX - destination_kernel_va ||
	    bytes > ULONG_MAX - source_kernel_va)
		return -EFAULT;

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

		status = nacre_user_access_save_enable();
		ret = sbi_ecall(
			NACRE_SBI_REGISTER_EXT,
			NACRE_UACCESS_PRIVATE_COPY_KERNEL_ALIAS,
			src, dst, chunk, caller_pc, current->pid, 0);
		nacre_user_access_restore(status);

		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			/* M checked both mappings and tags for this chunk only. */
			memcpy((void *)dst, (const void *)src, chunk);
			copied += chunk;
			continue;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACRE][private-kernel-alias-copy-denied] pid=%d comm=%s cid=%lx dst=%lx src=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
					   destination_kernel_va,
					   source_kernel_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACRE][private-kernel-alias-copy-bad-result] pid=%d comm=%s cid=%lx dst=%lx src=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid, dst, src,
					   chunk, copied, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}

		copied += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacre_private_data_copy_kernel_alias);

int nacre_private_data_clear_user(unsigned long user_va,
				 unsigned long bytes,
				 unsigned long caller_pc,
				 unsigned long *left)
{
	unsigned long cleared = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacre_private_data_uaccess_active())
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
		bool retried = false;

		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

retry:
		status = csr_read(CSR_STATUS);
		if (!(status & SR_SUM))
			csr_set(CSR_STATUS, SR_SUM);
		ret = sbi_ecall(NACRE_SBI_REGISTER_EXT,
				NACRE_UACCESS_PRIVATE_CLEAR_USER,
				dst, chunk, caller_pc, current->pid, 0, 0);
		if (!(status & SR_SUM))
			csr_clear(CSR_STATUS, SR_SUM);

		if ((ret.error == SBI_ERR_NOT_SUPPORTED || ret.error == SBI_ERR_DENIED_LOCKED) && !retried) {
			retried = true;
			if (!nacre_private_data_fault_in_writeable(dst, chunk))
				goto retry;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACRE][private-clear-user-denied] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu cleared=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
					   user_va, bytes, cleared,
					   ret.error, ret.value);
			*left = bytes - cleared;
			return cleared ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACRE][private-clear-user-bad-result] pid=%d comm=%s cid=%lx user_va=%lx chunk=%lu cleared=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacre_cid,
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
EXPORT_SYMBOL(nacre_private_data_clear_user);

