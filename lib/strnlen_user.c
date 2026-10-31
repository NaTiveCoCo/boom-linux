// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/instruction_pointer.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/bitops.h>

#include <asm/word-at-a-time.h>

#ifdef NACRE
static __always_inline long nacre_strnlen_user_staged_result(
	const struct nacre_uaccess_string_read_desc *desc,
	unsigned long count, unsigned long max)
{
	if (desc->nul_index != NACRE_UACCESS_STRING_READ_NO_NUL)
		return desc->nul_index + 1;
	if (max >= count)
		return count + 1;
	return 0;
}

static __always_inline void nacre_strnlen_user_init_desc(
	struct nacre_uaccess_string_read_desc *desc, unsigned long count,
	unsigned long caller_pc)
{
	*desc = (struct nacre_uaccess_string_read_desc) {
		.version = NACRE_UACCESS_STRING_READ_DESC_VERSION,
		.op = NACRE_UACCESS_STRING_READ_OP_MEASURE_CSTR,
		.count = count,
		.nul_index = NACRE_UACCESS_STRING_READ_NO_NUL,
		.caller_pc = caller_pc,
	};
}
#endif

/*
 * Do a strnlen, return length of string *with* final '\0'.
 * 'count' is the user-supplied count, while 'max' is the
 * address space maximum.
 *
 * Return 0 for exceptions (which includes hitting the address
 * space maximum), or 'count+1' if hitting the user-supplied
 * maximum count.
 *
 * NOTE! We can sometimes overshoot the user-supplied maximum
 * if it fits in a aligned 'long'. The caller needs to check
 * the return value against "> max".
 */
static __always_inline long do_strnlen_user(const char __user *src, unsigned long count, unsigned long max)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	unsigned long align, res = 0;
	unsigned long c;

	/*
	 * Do everything aligned. But that means that we
	 * need to also expand the maximum..
	 */
	align = (sizeof(unsigned long) - 1) & (unsigned long)src;
	src -= align;
	max += align;

	unsafe_get_user(c, (unsigned long __user *)src, efault);
	c |= aligned_byte_mask(align);

	for (;;) {
		unsigned long data;
		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			return res + find_zero(data) + 1 - align;
		}
		res += sizeof(unsigned long);
		/* We already handled 'unsigned long' bytes. Did we do it all ? */
		if (unlikely(max <= sizeof(unsigned long)))
			break;
		max -= sizeof(unsigned long);
		unsafe_get_user(c, (unsigned long __user *)(src+res), efault);
	}
	res -= align;

	/*
	 * Uhhuh. We hit 'max'. But was that the user-specified maximum
	 * too? If so, return the marker for "too long".
	 */
	if (res >= count)
		return count+1;

	/*
	 * Nope: we hit the address space limit, and we still had more
	 * characters the caller would have wanted. That's 0.
	 */
efault:
	return 0;
}

/**
 * strnlen_user: - Get the size of a user string INCLUDING final NUL.
 * @str: The string to measure.
 * @count: Maximum count (including NUL character)
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * If the string is too long, returns a number larger than @count. User
 * has to check the return value against "> count".
 * On exception (or invalid count), returns 0.
 *
 * NOTE! You should basically never use this function. There is
 * almost never any valid case for using the length of a user space
 * string, since the string can be changed at any time by other
 * threads. Use "strncpy_from_user()" instead to get a stable copy
 * of the string.
 */
long strnlen_user(const char __user *str, long count)
{
	unsigned long max_addr, src_addr;

	if (unlikely(count <= 0))
		return 0;

	if (can_do_masked_user_access()) {
		long retval;
#ifdef NACRE
		struct nacre_uaccess_string_read_desc nacre_desc;
		int nacre_ret;
#endif

		str = masked_user_access_begin(str);
#ifdef NACRE
		nacre_strnlen_user_init_desc(&nacre_desc, count, _RET_IP_);
		nacre_ret = nacre_uaccess_string_read_begin((unsigned long)str,
							  count, &nacre_desc);
		if (nacre_ret > 0) {
			retval = nacre_strnlen_user_staged_result(&nacre_desc,
								 count, count);
			if (!nacre_uaccess_scope_end(
				    NACRE_UACCESS_SCOPE_STRING_READ,
				    NACRE_UACCESS_SCOPE_DIR_FROM_USER,
				    (unsigned long)str, count, retval))
				retval = 0;
			user_read_access_end();
			return retval;
		}
		if (nacre_ret < 0) {
			user_read_access_end();
			return 0;
		}
#endif
		retval = do_strnlen_user(str, count, count);
		user_read_access_end();
		return retval;
	}

	max_addr = TASK_SIZE_MAX;
	src_addr = (unsigned long)untagged_addr(str);
	if (likely(src_addr < max_addr)) {
		unsigned long max = max_addr - src_addr;
		long retval;
#ifdef NACRE
		struct nacre_uaccess_string_read_desc nacre_desc;
		int nacre_ret;
#endif

		/*
		 * Truncate 'max' to the user-specified limit, so that
		 * we only have one limit we need to check in the loop
		 */
		if (max > count)
			max = count;

		if (user_read_access_begin(str, max)) {
#ifdef NACRE
			nacre_strnlen_user_init_desc(&nacre_desc, count, _RET_IP_);
			nacre_ret = nacre_uaccess_string_read_begin(
				(unsigned long)str, max, &nacre_desc);
			if (nacre_ret > 0) {
				retval = nacre_strnlen_user_staged_result(
					&nacre_desc, count, max);
				if (!nacre_uaccess_scope_end(
					    NACRE_UACCESS_SCOPE_STRING_READ,
					    NACRE_UACCESS_SCOPE_DIR_FROM_USER,
					    (unsigned long)str, max,
					    retval))
					retval = 0;
				user_read_access_end();
				return retval;
			}
			if (nacre_ret < 0) {
				user_read_access_end();
				return 0;
			}
#endif
			retval = do_strnlen_user(str, count, max);
			user_read_access_end();
			return retval;
		}
	}
	return 0;
}
EXPORT_SYMBOL(strnlen_user);
