// SPDX-License-Identifier: GPL-2.0-only
/* Linux -> AS runtime 最小 ENTER mailbox 的 host-buildable pure builder。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <asm/nacc_enter.h>

static int nacc_enter_ranges_overlap(const void *left, size_t left_size,
				     const void *right, size_t right_size)
{
	unsigned long left_base = (unsigned long)left;
	unsigned long right_base = (unsigned long)right;

	if (left_size > ~0UL - left_base || right_size > ~0UL - right_base)
		return 1;
	return left_base < right_base + right_size &&
	       right_base < left_base + left_size;
}

static int nacc_enter_range_fits(nacc_enter_u64 base, nacc_enter_u64 size,
				 nacc_enter_u64 range_base,
				 nacc_enter_u64 range_size)
{
	return size && base <= ~(nacc_enter_u64)0 - size &&
	       range_base >= base && range_base - base <= size &&
	       range_size <= size - (range_base - base);
}

int nacc_enter_message_build(void *mailbox, size_t mailbox_size,
			     const struct nacc_enter_message_request *request)
{
	struct nacc_runtime_mailbox_descriptor *descriptor;
	struct nacc_runtime_enter_payload *payload;
	nacc_enter_u64 ptp_size;
	nacc_enter_u8 *code;

	if (!mailbox || !request || !request->code_prefix ||
	    mailbox_size != NACC_ENTER_MAILBOX_SIZE ||
	    (unsigned long)mailbox &
		(__alignof__(struct nacc_runtime_mailbox_descriptor) - 1))
		return -EINVAL;
	if (!request->sequence || !request->agent_handle ||
	    !request->mm_handle || !request->thread_handle ||
	    !request->service_handle || !request->object_generation ||
	    !request->ptp_page_count || !request->code_prefix_length ||
	    request->code_prefix_length > NACC_ENTER_MAX_CODE_PREFIX ||
	    request->entry_offset >= request->code_prefix_length ||
	    request->ptp_page_count > ~(nacc_enter_u64)0 /
					 NACC_ENTER_PAGE_SIZE)
		return -EINVAL;
	if (nacc_enter_ranges_overlap(mailbox, mailbox_size, request,
				      sizeof(*request)) ||
	    nacc_enter_ranges_overlap(mailbox, mailbox_size,
				      request->code_prefix,
				      request->code_prefix_length))
		return -EINVAL;
	ptp_size = request->ptp_page_count * NACC_ENTER_PAGE_SIZE;
	if ((request->pool_base | request->pool_size |
	     request->live_root_physical_address |
	     request->code_physical_address | request->stack_physical_address) &
	    (NACC_ENTER_PAGE_SIZE - 1))
		return -EINVAL;
	if (!nacc_enter_range_fits(request->pool_base, request->pool_size,
				   request->live_root_physical_address,
				   ptp_size) ||
	    !nacc_enter_range_fits(request->pool_base, request->pool_size,
				   request->code_physical_address,
				   NACC_ENTER_PAGE_SIZE) ||
	    !nacc_enter_range_fits(request->pool_base, request->pool_size,
				   request->stack_physical_address,
				   NACC_ENTER_PAGE_SIZE) ||
	    request->code_physical_address - request->pool_base <
		request->live_root_physical_address - request->pool_base +
			ptp_size ||
	    request->stack_physical_address - request->pool_base <
		request->live_root_physical_address - request->pool_base +
			ptp_size ||
	    request->code_physical_address == request->stack_physical_address)
		return -EINVAL;

	memset(mailbox, 0, mailbox_size);
	descriptor = mailbox;
	payload = (void *)((nacc_enter_u8 *)mailbox + sizeof(*descriptor));
	code = (nacc_enter_u8 *)payload + sizeof(*payload);
	descriptor->header.magic = NACC_RUNTIME_MAILBOX_MAGIC;
	descriptor->header.abi_major = NACC_RUNTIME_ABI_MAJOR;
	descriptor->header.abi_minor = NACC_RUNTIME_ABI_MINOR;
	descriptor->header.struct_size = sizeof(*descriptor);
	descriptor->header.features = NACC_RUNTIME_FEATURE_BASE |
		NACC_RUNTIME_FEATURE_SERVICE_GENERATION;
	descriptor->opcode = NACC_RUNTIME_ENTER_OPCODE;
	descriptor->flags = NACC_RUNTIME_MAILBOX_FLAG_REQUEST;
	descriptor->sequence = request->sequence;
	descriptor->agent_handle = request->agent_handle;
	descriptor->mm_handle = request->mm_handle;
	descriptor->thread_handle = request->thread_handle;
	descriptor->service_handle = request->service_handle;
	descriptor->object_generation = request->object_generation;
	descriptor->payload_offset = sizeof(*descriptor);
	descriptor->payload_length = sizeof(*payload) +
		request->code_prefix_length;
	payload->live_root_physical_address =
		request->live_root_physical_address;
	payload->ptp_base = request->live_root_physical_address;
	payload->ptp_page_count = request->ptp_page_count;
	payload->code_physical_address = request->code_physical_address;
	payload->code_virtual_address = NACC_ENTER_CODE_VIRTUAL_ADDRESS;
	payload->stack_physical_address = request->stack_physical_address;
	payload->stack_virtual_address = NACC_ENTER_STACK_VIRTUAL_ADDRESS;
	payload->entry_offset = request->entry_offset;
	payload->stack_pointer = NACC_ENTER_STACK_POINTER;
	payload->code_prefix_length = request->code_prefix_length;
	payload->page_size = NACC_ENTER_PAGE_SIZE;
	memcpy(code, request->code_prefix, request->code_prefix_length);
	return 0;
}
