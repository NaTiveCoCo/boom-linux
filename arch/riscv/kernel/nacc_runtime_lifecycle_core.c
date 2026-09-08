// SPDX-License-Identifier: GPL-2.0-only
/* AS runtime lifecycle mailbox 的 host-buildable builder/response validator。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <asm/nacc_runtime_lifecycle.h>

static int nacc_runtime_words_are_zero(const nacc_enter_u64 *words,
				       size_t count)
{
	size_t index;

	for (index = 0; index < count; index++)
		if (words[index])
			return 0;
	return 1;
}

static int nacc_runtime_ranges_overlap(const void *left, size_t left_size,
				       const void *right, size_t right_size)
{
	unsigned long left_base = (unsigned long)left;
	unsigned long right_base = (unsigned long)right;

	if (left_size > ~0UL - left_base || right_size > ~0UL - right_base)
		return 1;
	return left_base < right_base + right_size &&
	       right_base < left_base + left_size;
}

static int nacc_runtime_ref_is_zero(struct nacc_runtime_object_ref ref)
{
	return !ref.handle && !ref.generation;
}

static int nacc_runtime_ref_is_valid(struct nacc_runtime_object_ref ref)
{
	return ref.handle && ref.generation &&
	       ref.handle != ~(nacc_enter_u64)0 &&
	       ref.generation != ~(nacc_enter_u64)0;
}

int nacc_runtime_lifecycle_request_validate(
	const struct nacc_runtime_lifecycle_request *request)
{
	if (!request || !request->sequence)
		return -EINVAL;
	switch (request->opcode) {
	case NACC_RUNTIME_AGENT_CREATE_OPCODE:
		return !(nacc_runtime_ref_is_zero(request->agent) &&
		       nacc_runtime_ref_is_zero(request->mm) &&
		       nacc_runtime_ref_is_zero(request->thread)) ? -EINVAL : 0;
	case NACC_RUNTIME_MM_CREATE_OPCODE:
	case NACC_RUNTIME_TASK_CREATE_OPCODE:
		return !(nacc_runtime_ref_is_valid(request->agent) &&
		       nacc_runtime_ref_is_zero(request->mm) &&
		       nacc_runtime_ref_is_zero(request->thread)) ? -EINVAL : 0;
	case NACC_RUNTIME_TASK_ATTACH_OPCODE:
		return !(nacc_runtime_ref_is_valid(request->agent) &&
		       nacc_runtime_ref_is_valid(request->mm) &&
		       nacc_runtime_ref_is_valid(request->thread)) ? -EINVAL : 0;
	default:
		return -EINVAL;
	}
}

int nacc_runtime_lifecycle_message_build(
	void *mailbox, size_t mailbox_size,
	const struct nacc_runtime_lifecycle_request *request)
{
	struct nacc_runtime_mailbox_descriptor *descriptor;
	struct nacc_runtime_lifecycle_payload *payload;

	if (!mailbox || mailbox_size != NACC_ENTER_MAILBOX_SIZE ||
	    (unsigned long)mailbox &
		(__alignof__(struct nacc_runtime_mailbox_descriptor) - 1) ||
	    nacc_runtime_lifecycle_request_validate(request) ||
	    nacc_runtime_ranges_overlap(mailbox, mailbox_size, request,
				request ? sizeof(*request) : 0))
		return -EINVAL;

	memset(mailbox, 0, mailbox_size);
	descriptor = mailbox;
	payload = (void *)((nacc_enter_u8 *)mailbox + sizeof(*descriptor));
	descriptor->header.magic = NACC_RUNTIME_MAILBOX_MAGIC;
	descriptor->header.abi_major = NACC_RUNTIME_ABI_MAJOR;
	descriptor->header.abi_minor = NACC_RUNTIME_ABI_MINOR;
	descriptor->header.struct_size = sizeof(*descriptor);
	descriptor->header.features = NACC_RUNTIME_FEATURE_BASE |
		NACC_RUNTIME_FEATURE_SERVICE_GENERATION |
		NACC_RUNTIME_FEATURE_LIFECYCLE_CREATE_ATTACH;
	descriptor->opcode = request->opcode;
	descriptor->flags = NACC_RUNTIME_MAILBOX_FLAG_REQUEST;
	descriptor->sequence = request->sequence;
	descriptor->agent_handle = request->agent.handle;
	descriptor->mm_handle = request->mm.handle;
	descriptor->thread_handle = request->thread.handle;
	descriptor->payload_offset = sizeof(*descriptor);
	descriptor->payload_length = sizeof(*payload);
	payload->agent_generation = request->agent.generation;
	payload->mm_generation = request->mm.generation;
	payload->thread_generation = request->thread.generation;
	return 0;
}

static int nacc_runtime_lifecycle_header_valid(
	const struct nacc_runtime_mailbox_descriptor *descriptor,
	const struct nacc_runtime_lifecycle_request *request)
{
	const nacc_enter_u64 known_features =
		NACC_RUNTIME_FEATURE_BASE |
		NACC_RUNTIME_FEATURE_SERVICE_GENERATION |
		NACC_RUNTIME_FEATURE_SERVICE_ALLOCATION |
		NACC_RUNTIME_FEATURE_LIFECYCLE_CREATE_ATTACH;
	const nacc_enter_u64 required_features =
		NACC_RUNTIME_FEATURE_BASE |
		NACC_RUNTIME_FEATURE_SERVICE_GENERATION |
		NACC_RUNTIME_FEATURE_LIFECYCLE_CREATE_ATTACH;

	return descriptor->header.magic == NACC_RUNTIME_MAILBOX_MAGIC &&
	       descriptor->header.abi_major == NACC_RUNTIME_ABI_MAJOR &&
	       descriptor->header.abi_minor >= 3 &&
	       descriptor->header.struct_size >= sizeof(*descriptor) &&
	       descriptor->header.struct_size <= NACC_ENTER_MAILBOX_SIZE &&
	       !(descriptor->header.features & ~known_features) &&
	       (descriptor->header.features & required_features) ==
		       required_features &&
	       nacc_runtime_words_are_zero(descriptor->header.reserved,
				       NACC_RUNTIME_RESERVED_WORDS) &&
	       descriptor->opcode == request->opcode &&
	       descriptor->flags == NACC_RUNTIME_MAILBOX_FLAG_RESPONSE &&
	       descriptor->sequence == request->sequence &&
	       !descriptor->service_handle &&
	       nacc_runtime_words_are_zero(descriptor->reserved,
				       NACC_RUNTIME_RESERVED_WORDS) &&
	       descriptor->payload_offset >= descriptor->header.struct_size &&
	       descriptor->payload_offset <= NACC_ENTER_MAILBOX_SIZE &&
	       !descriptor->payload_length;
}

int nacc_runtime_lifecycle_response_validate(
	const void *mailbox_snapshot, size_t snapshot_size,
	const struct nacc_runtime_lifecycle_request *request,
	struct nacc_runtime_lifecycle_result *result)
{
	const struct nacc_runtime_mailbox_descriptor *descriptor =
		mailbox_snapshot;
	struct nacc_runtime_lifecycle_result candidate = { 0 };

	if (!mailbox_snapshot || snapshot_size != NACC_ENTER_MAILBOX_SIZE ||
	    (unsigned long)mailbox_snapshot &
		(__alignof__(struct nacc_runtime_mailbox_descriptor) - 1) ||
	    !result || nacc_runtime_lifecycle_request_validate(request) ||
	    nacc_runtime_ranges_overlap(mailbox_snapshot, snapshot_size, result,
				sizeof(*result)) ||
	    nacc_runtime_ranges_overlap(mailbox_snapshot, snapshot_size, request,
				sizeof(*request)) ||
	    nacc_runtime_ranges_overlap(request, sizeof(*request), result,
				sizeof(*result)))
		return -EINVAL;
	if (!nacc_runtime_lifecycle_header_valid(descriptor, request))
		return -EPROTO;
	if (descriptor->status == NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY) {
		if (request->opcode == NACC_RUNTIME_TASK_ATTACH_OPCODE ||
		    descriptor->agent_handle || descriptor->mm_handle ||
		    descriptor->thread_handle || descriptor->object_generation)
			return -EPROTO;
		candidate.status = descriptor->status;
		*result = candidate;
		return 0;
	}
	if (descriptor->status != NACC_RUNTIME_LIFECYCLE_STATUS_OK ||
	    !descriptor->object_generation ||
	    descriptor->object_generation == ~(nacc_enter_u64)0)
		return -EPROTO;

	candidate.status = descriptor->status;
	switch (request->opcode) {
	case NACC_RUNTIME_AGENT_CREATE_OPCODE:
		candidate.agent = (struct nacc_runtime_object_ref) {
			.handle = descriptor->agent_handle,
			.generation = descriptor->object_generation,
		};
		if (!nacc_runtime_ref_is_valid(candidate.agent) ||
		    descriptor->mm_handle || descriptor->thread_handle)
			return -EPROTO;
		break;
	case NACC_RUNTIME_MM_CREATE_OPCODE:
		candidate.agent = request->agent;
		candidate.mm = (struct nacc_runtime_object_ref) {
			.handle = descriptor->mm_handle,
			.generation = descriptor->object_generation,
		};
		if (descriptor->agent_handle != request->agent.handle ||
		    !nacc_runtime_ref_is_valid(candidate.mm) ||
		    descriptor->thread_handle)
			return -EPROTO;
		break;
	case NACC_RUNTIME_TASK_CREATE_OPCODE:
		candidate.agent = request->agent;
		candidate.thread = (struct nacc_runtime_object_ref) {
			.handle = descriptor->thread_handle,
			.generation = descriptor->object_generation,
		};
		if (descriptor->agent_handle != request->agent.handle ||
		    descriptor->mm_handle ||
		    !nacc_runtime_ref_is_valid(candidate.thread))
			return -EPROTO;
		break;
	case NACC_RUNTIME_TASK_ATTACH_OPCODE:
		candidate.agent = request->agent;
		candidate.mm = request->mm;
		candidate.thread = request->thread;
		if (descriptor->agent_handle != request->agent.handle ||
		    descriptor->mm_handle != request->mm.handle ||
		    descriptor->thread_handle != request->thread.handle ||
		    descriptor->object_generation != request->thread.generation)
			return -EPROTO;
		break;
	default:
		return -EINVAL;
	}
	*result = candidate;
	return 0;
}
