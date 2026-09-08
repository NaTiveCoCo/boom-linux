// SPDX-License-Identifier: GPL-2.0-only
/* Linux runtime request/completion 的 host-buildable single-hart 状态机。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <asm/nacc_runtime_session.h>

static int nacc_runtime_session_ranges_overlap(const void *left,
					       size_t left_size,
					       const void *right,
					       size_t right_size)
{
	unsigned long left_base = (unsigned long)left;
	unsigned long right_base = (unsigned long)right;

	if (left_size > ~0UL - left_base || right_size > ~0UL - right_base)
		return 1;
	return left_base < right_base + right_size &&
	       right_base < left_base + left_size;
}

static int nacc_runtime_session_words_are_zero(const nacc_enter_u64 *words,
					       size_t count)
{
	size_t index;

	for (index = 0; index < count; index++)
		if (words[index])
			return 0;
	return 1;
}

static int nacc_runtime_session_bytes_are_zero(const nacc_enter_u8 *bytes,
					       size_t count)
{
	size_t index;

	for (index = 0; index < count; index++)
		if (bytes[index])
			return 0;
	return 1;
}

int nacc_linux_runtime_session_initialize(
	struct nacc_linux_runtime_session *session,
	nacc_enter_u64 initial_sequence)
{
	nacc_enter_u32 expected = NACC_RUNTIME_SESSION_UNINITIALIZED;

	if (!session ||
	    ((unsigned long)session & (NACC_ENTER_MAILBOX_SIZE - 1)) ||
	    !initial_sequence)
		return -EINVAL;
	if (!__atomic_compare_exchange_n(
		    &session->state, &expected, NACC_RUNTIME_SESSION_ARMING,
		    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return -EALREADY;
	if (session->reserved || session->next_sequence ||
	    memcmp(&session->pending_request,
		   &(struct nacc_runtime_lifecycle_request) { 0 },
		   sizeof(session->pending_request)) ||
	    !nacc_runtime_session_bytes_are_zero(
		session->response_alignment_padding,
		sizeof(session->response_alignment_padding)) ||
	    !nacc_runtime_session_bytes_are_zero(
		session->response_snapshot,
		sizeof(session->response_snapshot))) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EINVAL;
	}
	session->next_sequence = initial_sequence;
	__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_IDLE,
			 __ATOMIC_RELEASE);
	return 0;
}

int nacc_linux_runtime_session_arm(
	struct nacc_linux_runtime_session *session,
	const struct nacc_runtime_lifecycle_request *request)
{
	struct nacc_runtime_lifecycle_request candidate;
	nacc_enter_u32 expected = NACC_RUNTIME_SESSION_IDLE;

	if (!session || !request || nacc_runtime_session_ranges_overlap(
		    session, sizeof(*session), request, sizeof(*request)))
		return -EINVAL;
	candidate = *request;
	if (nacc_runtime_lifecycle_request_validate(&candidate))
		return -EINVAL;
	if (!__atomic_compare_exchange_n(
		    &session->state, &expected, NACC_RUNTIME_SESSION_ARMING,
		    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return -EBUSY;
	if (candidate.sequence < session->next_sequence) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_IDLE,
				 __ATOMIC_RELEASE);
		return -ESTALE;
	}
	if (candidate.sequence > session->next_sequence) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EPROTO;
	}
	if (session->reserved ||
	    memcmp(&session->pending_request,
		   &(struct nacc_runtime_lifecycle_request) { 0 },
		   sizeof(session->pending_request)) ||
	    !nacc_runtime_session_bytes_are_zero(
		session->response_alignment_padding,
		sizeof(session->response_alignment_padding)) ||
	    !nacc_runtime_session_bytes_are_zero(
		session->response_snapshot,
		sizeof(session->response_snapshot))) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EINVAL;
	}
	session->pending_request = candidate;
	__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_PENDING,
			 __ATOMIC_RELEASE);
	return 0;
}

int nacc_linux_runtime_session_response_capture(
	struct nacc_linux_runtime_session *session,
	const void *shared_mailbox, size_t shared_mailbox_size,
	nacc_enter_u64 sequence, nacc_enter_u64 request_opcode,
	const nacc_enter_u64 reserved_registers[5])
{
	nacc_enter_u64 reserved_snapshot[5];
	nacc_enter_u32 expected = NACC_RUNTIME_SESSION_PENDING;

	if (!session || !shared_mailbox ||
	    shared_mailbox_size != NACC_ENTER_MAILBOX_SIZE ||
	    ((unsigned long)shared_mailbox &
	     (__alignof__(struct nacc_runtime_mailbox_descriptor) - 1)) ||
	    nacc_runtime_session_ranges_overlap(
		session, sizeof(*session), shared_mailbox,
		shared_mailbox_size) ||
	    !reserved_registers)
		return -EINVAL;
	memcpy(reserved_snapshot, reserved_registers, sizeof(reserved_snapshot));
	if (!__atomic_compare_exchange_n(
		    &session->state, &expected, NACC_RUNTIME_SESSION_CAPTURING,
		    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return -EALREADY;
	if (nacc_runtime_lifecycle_request_validate(
		    &session->pending_request) ||
	    session->pending_request.sequence != session->next_sequence) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EINVAL;
	}
	if (sequence && sequence < session->pending_request.sequence) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_PENDING,
				 __ATOMIC_RELEASE);
		return -ESTALE;
	}
	if (!nacc_runtime_session_words_are_zero(reserved_snapshot, 5) ||
	    !sequence || sequence != session->next_sequence ||
	    sequence != session->pending_request.sequence ||
	    request_opcode > ~(nacc_enter_u32)0 ||
	    request_opcode != session->pending_request.opcode) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EPROTO;
	}
	memcpy(session->response_snapshot, shared_mailbox,
	       sizeof(session->response_snapshot));
	__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_CAPTURED,
			 __ATOMIC_RELEASE);
	return 0;
}

int nacc_linux_runtime_session_complete(
	struct nacc_linux_runtime_session *session,
	nacc_enter_u64 expected_sequence,
	struct nacc_runtime_lifecycle_result *result)
{
	struct nacc_runtime_lifecycle_result candidate;
	nacc_enter_u32 expected = NACC_RUNTIME_SESSION_CAPTURED;
	int ret;

	if (!session || !expected_sequence || !result ||
	    nacc_runtime_session_ranges_overlap(
		session, sizeof(*session), result, sizeof(*result)))
		return -EINVAL;
	if (!__atomic_compare_exchange_n(
		    &session->state, &expected, NACC_RUNTIME_SESSION_COMPLETING,
		    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return -EALREADY;
	if (nacc_runtime_lifecycle_request_validate(
		    &session->pending_request) ||
	    session->pending_request.sequence != session->next_sequence) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EINVAL;
	}
	if (expected_sequence < session->next_sequence) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_CAPTURED,
				 __ATOMIC_RELEASE);
		return -ESTALE;
	}
	if (expected_sequence > session->next_sequence ||
	    expected_sequence != session->pending_request.sequence) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EPROTO;
	}
	ret = nacc_runtime_lifecycle_response_validate(
		session->response_snapshot, sizeof(session->response_snapshot),
		&session->pending_request, &candidate);
	if (ret || session->next_sequence == ~(nacc_enter_u64)0) {
		__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return ret ? ret : -EOVERFLOW;
	}
	session->next_sequence++;
	memset(&session->pending_request, 0, sizeof(session->pending_request));
	memset(session->response_snapshot, 0,
	       sizeof(session->response_snapshot));
	*result = candidate;
	__atomic_store_n(&session->state, NACC_RUNTIME_SESSION_IDLE,
			 __ATOMIC_RELEASE);
	return 0;
}
