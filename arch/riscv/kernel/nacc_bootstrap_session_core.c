// SPDX-License-Identifier: GPL-2.0-only
/* NACC single-hart Linux bootstrap session 的 host-buildable pure core。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stddef.h>
#endif

#include <asm/nacc_bootstrap_session.h>

static bool nacc_linux_session_page_aligned(nacc_bootstrap_u64 value)
{
	return !(value & (NACC_BOOTSTRAP_PAGE_SIZE - 1));
}

static bool nacc_linux_session_satp_is_sv39(nacc_bootstrap_u64 satp)
{
	return (satp & NACC_LINUX_SESSION_SATP_MODE_MASK) ==
	       NACC_LINUX_SESSION_SATP_MODE_SV39;
}

int nacc_linux_bootstrap_session_arm(
	struct nacc_linux_bootstrap_session *session,
	nacc_bootstrap_u64 context_address,
	nacc_bootstrap_u64 bootstrap_sequence,
	nacc_bootstrap_u64 linux_thread_pointer,
	nacc_bootstrap_u64 old_satp, nacc_bootstrap_u64 control_satp,
	nacc_bootstrap_u64 allowed_rx_base,
	nacc_bootstrap_u64 allowed_rx_size)
{
	nacc_bootstrap_u32 expected = NACC_LINUX_SESSION_UNINITIALIZED;

	if (!session)
		return -EINVAL;
	if (__atomic_load_n(&session->state, __ATOMIC_ACQUIRE) !=
	    NACC_LINUX_SESSION_UNINITIALIZED)
		return -EALREADY;
	if (!context_address ||
	    !nacc_linux_session_page_aligned(context_address) ||
	    context_address >= NACC_BOOTSTRAP_SV39_USER_LIMIT ||
	    context_address > NACC_BOOTSTRAP_SV39_USER_LIMIT -
			      NACC_LINUX_FIRST_ENTRY_CONTEXT_SIZE ||
	    !bootstrap_sequence || !linux_thread_pointer ||
	    linux_thread_pointer < NACC_LINUX_SESSION_KERNEL_BASE ||
	    (linux_thread_pointer & (sizeof(nacc_bootstrap_u64) - 1)) ||
	    !nacc_linux_session_satp_is_sv39(old_satp) ||
	    !nacc_linux_session_satp_is_sv39(control_satp) ||
	    !(old_satp & NACC_LINUX_SESSION_SATP_PPN_MASK) ||
	    !(control_satp & NACC_LINUX_SESSION_SATP_PPN_MASK) ||
	    (old_satp & NACC_LINUX_SESSION_SATP_PPN_MASK) ==
		    (control_satp & NACC_LINUX_SESSION_SATP_PPN_MASK) ||
	    !allowed_rx_base ||
	    !nacc_linux_session_page_aligned(allowed_rx_base) ||
	    allowed_rx_size < NACC_LINUX_RUNTIME_ENTRY_INSN_SIZE ||
	    allowed_rx_base >= NACC_BOOTSTRAP_SV39_USER_LIMIT ||
	    allowed_rx_size > NACC_BOOTSTRAP_SV39_USER_LIMIT -
			      allowed_rx_base)
		return -EINVAL;
	if (!__atomic_compare_exchange_n(
		    &session->state, &expected, NACC_LINUX_SESSION_ARMING,
		    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return -EALREADY;
	if (session->reserved || session->context_address ||
	    session->context_size || session->bootstrap_sequence ||
	    session->linux_thread_pointer || session->old_satp ||
	    session->control_satp || session->allowed_rx_base ||
	    session->allowed_rx_size || session->runtime_entry_address ||
	    __atomic_load_n(&session->handshake_cookie, __ATOMIC_ACQUIRE)) {
		__atomic_store_n(&session->state, NACC_LINUX_SESSION_FAILED,
				 __ATOMIC_RELEASE);
		return -EINVAL;
	}

	session->context_address = context_address;
	session->context_size = NACC_LINUX_FIRST_ENTRY_CONTEXT_SIZE;
	session->bootstrap_sequence = bootstrap_sequence;
	session->linux_thread_pointer = linux_thread_pointer;
	session->old_satp = old_satp;
	session->control_satp = control_satp;
	session->allowed_rx_base = allowed_rx_base;
	session->allowed_rx_size = allowed_rx_size;
	__atomic_store_n(&session->state, NACC_LINUX_SESSION_ARMED,
			 __ATOMIC_RELEASE);
	return 0;
}

int nacc_linux_bootstrap_session_ready_validate(
	const struct nacc_linux_bootstrap_session *session,
	const struct nacc_linux_bootstrap_ready_request *request)
{
	if (!session || !request)
		return -EINVAL;
	if (__atomic_load_n(&session->state, __ATOMIC_ACQUIRE) !=
	    NACC_LINUX_SESSION_ARMED)
		return -EALREADY;
	if (session->reserved ||
	    __atomic_load_n(&session->handshake_cookie, __ATOMIC_ACQUIRE) ||
	    request->context_address != session->context_address ||
	    request->context_size != session->context_size ||
	    request->bootstrap_sequence != session->bootstrap_sequence ||
	    !request->handshake_cookie ||
	    request->current_thread_pointer != session->linux_thread_pointer ||
	    !request->runtime_entry_address ||
	    (request->runtime_entry_address &
	     (NACC_LINUX_RUNTIME_ENTRY_INSN_SIZE - 1)) ||
	    request->runtime_entry_address < session->allowed_rx_base ||
	    request->runtime_entry_address - session->allowed_rx_base >
		    session->allowed_rx_size - NACC_LINUX_RUNTIME_ENTRY_INSN_SIZE ||
	    request->reserved[0] || request->reserved[1])
		return -EINVAL;
	return 0;
}

int nacc_linux_bootstrap_session_ready_commit(
	struct nacc_linux_bootstrap_session *session,
	const struct nacc_linux_bootstrap_ready_request *request)
{
	nacc_bootstrap_u32 expected = NACC_LINUX_SESSION_ARMED;
	int ret;

	ret = nacc_linux_bootstrap_session_ready_validate(session, request);
	if (ret)
		return ret;
	if (!__atomic_compare_exchange_n(
		    &session->state, &expected,
		    NACC_LINUX_SESSION_ACCEPTING_READY, false,
		    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return -EALREADY;
	session->runtime_entry_address = request->runtime_entry_address;
	__atomic_store_n(&session->handshake_cookie,
			 request->handshake_cookie, __ATOMIC_RELEASE);
	__atomic_store_n(&session->state, NACC_LINUX_SESSION_READY,
			 __ATOMIC_RELEASE);
	return 0;
}

int nacc_linux_bootstrap_session_fail(
	struct nacc_linux_bootstrap_session *session)
{
	nacc_bootstrap_u32 expected = NACC_LINUX_SESSION_ARMED;

	if (!session)
		return -EINVAL;
	if (!__atomic_compare_exchange_n(
		    &session->state, &expected, NACC_LINUX_SESSION_FAILED,
		    false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return -EALREADY;
	return 0;
}

bool nacc_linux_bootstrap_session_is_ready(
	const struct nacc_linux_bootstrap_session *session)
{
	return session &&
	       __atomic_load_n(&session->state, __ATOMIC_ACQUIRE) ==
		       NACC_LINUX_SESSION_READY &&
		       session->handshake_cookie && session->runtime_entry_address;
}
