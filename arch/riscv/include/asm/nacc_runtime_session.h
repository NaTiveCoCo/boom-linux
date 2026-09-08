/* SPDX-License-Identifier: GPL-2.0-only */
/* Linux single-hart runtime request/completion transaction 契约。 */
#ifndef _ASM_RISCV_NACC_RUNTIME_SESSION_H
#define _ASM_RISCV_NACC_RUNTIME_SESSION_H

#include <asm/nacc_runtime_lifecycle.h>

#define NACC_RUNTIME_SESSION_METADATA_SIZE 80U

enum nacc_linux_runtime_session_state {
	NACC_RUNTIME_SESSION_UNINITIALIZED = 0,
	NACC_RUNTIME_SESSION_IDLE,
	NACC_RUNTIME_SESSION_ARMING,
	NACC_RUNTIME_SESSION_PENDING,
	NACC_RUNTIME_SESSION_CAPTURING,
	NACC_RUNTIME_SESSION_CAPTURED,
	NACC_RUNTIME_SESSION_COMPLETING,
	NACC_RUNTIME_SESSION_FAILED,
};

struct nacc_linux_runtime_session {
	nacc_enter_u32 state;
	nacc_enter_u32 reserved;
	nacc_enter_u64 next_sequence;
	struct nacc_runtime_lifecycle_request pending_request;
	nacc_enter_u8 response_alignment_padding[
		NACC_ENTER_MAILBOX_SIZE - NACC_RUNTIME_SESSION_METADATA_SIZE];
	nacc_enter_u8 response_snapshot[NACC_ENTER_MAILBOX_SIZE];
};

_Static_assert(offsetof(struct nacc_linux_runtime_session,
		       response_alignment_padding) ==
		       NACC_RUNTIME_SESSION_METADATA_SIZE,
		       "NACC runtime session metadata layout changed");
_Static_assert(offsetof(struct nacc_linux_runtime_session,
		       response_snapshot) == NACC_ENTER_MAILBOX_SIZE,
		       "NACC runtime response snapshot alignment changed");
_Static_assert(sizeof(struct nacc_linux_runtime_session) ==
		       2 * NACC_ENTER_MAILBOX_SIZE,
		       "NACC runtime session layout changed");

int nacc_linux_runtime_session_initialize(
	struct nacc_linux_runtime_session *session,
	nacc_enter_u64 initial_sequence);
int nacc_linux_runtime_session_arm(
	struct nacc_linux_runtime_session *session,
	const struct nacc_runtime_lifecycle_request *request);
int nacc_linux_runtime_session_response_capture(
	struct nacc_linux_runtime_session *session,
	const void *shared_mailbox, size_t shared_mailbox_size,
	nacc_enter_u64 sequence, nacc_enter_u64 request_opcode,
	const nacc_enter_u64 reserved_registers[5]);
int nacc_linux_runtime_session_complete(
	struct nacc_linux_runtime_session *session,
	nacc_enter_u64 expected_sequence,
	struct nacc_runtime_lifecycle_result *result);

#endif /* _ASM_RISCV_NACC_RUNTIME_SESSION_H */
