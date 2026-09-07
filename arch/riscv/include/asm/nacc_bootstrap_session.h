/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC single-hart Linux bootstrap session 的内部契约。 */
#ifndef _ASM_RISCV_NACC_BOOTSTRAP_SESSION_H
#define _ASM_RISCV_NACC_BOOTSTRAP_SESSION_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include <asm/nacc_bootstrap.h>

#define NACC_LINUX_FIRST_ENTRY_CONTEXT_SIZE 400ULL
#define NACC_LINUX_SESSION_KERNEL_BASE 0xffffffc000000000ULL
#define NACC_LINUX_SESSION_SATP_MODE_SHIFT 60U
#define NACC_LINUX_SESSION_SATP_MODE_MASK \
	(0xfULL << NACC_LINUX_SESSION_SATP_MODE_SHIFT)
#define NACC_LINUX_SESSION_SATP_MODE_SV39 \
	(8ULL << NACC_LINUX_SESSION_SATP_MODE_SHIFT)
#define NACC_LINUX_SESSION_SATP_PPN_BITS 44U
#define NACC_LINUX_SESSION_SATP_PPN_MASK \
	((1ULL << NACC_LINUX_SESSION_SATP_PPN_BITS) - 1)

enum nacc_linux_bootstrap_session_state {
	NACC_LINUX_SESSION_UNINITIALIZED = 0,
	NACC_LINUX_SESSION_ARMING,
	NACC_LINUX_SESSION_ARMED,
	NACC_LINUX_SESSION_ACCEPTING_READY,
	NACC_LINUX_SESSION_READY,
	NACC_LINUX_SESSION_FAILED,
};

struct nacc_linux_bootstrap_session {
	nacc_bootstrap_u32 state;
	nacc_bootstrap_u32 reserved;
	nacc_bootstrap_u64 context_address;
	nacc_bootstrap_u64 context_size;
	nacc_bootstrap_u64 bootstrap_sequence;
	nacc_bootstrap_u64 linux_thread_pointer;
	nacc_bootstrap_u64 old_satp;
	nacc_bootstrap_u64 control_satp;
	nacc_bootstrap_u64 handshake_cookie;
};

struct nacc_linux_bootstrap_ready_request {
	nacc_bootstrap_u64 context_address;
	nacc_bootstrap_u64 context_size;
	nacc_bootstrap_u64 bootstrap_sequence;
	nacc_bootstrap_u64 handshake_cookie;
	nacc_bootstrap_u64 current_thread_pointer;
	nacc_bootstrap_u64 reserved[3];
};

int nacc_linux_bootstrap_session_arm(
	struct nacc_linux_bootstrap_session *session,
	nacc_bootstrap_u64 context_address,
	nacc_bootstrap_u64 bootstrap_sequence,
	nacc_bootstrap_u64 linux_thread_pointer,
	nacc_bootstrap_u64 old_satp, nacc_bootstrap_u64 control_satp);
int nacc_linux_bootstrap_session_ready_validate(
	const struct nacc_linux_bootstrap_session *session,
	const struct nacc_linux_bootstrap_ready_request *request);
int nacc_linux_bootstrap_session_ready_commit(
	struct nacc_linux_bootstrap_session *session,
	const struct nacc_linux_bootstrap_ready_request *request);
int nacc_linux_bootstrap_session_fail(
	struct nacc_linux_bootstrap_session *session);
bool nacc_linux_bootstrap_session_is_ready(
	const struct nacc_linux_bootstrap_session *session);

#ifdef __KERNEL__
struct nacc_root_build_result;
struct pt_regs;

void nacc_linux_bootstrap_enter(
	const struct nacc_bootstrap_descriptor *descriptor,
	const struct nacc_root_build_result *root);
long nacc_linux_bootstrap_ready(struct pt_regs *regs);
#endif

#endif /* _ASM_RISCV_NACC_BOOTSTRAP_SESSION_H */
