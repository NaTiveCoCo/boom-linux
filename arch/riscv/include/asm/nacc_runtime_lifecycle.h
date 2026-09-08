/* SPDX-License-Identifier: GPL-2.0-only */
/* Linux ↔ AS runtime lifecycle object mailbox ABI。 */
#ifndef _ASM_RISCV_NACC_RUNTIME_LIFECYCLE_H
#define _ASM_RISCV_NACC_RUNTIME_LIFECYCLE_H

#include <asm/nacc_enter.h>

#define NACC_RUNTIME_AGENT_CREATE_OPCODE 0x0010U
#define NACC_RUNTIME_AGENT_RETIRE_OPCODE 0x0011U
#define NACC_RUNTIME_MM_CREATE_OPCODE 0x0020U
#define NACC_RUNTIME_MM_RETIRE_OPCODE 0x0021U
#define NACC_RUNTIME_TASK_CREATE_OPCODE 0x0030U
#define NACC_RUNTIME_TASK_ATTACH_OPCODE 0x0031U
#define NACC_RUNTIME_TASK_RETIRE_OPCODE 0x0032U

#define NACC_RUNTIME_LIFECYCLE_STATUS_OK 0
#define NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY (-1)

struct nacc_runtime_lifecycle_payload {
	nacc_enter_u64 agent_generation;
	nacc_enter_u64 mm_generation;
	nacc_enter_u64 thread_generation;
	nacc_enter_u64 reserved[NACC_RUNTIME_RESERVED_WORDS];
};

struct nacc_runtime_object_ref {
	nacc_enter_u64 handle;
	nacc_enter_u64 generation;
};

struct nacc_runtime_lifecycle_request {
	nacc_enter_u32 opcode;
	nacc_enter_u64 sequence;
	struct nacc_runtime_object_ref agent;
	struct nacc_runtime_object_ref mm;
	struct nacc_runtime_object_ref thread;
};

struct nacc_runtime_lifecycle_result {
	nacc_enter_s64 status;
	struct nacc_runtime_object_ref agent;
	struct nacc_runtime_object_ref mm;
	struct nacc_runtime_object_ref thread;
};

int nacc_runtime_lifecycle_request_validate(
	const struct nacc_runtime_lifecycle_request *request);
int nacc_runtime_lifecycle_message_build(
	void *mailbox, size_t mailbox_size,
	const struct nacc_runtime_lifecycle_request *request);

/*
 * mailbox_snapshot 必须是 release shared slot 前复制完成的 Linux-owned page。
 * -EPROTO 表示 AS identity/internal ABI 违约，production caller 必须 fail-stop，
 * 不能把它降级成普通 errno 后继续运行。
 */
int nacc_runtime_lifecycle_response_validate(
	const void *mailbox_snapshot, size_t snapshot_size,
	const struct nacc_runtime_lifecycle_request *request,
	struct nacc_runtime_lifecycle_result *result);

_Static_assert(sizeof(struct nacc_runtime_lifecycle_payload) == 56,
		       "NACC runtime lifecycle payload layout changed");
_Static_assert(sizeof(struct nacc_runtime_mailbox_descriptor) +
		       sizeof(struct nacc_runtime_lifecycle_payload) <=
		       NACC_ENTER_MAILBOX_SIZE,
		       "NACC runtime lifecycle mailbox exceeds one page");

#endif /* _ASM_RISCV_NACC_RUNTIME_LIFECYCLE_H */
