/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linux -> AS runtime 最小 ENTER mailbox ABI 与纯消息构造器。
 * wire format 必须与 Agent runtime 的 nacc_abi.h v1.2 保持一致。
 */
#ifndef _ASM_RISCV_NACC_ENTER_H
#define _ASM_RISCV_NACC_ENTER_H

#ifdef __KERNEL__
#include <linux/stddef.h>
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#endif

#define NACC_ENTER_MAILBOX_SIZE 4096U
#define NACC_ENTER_PAGE_SIZE 4096ULL
#define NACC_ENTER_CODE_VIRTUAL_ADDRESS 0x00010000ULL
#define NACC_ENTER_STACK_VIRTUAL_ADDRESS 0x00020000ULL
#define NACC_ENTER_STACK_POINTER 0x00021000ULL
#define NACC_ENTER_MAX_CODE_PREFIX 3800U

#define NACC_RUNTIME_MAILBOX_MAGIC 0x4e4143434d424f58ULL
#define NACC_RUNTIME_ABI_MAJOR 1U
#define NACC_RUNTIME_ABI_MINOR 2U
#define NACC_RUNTIME_FEATURE_BASE (1ULL << 0)
#define NACC_RUNTIME_FEATURE_SERVICE_GENERATION (1ULL << 1)
#define NACC_RUNTIME_FEATURE_SERVICE_ALLOCATION (1ULL << 5)
#define NACC_RUNTIME_ENTER_OPCODE 0x0040U
#define NACC_RUNTIME_MAILBOX_FLAG_REQUEST (1U << 0)
#define NACC_RUNTIME_RESERVED_WORDS 4U

#ifdef __KERNEL__
typedef u16 nacc_enter_u16;
typedef u32 nacc_enter_u32;
typedef u64 nacc_enter_u64;
typedef s64 nacc_enter_s64;
typedef u8 nacc_enter_u8;
#else
typedef uint16_t nacc_enter_u16;
typedef uint32_t nacc_enter_u32;
typedef uint64_t nacc_enter_u64;
typedef int64_t nacc_enter_s64;
typedef uint8_t nacc_enter_u8;
#endif

struct nacc_runtime_abi_header {
	nacc_enter_u64 magic;
	nacc_enter_u16 abi_major;
	nacc_enter_u16 abi_minor;
	nacc_enter_u32 struct_size;
	nacc_enter_u64 features;
	nacc_enter_u64 reserved[NACC_RUNTIME_RESERVED_WORDS];
};

struct nacc_runtime_mailbox_descriptor {
	struct nacc_runtime_abi_header header;
	nacc_enter_u32 opcode;
	nacc_enter_u32 flags;
	nacc_enter_u64 sequence;
	nacc_enter_s64 status;
	nacc_enter_u64 agent_handle;
	nacc_enter_u64 mm_handle;
	nacc_enter_u64 thread_handle;
	/* v1.2 allocation request 必须保持 zero pair；由 AS 返回真实 identity。 */
	nacc_enter_u64 service_handle;
	nacc_enter_u64 object_generation;
	nacc_enter_u64 payload_offset;
	nacc_enter_u64 payload_length;
	nacc_enter_u64 reserved[NACC_RUNTIME_RESERVED_WORDS];
};

struct nacc_runtime_enter_payload {
	nacc_enter_u64 live_root_physical_address;
	nacc_enter_u64 ptp_base;
	nacc_enter_u64 ptp_page_count;
	nacc_enter_u64 code_physical_address;
	nacc_enter_u64 code_virtual_address;
	nacc_enter_u64 stack_physical_address;
	nacc_enter_u64 stack_virtual_address;
	nacc_enter_u64 entry_offset;
	nacc_enter_u64 stack_pointer;
	nacc_enter_u64 code_prefix_length;
	nacc_enter_u64 page_size;
	nacc_enter_u64 flags;
	nacc_enter_u64 reserved[NACC_RUNTIME_RESERVED_WORDS];
};

struct nacc_enter_message_request {
	nacc_enter_u64 pool_base;
	nacc_enter_u64 pool_size;
	nacc_enter_u64 live_root_physical_address;
	nacc_enter_u64 ptp_page_count;
	nacc_enter_u64 code_physical_address;
	nacc_enter_u64 stack_physical_address;
	nacc_enter_u64 entry_offset;
	nacc_enter_u64 sequence;
	nacc_enter_u64 agent_handle;
	nacc_enter_u64 mm_handle;
	nacc_enter_u64 thread_handle;
	const nacc_enter_u8 *code_prefix;
	size_t code_prefix_length;
};

struct nacc_enter_elf_metadata {
	bool fixed_executable;
	bool direct_executable;
	bool has_interpreter;
	nacc_enter_u32 load_segment_count;
	nacc_enter_u32 executable_load_segment_count;
	nacc_enter_u32 executable_flags;
	nacc_enter_u64 executable_file_offset;
	nacc_enter_u64 executable_virtual_address;
	nacc_enter_u64 executable_file_size;
	nacc_enter_u64 executable_memory_size;
	nacc_enter_u64 entry;
};

/* caller 必须先确认 backend 已协商 SERVICE_ALLOCATION capability。 */
int nacc_enter_message_build(void *mailbox, size_t mailbox_size,
			     const struct nacc_enter_message_request *request);
int nacc_enter_elf_metadata_validate(
	const struct nacc_enter_elf_metadata *metadata,
	nacc_enter_u64 *entry_offset, size_t *code_prefix_length);

_Static_assert(sizeof(struct nacc_runtime_abi_header) == 56,
		       "NACC runtime ABI header layout changed");
_Static_assert(sizeof(struct nacc_runtime_mailbox_descriptor) == 168,
		       "NACC runtime mailbox descriptor layout changed");
_Static_assert(offsetof(struct nacc_runtime_mailbox_descriptor,
			payload_offset) == 120,
		       "NACC runtime payload offset layout changed");
_Static_assert(sizeof(struct nacc_runtime_enter_payload) == 128,
		       "NACC runtime ENTER payload layout changed");
_Static_assert(sizeof(struct nacc_runtime_mailbox_descriptor) +
		       sizeof(struct nacc_runtime_enter_payload) +
		       NACC_ENTER_MAX_CODE_PREFIX == NACC_ENTER_MAILBOX_SIZE,
		       "NACC runtime ENTER mailbox capacity changed");

#endif /* _ASM_RISCV_NACC_ENTER_H */
