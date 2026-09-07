/* SPDX-License-Identifier: GPL-2.0-only */
/* Linux 消费的 canonical Agent build-time image metadata。 */
#ifndef _ASM_RISCV_NACC_AGENT_IMAGE_H
#define _ASM_RISCV_NACC_AGENT_IMAGE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#define NACC_LINUX_AGENT_IMAGE_MAGIC 0x4e414349U
#define NACC_LINUX_AGENT_IMAGE_ABI_MAJOR 1U
#define NACC_LINUX_AGENT_IMAGE_ABI_MINOR 2U
#define NACC_LINUX_AGENT_IMAGE_DESCRIPTOR_SIZE 280U
#define NACC_LINUX_AGENT_IMAGE_SEGMENT_COUNT 2U
#define NACC_LINUX_AGENT_IMAGE_PAGE_SIZE 4096ULL
#define NACC_LINUX_AGENT_IMAGE_MAX_ARTIFACT_SIZE (16ULL * 1024ULL * 1024ULL)
#define NACC_LINUX_AGENT_IMAGE_MAX_REGION_SIZE (64ULL * 1024ULL * 1024ULL)
#define NACC_LINUX_AGENT_IMAGE_MAX_BSS_SIZE (16ULL * 1024ULL * 1024ULL)
#define NACC_LINUX_AGENT_IMAGE_MAX_STACK_SIZE (1ULL * 1024ULL * 1024ULL)
#define NACC_LINUX_AGENT_IMAGE_MAX_ALIGNMENT (2ULL * 1024ULL * 1024ULL)
#define NACC_LINUX_AGENT_IMAGE_BOOT_CONTEXT_SIZE NACC_LINUX_AGENT_IMAGE_PAGE_SIZE
#define NACC_LINUX_AGENT_IMAGE_REQUIRED_FEATURES 0xfULL
#define NACC_LINUX_AGENT_IMAGE_RX_FLAGS 5U
#define NACC_LINUX_AGENT_IMAGE_RW_FLAGS 6U
#define NACC_LINUX_AGENT_IMAGE_DIGEST_SIZE 32U

#ifdef __KERNEL__
typedef u32 nacc_agent_image_u32;
typedef u64 nacc_agent_image_u64;
typedef u8 nacc_agent_image_u8;
#else
typedef uint32_t nacc_agent_image_u32;
typedef uint64_t nacc_agent_image_u64;
typedef uint8_t nacc_agent_image_u8;
#endif

struct nacc_agent_image_segment {
	nacc_agent_image_u64 file_offset;
	nacc_agent_image_u64 virtual_offset;
	nacc_agent_image_u64 file_size;
	nacc_agent_image_u64 memory_size;
	nacc_agent_image_u32 flags;
	nacc_agent_image_u32 alignment;
};

struct nacc_agent_image_metadata {
	nacc_agent_image_u32 magic;
	nacc_agent_image_u32 abi_major;
	nacc_agent_image_u32 abi_minor;
	nacc_agent_image_u32 descriptor_size;
	nacc_agent_image_u64 artifact_size;
	nacc_agent_image_u64 entry_offset;
	nacc_agent_image_u64 required_features;
	nacc_agent_image_u64 bss_size;
	nacc_agent_image_u64 stack_size;
	nacc_agent_image_u64 stack_alignment;
	struct nacc_agent_image_segment segments[NACC_LINUX_AGENT_IMAGE_SEGMENT_COUNT];
	nacc_agent_image_u64 stack_top_offset;
	nacc_agent_image_u64 boot_context_offset;
	nacc_agent_image_u64 bootstrap_handshake_offset;
	nacc_agent_image_u8 artifact_digest[NACC_LINUX_AGENT_IMAGE_DIGEST_SIZE];
	nacc_agent_image_u8 descriptor_digest[NACC_LINUX_AGENT_IMAGE_DIGEST_SIZE];
};

int nacc_agent_image_metadata_validate(
	const struct nacc_agent_image_metadata *metadata);

#ifdef __KERNEL__
const struct nacc_agent_image_metadata *nacc_agent_image_metadata_snapshot(void);
#endif

#endif /* _ASM_RISCV_NACC_AGENT_IMAGE_H */
