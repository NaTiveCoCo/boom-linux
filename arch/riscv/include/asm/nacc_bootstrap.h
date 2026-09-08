/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * NACC private bootstrap ABI。
 *
 * 该 header 必须与 OpenSBI v2.0 的 232-byte descriptor 保持逐字段一致。
 * 它不是 user-visible UAPI，也不表示 Linux 已经完成 Agent bootstrap。
 */
#ifndef _ASM_RISCV_NACC_BOOTSTRAP_H
#define _ASM_RISCV_NACC_BOOTSTRAP_H

#ifdef __KERNEL__
#include <linux/stddef.h>
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#endif

#define NACC_BOOTSTRAP_MAGIC 0x4e414343U
#define NACC_BOOTSTRAP_ABI_MAJOR 2U
#define NACC_BOOTSTRAP_ABI_MINOR 0U
#define NACC_BOOTSTRAP_PAGE_SIZE 4096ULL
#define NACC_BOOTSTRAP_DESCRIPTOR_MAX_SIZE 4096U
#define NACC_BOOTSTRAP_SV39_USER_LIMIT (1ULL << 38)
#define NACC_BOOTSTRAP_FEATURE_MANAGEMENT_VA (1ULL << 0)
#define NACC_BOOTSTRAP_FEATURES_V2 NACC_BOOTSTRAP_FEATURE_MANAGEMENT_VA
/* breakpoint 必须留给 M-mode，供 Agent fatal vector fail-stop。 */
#define NACC_BOOTSTRAP_DELEGATION_EXCEPTION_MASK 0x000000000000b1f7ULL
#define NACC_BOOTSTRAP_DELEGATION_INTERRUPT_MASK 0x0000000000000222ULL

/* descriptor 的五个 user-half virtual range 使用互不相邻的固定 window。 */
#define NACC_BOOTSTRAP_AGENT_VIRTUAL_BASE 0x0000000100000000ULL
#define NACC_BOOTSTRAP_MAILBOX_VIRTUAL_BASE 0x0000000200000000ULL
#define NACC_BOOTSTRAP_EMERGENCY_VIRTUAL_BASE 0x0000000300000000ULL
#define NACC_BOOTSTRAP_POOL_VIRTUAL_BASE 0x0000000400000000ULL
#define NACC_BOOTSTRAP_BITMAP_VIRTUAL_BASE 0x0000000500000000ULL

#define NACC_BOOTSTRAP_DESCRIPTOR_V1_0_SIZE 184U
#define NACC_BOOTSTRAP_DESCRIPTOR_V1_1_SIZE 216U

#ifdef __KERNEL__
typedef u32 nacc_bootstrap_u32;
typedef u16 nacc_bootstrap_u16;
typedef u64 nacc_bootstrap_u64;
#else
typedef uint32_t nacc_bootstrap_u32;
typedef uint16_t nacc_bootstrap_u16;
typedef uint64_t nacc_bootstrap_u64;
#endif

struct nacc_bootstrap_range {
	nacc_bootstrap_u64 base;
	nacc_bootstrap_u64 size;
};

/* 与 OpenSBI 同步的 Platform authoritative physical layout。 */
struct nacc_bootstrap_physical_layout {
	struct nacc_bootstrap_range arena;
	struct nacc_bootstrap_range agent_region;
	struct nacc_bootstrap_range bitmap_target;
	struct nacc_bootstrap_range bitmap_backing;
	struct nacc_bootstrap_range nacc_pool;
	struct nacc_bootstrap_range control_root_l0;
	struct nacc_bootstrap_range mailbox;
	struct nacc_bootstrap_range emergency_stack;
};

/* reserved-memory callback 接收的唯一 NACC agent physical range。 */
struct nacc_bootstrap_agent_memory_state {
	nacc_bootstrap_u32 matches;
	struct nacc_bootstrap_range range;
};

/*
 * Linux 提供给 OpenSBI 的 runtime layout；所有 range 都是 physical range。
 * external emergency workspace 仅供 single-hart M bootstrap callback 临时保存
 * lower PTP audit list/bitmap；它不承载 secret 或长期可信 state，no-map 不代表
 * M-private 硬件保护，也不得把它加入 AS initial leaf set。
 */
struct nacc_bootstrap_descriptor {
	nacc_bootstrap_u32 magic;
	nacc_bootstrap_u16 abi_major;
	nacc_bootstrap_u16 abi_minor;
	nacc_bootstrap_u32 struct_size;
	nacc_bootstrap_u32 reserved0;
	nacc_bootstrap_u64 feature_bits;
	struct nacc_bootstrap_range agent_region;
	struct nacc_bootstrap_range bitmap_target;
	struct nacc_bootstrap_range bitmap_backing;
	struct nacc_bootstrap_range nacc_pool;
	struct nacc_bootstrap_range control_root_l0;
	struct nacc_bootstrap_range mailbox;
	struct nacc_bootstrap_range emergency_stack;
	nacc_bootstrap_u64 delegation_exception_mask;
	nacc_bootstrap_u64 delegation_interrupt_mask;
	nacc_bootstrap_u64 reserved[4];
	nacc_bootstrap_u64 agent_virtual_base;
	nacc_bootstrap_u64 mailbox_virtual_base;
	nacc_bootstrap_u64 emergency_stack_virtual_top;
	nacc_bootstrap_u64 bootstrap_sequence;
	nacc_bootstrap_u64 nacc_pool_virtual_base;
	nacc_bootstrap_u64 bitmap_backing_virtual_base;
};

#define NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE \
	((unsigned int)sizeof(struct nacc_bootstrap_descriptor))

#define NACC_BOOTSTRAP_CAP_PROBE (1UL << 0)
#define NACC_BOOTSTRAP_CAP_BOOTSTRAP (1UL << 1)
#define NACC_BOOTSTRAP_CAP_GET_MEASUREMENT (1UL << 2)
#define NACC_BOOTSTRAP_CAP_FATAL (1UL << 3)
#define NACC_BOOTSTRAP_CAP_REQUIRED \
	(NACC_BOOTSTRAP_CAP_PROBE | NACC_BOOTSTRAP_CAP_BOOTSTRAP | \
	 NACC_BOOTSTRAP_CAP_GET_MEASUREMENT | NACC_BOOTSTRAP_CAP_FATAL)

/* 返回 0 表示 descriptor 可被 Linux 接受；不会执行或确认 bootstrap。 */
int nacc_bootstrap_validate(const struct nacc_bootstrap_descriptor *descriptor,
				    size_t buffer_size);
int nacc_bootstrap_physical_layout_validate(
	const struct nacc_bootstrap_physical_layout *layout);
int nacc_bootstrap_physical_layout_match(
	const struct nacc_bootstrap_descriptor *descriptor,
	size_t descriptor_buffer_size,
	const struct nacc_bootstrap_physical_layout *layout);
int nacc_bootstrap_descriptor_build(
	struct nacc_bootstrap_descriptor *descriptor,
	const struct nacc_bootstrap_physical_layout *layout,
	nacc_bootstrap_u64 bootstrap_sequence);

/* 这些 validator 不依赖内核运行时状态，可由 host selftest 直接编译。 */
int nacc_bootstrap_agent_memory_range_validate(nacc_bootstrap_u64 base,
						       nacc_bootstrap_u64 size);
int nacc_bootstrap_agent_memory_state_validate(
		const struct nacc_bootstrap_agent_memory_state *state,
		bool require_present, unsigned int physical_address_bits);

/* 只有完整且无未知 bit 的 capability 集合才允许后续 bootstrap 代码使用。 */
bool nacc_bootstrap_capabilities_allow_bootstrap(unsigned long capabilities);

/* setup_arch 在 sbi_init 后调用；该函数只 probe 和记录，不发起 BOOTSTRAP。 */
void nacc_bootstrap_sbi_probe(void);
unsigned long nacc_bootstrap_sbi_capabilities(void);
void nacc_bootstrap_memory_preflight(void);
bool nacc_bootstrap_agent_memory_available(void);
const struct nacc_bootstrap_range *nacc_bootstrap_agent_memory_snapshot(void);
bool nacc_bootstrap_physical_layout_available(void);
const struct nacc_bootstrap_physical_layout *
nacc_bootstrap_physical_layout_snapshot(void);

_Static_assert(sizeof(struct nacc_bootstrap_range) == 16,
		       "nacc_bootstrap_range ABI size changed");
_Static_assert(sizeof(struct nacc_bootstrap_physical_layout) == 128,
		       "nacc_bootstrap_physical_layout size changed");
_Static_assert(sizeof(struct nacc_bootstrap_descriptor) == 232,
		       "nacc_bootstrap_descriptor ABI size changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor, feature_bits) == 16,
		       "nacc_bootstrap_descriptor feature_bits offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor, agent_region) == 24,
		       "nacc_bootstrap_descriptor agent_region offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor,
			       delegation_exception_mask) == 136,
		       "nacc_bootstrap_descriptor delegation offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor, reserved) == 152,
		       "nacc_bootstrap_descriptor reserved offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor,
			       agent_virtual_base) == 184,
		       "nacc_bootstrap_descriptor virtual layout offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor,
			       mailbox_virtual_base) == 192,
		       "nacc_bootstrap_descriptor mailbox VA offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor,
			       emergency_stack_virtual_top) == 200,
		       "nacc_bootstrap_descriptor emergency stack VA offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor,
			       bootstrap_sequence) == 208,
		       "nacc_bootstrap_descriptor sequence offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor,
			       nacc_pool_virtual_base) ==
		       NACC_BOOTSTRAP_DESCRIPTOR_V1_1_SIZE,
		       "nacc_bootstrap_descriptor pool VA offset changed");
_Static_assert(offsetof(struct nacc_bootstrap_descriptor,
			       bitmap_backing_virtual_base) == 224,
		       "nacc_bootstrap_descriptor bitmap backing VA offset changed");

#endif /* _ASM_RISCV_NACC_BOOTSTRAP_H */
