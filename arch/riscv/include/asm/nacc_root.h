/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC initial Sv39 control ROOT_L0 builder 的内部接口。 */
#ifndef _ASM_RISCV_NACC_ROOT_H
#define _ASM_RISCV_NACC_ROOT_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

#include <asm/nacc_agent_image.h>
#include <asm/nacc_bootstrap.h>

#define NACC_ROOT_PAGE_SIZE 4096ULL
#define NACC_ROOT_PTE_COUNT 512U
#define NACC_ROOT_KERNEL_HALF_INDEX 256U
#define NACC_ROOT_SV39_USER_LIMIT (1ULL << 38)
#define NACC_ROOT_PTE_VALID (1ULL << 0)
#define NACC_ROOT_PTE_READ (1ULL << 1)
#define NACC_ROOT_PTE_WRITE (1ULL << 2)
#define NACC_ROOT_PTE_EXECUTE (1ULL << 3)
#define NACC_ROOT_PTE_USER (1ULL << 4)
#define NACC_ROOT_PTE_GLOBAL (1ULL << 5)
#define NACC_ROOT_PTE_ACCESSED (1ULL << 6)
#define NACC_ROOT_PTE_DIRTY (1ULL << 7)
#define NACC_ROOT_MAX_USER_MAPPINGS 16U

struct nacc_root_user_mapping {
	nacc_bootstrap_u64 virtual_base;
	nacc_bootstrap_u64 physical_base;
	nacc_bootstrap_u64 page_count;
	nacc_bootstrap_u64 permissions;
};

struct nacc_root_build_result {
	nacc_bootstrap_u64 root_physical_address;
	nacc_bootstrap_u64 next_pool_physical_address;
	nacc_bootstrap_u64 lower_ptp_count;
	nacc_bootstrap_u64 leaf_count;
};

struct nacc_root_live_config {
	nacc_bootstrap_u64 root_physical_address;
	nacc_bootstrap_u64 ptp_pool_base;
	nacc_bootstrap_u64 ptp_pool_size;
	const struct nacc_root_build_result *control_root;
	const struct nacc_root_user_mapping *user_mappings;
	size_t user_mapping_count;
};

typedef int (*nacc_root_zero_page_t)(nacc_bootstrap_u64 physical_address,
				     void *opaque);
typedef int (*nacc_root_read_pte_t)(nacc_bootstrap_u64 physical_address,
				    nacc_bootstrap_u32 index,
				    nacc_bootstrap_u64 *value, void *opaque);
typedef int (*nacc_root_write_pte_t)(nacc_bootstrap_u64 physical_address,
				     nacc_bootstrap_u32 index,
				     nacc_bootstrap_u64 value, void *opaque);

struct nacc_root_backend {
	nacc_root_zero_page_t zero_page;
	nacc_root_read_pte_t read_pte;
	nacc_root_write_pte_t write_pte;
	void *opaque;
};

/*
 * kernel_root_high 包含当前 init_mm.pgd 的 index 256..511 raw PTE。
 * 成功前 result 保持不变；backend page 写入失败属于 early-boot fatal 状态。
 */
int nacc_root_build(struct nacc_root_build_result *result,
		    const struct nacc_bootstrap_physical_layout *layout,
		    const struct nacc_bootstrap_descriptor *descriptor,
		    const struct nacc_agent_image_metadata *image,
		    const nacc_bootstrap_u64 kernel_root_high[256],
		    const struct nacc_root_backend *backend);
/*
 * 失败时不发布 result，但 staging PTP slice 可能已有写入；调用方必须在重用
 * 该 slice 前完整清零。control_root 必须来自同一 layout 的 control build，
 * ptp_pool slice 必须由外层 allocator 独占。
 */
int nacc_root_build_live(struct nacc_root_build_result *result,
			 const struct nacc_bootstrap_physical_layout *layout,
			 const struct nacc_bootstrap_descriptor *descriptor,
			 const struct nacc_agent_image_metadata *image,
			 const nacc_bootstrap_u64 kernel_root_high[256],
			 const struct nacc_root_live_config *config,
			 const struct nacc_root_backend *backend);

#ifdef __KERNEL__
void nacc_root_prepare(void);
bool nacc_root_is_ready(void);
const struct nacc_bootstrap_descriptor *nacc_root_descriptor_snapshot(void);
const struct nacc_root_build_result *nacc_root_result_snapshot(void);
#endif

#endif /* _ASM_RISCV_NACC_ROOT_H */
