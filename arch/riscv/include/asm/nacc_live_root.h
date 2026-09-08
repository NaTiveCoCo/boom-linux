/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC single-mm live ROOT_L0 pool layout planner 的内部接口。 */
#ifndef _ASM_RISCV_NACC_LIVE_ROOT_H
#define _ASM_RISCV_NACC_LIVE_ROOT_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

#include <asm/nacc_root.h>

struct nacc_live_root_layout_request {
	/* 包含 live ROOT_L0 本身以及所有 lower PTP。 */
	nacc_bootstrap_u64 ptp_page_count;
	const nacc_bootstrap_u64 *payload_page_counts;
	size_t payload_mapping_count;
};

struct nacc_live_root_layout_result {
	nacc_bootstrap_u64 ptp_base;
	nacc_bootstrap_u64 ptp_size;
	nacc_bootstrap_u64 payload_bases[NACC_ROOT_MAX_USER_MAPPINGS];
	nacc_bootstrap_u64 payload_page_count;
	nacc_bootstrap_u64 allocation_end;
};

/*
 * control_root 之前的 pool prefix 已由 control root builder 占用。成功时，
 * PTP slice 紧随该 prefix，所有 payload slice 再按请求顺序连续排列。
 * 失败时 result 保持不变；外层 owner 负责独占整个已规划区间。
 */
int nacc_live_root_layout_plan(struct nacc_live_root_layout_result *result,
			       const struct nacc_bootstrap_physical_layout *layout,
			       const struct nacc_root_build_result *control_root,
			       const struct nacc_live_root_layout_request *request);

#endif /* _ASM_RISCV_NACC_LIVE_ROOT_H */
