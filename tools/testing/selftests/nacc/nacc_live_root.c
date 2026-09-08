// SPDX-License-Identifier: GPL-2.0-only
/* NACC single-mm live ROOT_L0 pool layout planner contract test。 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "../../../../arch/riscv/include/asm/nacc_live_root.h"
#include "../kselftest.h"

static void initialize_layout(struct nacc_bootstrap_physical_layout *layout)
{
	memset(layout, 0, sizeof(*layout));
	layout->arena.base = UINT64_C(0x08000000);
	layout->arena.size = UINT64_C(0x60000000);
	layout->agent_region.base = UINT64_C(0x10000000);
	layout->agent_region.size = UINT64_C(0x01000000);
	layout->bitmap_target.base = UINT64_C(0x20000000);
	layout->bitmap_target.size = UINT64_C(0x04000000);
	layout->nacc_pool.base = UINT64_C(0x21000000);
	layout->nacc_pool.size = UINT64_C(0x02000000);
	layout->control_root_l0.base = layout->nacc_pool.base;
	layout->control_root_l0.size = NACC_ROOT_PAGE_SIZE;
	layout->bitmap_backing.base = UINT64_C(0x30000000);
	layout->bitmap_backing.size = NACC_ROOT_PAGE_SIZE;
	layout->mailbox.base = UINT64_C(0x40000000);
	layout->mailbox.size = NACC_ROOT_PAGE_SIZE;
	layout->emergency_stack.base = UINT64_C(0x50000000);
	layout->emergency_stack.size = NACC_ROOT_PAGE_SIZE;
}

static void report_contract(bool condition, const char *name)
{
	if (condition)
		ksft_test_result_pass("%s\n", name);
	else
		ksft_test_result_fail("%s\n", name);
}

int main(void)
{
	struct nacc_bootstrap_physical_layout layout;
	struct nacc_root_build_result control_root;
	struct nacc_live_root_layout_result result;
	struct nacc_live_root_layout_result sentinel;
	struct nacc_live_root_layout_request request;
	nacc_bootstrap_u64 payload_pages[] = { 1, 3 };
	int ret;

	ksft_print_header();
	ksft_set_plan(13);
	initialize_layout(&layout);
	control_root = (struct nacc_root_build_result) {
		.root_physical_address = layout.control_root_l0.base,
		.next_pool_physical_address = layout.nacc_pool.base +
			8 * NACC_ROOT_PAGE_SIZE,
	};
	request = (struct nacc_live_root_layout_request) {
		.ptp_page_count = 64,
		.payload_page_counts = payload_pages,
		.payload_mapping_count = 2,
	};
	memset(&result, 0xa5, sizeof(result));
	ret = nacc_live_root_layout_plan(&result, &layout, &control_root,
					 &request);
	report_contract(!ret, "valid live layout is planned");
	report_contract(result.ptp_base ==
			layout.nacc_pool.base + 8 * NACC_ROOT_PAGE_SIZE,
			"PTP slice follows the control prefix");
	report_contract(result.ptp_size == 64 * NACC_ROOT_PAGE_SIZE,
			"PTP slice has the requested size");
	report_contract(result.payload_bases[0] ==
			result.ptp_base + result.ptp_size,
			"first payload follows the PTP slice");
	report_contract(result.payload_bases[1] ==
			result.payload_bases[0] + NACC_ROOT_PAGE_SIZE,
			"payload mappings are contiguous and ordered");
	report_contract(result.payload_page_count == 4,
			"payload page total is exact");
	report_contract(result.allocation_end ==
			result.payload_bases[1] + 3 * NACC_ROOT_PAGE_SIZE,
			"allocation end covers every reserved slice");
	report_contract(!result.payload_bases[2],
			"unused payload slots are cleared");

	sentinel = result;
	request.ptp_page_count = layout.nacc_pool.size / NACC_ROOT_PAGE_SIZE;
	ret = nacc_live_root_layout_plan(&result, &layout, &control_root,
					 &request);
	report_contract(ret == -ENOSPC &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"pool exhaustion does not publish a partial result");

	request.ptp_page_count = 64;
	request.payload_mapping_count = 0;
	ret = nacc_live_root_layout_plan(&result, &layout, &control_root,
					 &request);
	report_contract(ret == -EINVAL &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"an empty payload request is rejected atomically");

	request.payload_mapping_count = 2;
	payload_pages[1] = UINT64_MAX;
	ret = nacc_live_root_layout_plan(&result, &layout, &control_root,
					 &request);
	report_contract(ret == -ENOSPC &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"oversized page counts cannot overflow allocation");

	payload_pages[1] = 3;
	control_root.next_pool_physical_address--;
	ret = nacc_live_root_layout_plan(&result, &layout, &control_root,
					 &request);
	report_contract(ret == -EINVAL &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"an invalid control prefix is rejected atomically");

	control_root.next_pool_physical_address = layout.nacc_pool.base;
	ret = nacc_live_root_layout_plan(&result, &layout, &control_root,
					 &request);
	report_contract(ret == -EINVAL &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"the control prefix must contain its ROOT_L0 page");

	ksft_finished();
}
