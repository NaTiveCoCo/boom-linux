// SPDX-License-Identifier: GPL-2.0-only
/* NACC single-mm live ROOT_L0 pool layout 的 host-buildable pure planner。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <asm/nacc_live_root.h>

static int nacc_live_root_reserve_pages(nacc_bootstrap_u64 *cursor,
					nacc_bootstrap_u64 end,
					nacc_bootstrap_u64 page_count,
					nacc_bootstrap_u64 *base)
{
	nacc_bootstrap_u64 available_pages;

	if (!page_count)
		return -EINVAL;
	available_pages = (end - *cursor) / NACC_ROOT_PAGE_SIZE;
	if (page_count > available_pages)
		return -ENOSPC;
	*base = *cursor;
	*cursor += page_count * NACC_ROOT_PAGE_SIZE;
	return 0;
}

int nacc_live_root_layout_plan(struct nacc_live_root_layout_result *result,
			       const struct nacc_bootstrap_physical_layout *layout,
			       const struct nacc_root_build_result *control_root,
			       const struct nacc_live_root_layout_request *request)
{
	struct nacc_live_root_layout_result candidate;
	nacc_bootstrap_u64 control_page_count;
	nacc_bootstrap_u64 expected_control_end;
	nacc_bootstrap_u64 cursor;
	nacc_bootstrap_u64 end;
	size_t index;
	int ret;

	if (!result || !layout || !control_root || !request ||
	    !request->ptp_page_count || !request->payload_mapping_count ||
	    request->payload_mapping_count > NACC_ROOT_MAX_USER_MAPPINGS ||
	    !request->payload_page_counts)
		return -EINVAL;
	ret = nacc_bootstrap_physical_layout_validate(layout);
	if (ret)
		return ret;
	control_page_count = layout->nacc_pool.size / NACC_ROOT_PAGE_SIZE;
	if (control_root->root_physical_address !=
		    layout->control_root_l0.base ||
	    control_root->lower_ptp_count >= control_page_count ||
	    (control_root->next_pool_physical_address &
	     (NACC_ROOT_PAGE_SIZE - 1)) ||
	    control_root->next_pool_physical_address <
		    layout->control_root_l0.base + NACC_ROOT_PAGE_SIZE ||
	    control_root->next_pool_physical_address >
		    layout->nacc_pool.base + layout->nacc_pool.size)
		return -EINVAL;
	expected_control_end = layout->nacc_pool.base +
		(control_root->lower_ptp_count + 1) * NACC_ROOT_PAGE_SIZE;
	if (control_root->next_pool_physical_address != expected_control_end)
		return -EINVAL;

	memset(&candidate, 0, sizeof(candidate));
	cursor = control_root->next_pool_physical_address;
	end = layout->nacc_pool.base + layout->nacc_pool.size;
	ret = nacc_live_root_reserve_pages(&cursor, end,
					   request->ptp_page_count,
					   &candidate.ptp_base);
	if (ret)
		return ret;
	candidate.ptp_size = request->ptp_page_count * NACC_ROOT_PAGE_SIZE;

	for (index = 0; index < request->payload_mapping_count; index++) {
		nacc_bootstrap_u64 page_count =
			request->payload_page_counts[index];
		nacc_bootstrap_u64 *base = &candidate.payload_bases[index];

		ret = nacc_live_root_reserve_pages(&cursor, end, page_count, base);
		if (ret)
			return ret;
		candidate.payload_page_count += page_count;
	}
	candidate.allocation_end = cursor;
	*result = candidate;
	return 0;
}
