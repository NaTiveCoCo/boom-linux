// SPDX-License-Identifier: GPL-2.0-only
/* NACC initial Sv39 control ROOT_L0 的 host-buildable pure builder。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stddef.h>
#endif

#include <asm/nacc_root.h>

#define NACC_ROOT_PPN_SHIFT 10U
#define NACC_ROOT_PAGE_SHIFT 12U
#define NACC_ROOT_VPN_BITS 9U
#define NACC_ROOT_PHYSICAL_BITS 56U

struct nacc_root_range {
	nacc_bootstrap_u64 virtual_base;
	nacc_bootstrap_u64 physical_base;
	nacc_bootstrap_u64 page_count;
	nacc_bootstrap_u64 permissions;
};

struct nacc_root_cursor {
	nacc_bootstrap_u64 next;
	nacc_bootstrap_u64 end;
	nacc_bootstrap_u64 root;
	nacc_bootstrap_u64 lower_ptp_count;
	const struct nacc_root_backend *backend;
};

static int nacc_root_backend_result(int ret)
{
	return ret < 0 ? ret : ret ? -EIO : 0;
}

static bool nacc_root_page_aligned(nacc_bootstrap_u64 value)
{
	return !(value & (NACC_ROOT_PAGE_SIZE - 1));
}

static bool nacc_root_page_in_pool(
	const struct nacc_bootstrap_physical_layout *layout,
	nacc_bootstrap_u64 physical_address)
{
	return physical_address >= layout->nacc_pool.base &&
	       physical_address <= layout->nacc_pool.base +
		       layout->nacc_pool.size - NACC_ROOT_PAGE_SIZE;
}

static bool nacc_root_range_contains(nacc_bootstrap_u64 outer_base,
				     nacc_bootstrap_u64 outer_size,
				     nacc_bootstrap_u64 inner_base,
				     nacc_bootstrap_u64 inner_size)
{
	return inner_base >= outer_base && inner_base - outer_base <= outer_size &&
	       inner_size <= outer_size - (inner_base - outer_base);
}

static bool nacc_root_ranges_overlap(nacc_bootstrap_u64 left_base,
				     nacc_bootstrap_u64 left_size,
				     nacc_bootstrap_u64 right_base,
				     nacc_bootstrap_u64 right_size)
{
	return left_base < right_base + right_size &&
	       right_base < left_base + left_size;
}

static int nacc_root_round_pages(nacc_bootstrap_u64 size,
				 nacc_bootstrap_u64 *page_count)
{
	if (!size || size > ~(nacc_bootstrap_u64)0 -
				 (NACC_ROOT_PAGE_SIZE - 1))
		return -EINVAL;
	*page_count = (size + NACC_ROOT_PAGE_SIZE - 1) /
		      NACC_ROOT_PAGE_SIZE;
	return 0;
}

static nacc_bootstrap_u64 nacc_root_table_pte(
	nacc_bootstrap_u64 physical_address)
{
	return (physical_address >> NACC_ROOT_PAGE_SHIFT) <<
		       NACC_ROOT_PPN_SHIFT |
	       NACC_ROOT_PTE_VALID;
}

static nacc_bootstrap_u64 nacc_root_leaf_pte(
	nacc_bootstrap_u64 physical_address, nacc_bootstrap_u64 permissions)
{
	nacc_bootstrap_u64 pte =
		(physical_address >> NACC_ROOT_PAGE_SHIFT) << NACC_ROOT_PPN_SHIFT;

	pte |= NACC_ROOT_PTE_VALID | NACC_ROOT_PTE_ACCESSED | permissions;
	if (permissions & NACC_ROOT_PTE_WRITE)
		pte |= NACC_ROOT_PTE_DIRTY;
	return pte;
}

static int nacc_root_allocate_table(struct nacc_root_cursor *cursor,
				    nacc_bootstrap_u64 *physical_address)
{
	int ret;

	while (cursor->next < cursor->end) {
		*physical_address = cursor->next;
		cursor->next += NACC_ROOT_PAGE_SIZE;
		if (*physical_address == cursor->root)
			continue;
		ret = nacc_root_backend_result(cursor->backend->zero_page(
			*physical_address, cursor->backend->opaque));
		if (ret)
			return ret;
		cursor->lower_ptp_count++;
		return 0;
	}
	return -ENOSPC;
}

static int nacc_root_follow_or_allocate(
	struct nacc_root_cursor *cursor,
	const struct nacc_bootstrap_physical_layout *layout,
	nacc_bootstrap_u64 table, nacc_bootstrap_u32 index,
	nacc_bootstrap_u64 *child)
{
	nacc_bootstrap_u64 pte;
	int ret;

	ret = nacc_root_backend_result(cursor->backend->read_pte(
		table, index, &pte, cursor->backend->opaque));
	if (ret)
		return ret;
	if (!pte) {
		ret = nacc_root_allocate_table(cursor, child);
		if (ret)
			return ret;
		return nacc_root_backend_result(cursor->backend->write_pte(
			table, index, nacc_root_table_pte(*child),
			cursor->backend->opaque));
	}
	if ((pte & 0x3ffULL) != NACC_ROOT_PTE_VALID)
		return -EINVAL;
	*child = (pte >> NACC_ROOT_PPN_SHIFT) << NACC_ROOT_PAGE_SHIFT;
	if (!nacc_root_page_aligned(*child) ||
	    !nacc_root_page_in_pool(layout, *child) || *child == cursor->root)
		return -EINVAL;
	return 0;
}

static int nacc_root_map_leaf(
	struct nacc_root_cursor *cursor,
	const struct nacc_bootstrap_physical_layout *layout,
	nacc_bootstrap_u64 virtual_address, nacc_bootstrap_u64 physical_address,
	nacc_bootstrap_u64 permissions)
{
	nacc_bootstrap_u64 l1;
	nacc_bootstrap_u64 l0;
	nacc_bootstrap_u64 old_pte;
	nacc_bootstrap_u32 vpn2;
	nacc_bootstrap_u32 vpn1;
	nacc_bootstrap_u32 vpn0;
	int ret;

	vpn2 = (virtual_address >> 30) & (NACC_ROOT_PTE_COUNT - 1);
	vpn1 = (virtual_address >> 21) & (NACC_ROOT_PTE_COUNT - 1);
	vpn0 = (virtual_address >> 12) & (NACC_ROOT_PTE_COUNT - 1);
	ret = nacc_root_follow_or_allocate(cursor, layout, cursor->root, vpn2,
					   &l1);
	if (ret)
		return ret;
	ret = nacc_root_follow_or_allocate(cursor, layout, l1, vpn1, &l0);
	if (ret)
		return ret;
	ret = nacc_root_backend_result(cursor->backend->read_pte(
		l0, vpn0, &old_pte, cursor->backend->opaque));
	if (ret)
		return ret;
	if (old_pte)
		return -EEXIST;
	return nacc_root_backend_result(cursor->backend->write_pte(
		l0, vpn0, nacc_root_leaf_pte(physical_address, permissions),
		cursor->backend->opaque));
}

static int nacc_root_initialize_ranges(
	struct nacc_root_range ranges[5],
	const struct nacc_bootstrap_physical_layout *layout,
	const struct nacc_bootstrap_descriptor *descriptor,
	const struct nacc_agent_image_metadata *image)
{
	nacc_bootstrap_u64 page_count;
	nacc_bootstrap_u64 span;
	size_t index;
	int ret;

	for (index = 0; index < 2; index++) {
		ret = nacc_root_round_pages(image->segments[index].memory_size,
					    &page_count);
		if (ret)
			return ret;
		span = page_count * NACC_ROOT_PAGE_SIZE;
		if (image->segments[index].virtual_offset >
			layout->agent_region.size ||
		    span > layout->agent_region.size -
			    image->segments[index].virtual_offset ||
		    descriptor->agent_virtual_base >
			    NACC_ROOT_SV39_USER_LIMIT -
			    image->segments[index].virtual_offset ||
		    descriptor->agent_virtual_base +
			    image->segments[index].virtual_offset >
			    NACC_ROOT_SV39_USER_LIMIT - span)
			return -ERANGE;
		ranges[index] = (struct nacc_root_range) {
			.virtual_base = descriptor->agent_virtual_base +
				image->segments[index].virtual_offset,
			.physical_base = layout->agent_region.base +
				image->segments[index].virtual_offset,
			.page_count = page_count,
			.permissions = index ?
				NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE :
				NACC_ROOT_PTE_READ | NACC_ROOT_PTE_EXECUTE,
		};
	}
	ranges[2] = (struct nacc_root_range) {
		.virtual_base = descriptor->mailbox_virtual_base,
		.physical_base = layout->mailbox.base,
		.page_count = layout->mailbox.size / NACC_ROOT_PAGE_SIZE,
		.permissions = NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE,
	};
	ranges[3] = (struct nacc_root_range) {
		.virtual_base = descriptor->nacc_pool_virtual_base,
		.physical_base = layout->nacc_pool.base,
		.page_count = layout->nacc_pool.size / NACC_ROOT_PAGE_SIZE,
		.permissions = NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE,
	};
	ranges[4] = (struct nacc_root_range) {
		.virtual_base = descriptor->bitmap_backing_virtual_base,
		.physical_base = layout->bitmap_backing.base,
		.page_count = layout->bitmap_backing.size / NACC_ROOT_PAGE_SIZE,
		.permissions = NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE,
	};
	return 0;
}

static int nacc_root_validate_live_config(
	const struct nacc_bootstrap_physical_layout *layout,
	const struct nacc_bootstrap_descriptor *descriptor,
	const struct nacc_root_range management[5],
	const struct nacc_root_live_config *config)
{
	const nacc_bootstrap_u64 allowed_permissions =
		NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE |
		NACC_ROOT_PTE_EXECUTE | NACC_ROOT_PTE_USER;
	size_t index;

	if (!config || !nacc_root_page_aligned(config->root_physical_address) ||
	    !nacc_root_page_aligned(config->ptp_pool_base) ||
	    !nacc_root_page_aligned(config->ptp_pool_size) ||
	    !config->ptp_pool_size ||
	    !config->control_root ||
	    config->control_root->root_physical_address !=
		    layout->control_root_l0.base ||
	    config->control_root->next_pool_physical_address <
		    layout->nacc_pool.base ||
	    config->control_root->next_pool_physical_address >
		    layout->nacc_pool.base + layout->nacc_pool.size ||
	    config->ptp_pool_base <
		    config->control_root->next_pool_physical_address ||
	    config->user_mapping_count > NACC_ROOT_MAX_USER_MAPPINGS ||
	    (config->user_mapping_count && !config->user_mappings) ||
	    !nacc_root_range_contains(layout->nacc_pool.base,
				      layout->nacc_pool.size,
				      config->ptp_pool_base,
				      config->ptp_pool_size) ||
	    !nacc_root_range_contains(config->ptp_pool_base,
				      config->ptp_pool_size,
				      config->root_physical_address,
				      NACC_ROOT_PAGE_SIZE))
		return -EINVAL;

	for (index = 0; index < config->user_mapping_count; index++) {
		const struct nacc_root_user_mapping *mapping =
			&config->user_mappings[index];
		nacc_bootstrap_u64 size;
		size_t other;

		if (!mapping->page_count ||
		    mapping->page_count > ~(nacc_bootstrap_u64)0 /
						  NACC_ROOT_PAGE_SIZE)
			return -EINVAL;
		size = mapping->page_count * NACC_ROOT_PAGE_SIZE;
		if (!nacc_root_page_aligned(mapping->virtual_base) ||
		    !nacc_root_page_aligned(mapping->physical_base) ||
		    mapping->virtual_base >= NACC_ROOT_SV39_USER_LIMIT ||
		    size > NACC_ROOT_SV39_USER_LIMIT - mapping->virtual_base ||
		    mapping->physical_base >=
			    (1ULL << NACC_ROOT_PHYSICAL_BITS) ||
		    size > (1ULL << NACC_ROOT_PHYSICAL_BITS) -
				   mapping->physical_base ||
		    (mapping->permissions & ~allowed_permissions) ||
		    !(mapping->permissions & NACC_ROOT_PTE_USER) ||
		    !(mapping->permissions & (NACC_ROOT_PTE_READ |
					       NACC_ROOT_PTE_EXECUTE)) ||
		    ((mapping->permissions & NACC_ROOT_PTE_WRITE) &&
		     !(mapping->permissions & NACC_ROOT_PTE_READ)) ||
		    !nacc_root_range_contains(layout->nacc_pool.base,
					      layout->nacc_pool.size,
					      mapping->physical_base, size) ||
		    nacc_root_ranges_overlap(
			    mapping->physical_base, size,
			    layout->nacc_pool.base,
			    config->control_root->next_pool_physical_address -
				    layout->nacc_pool.base) ||
		    nacc_root_ranges_overlap(mapping->physical_base, size,
					 config->ptp_pool_base,
					 config->ptp_pool_size) ||
		    nacc_root_ranges_overlap(mapping->virtual_base, size,
					 descriptor->agent_virtual_base,
					 layout->agent_region.size))
			return -EINVAL;
		for (other = 0; other < 5; other++) {
			nacc_bootstrap_u64 management_size =
				management[other].page_count * NACC_ROOT_PAGE_SIZE;

			if (nacc_root_ranges_overlap(mapping->virtual_base,
						   size,
						   management[other].virtual_base,
						   management_size))
				return -EEXIST;
		}
		for (other = 0; other < index; other++) {
			const struct nacc_root_user_mapping *prior =
				&config->user_mappings[other];
			nacc_bootstrap_u64 prior_size =
				prior->page_count * NACC_ROOT_PAGE_SIZE;

			if (nacc_root_ranges_overlap(mapping->virtual_base, size,
						   prior->virtual_base,
						   prior_size) ||
			    nacc_root_ranges_overlap(mapping->physical_base, size,
						   prior->physical_base,
						   prior_size))
				return -EEXIST;
		}
	}
	return 0;
}

static int nacc_root_build_common(
	struct nacc_root_build_result *result,
	const struct nacc_bootstrap_physical_layout *layout,
	const struct nacc_bootstrap_descriptor *descriptor,
	const struct nacc_agent_image_metadata *image,
	const nacc_bootstrap_u64 kernel_root_high[256],
	const struct nacc_root_live_config *config,
	const struct nacc_root_backend *backend)
{
	struct nacc_root_build_result candidate = {};
	struct nacc_root_range ranges[5];
	struct nacc_root_cursor cursor;
	nacc_bootstrap_u64 virtual_address;
	nacc_bootstrap_u64 physical_address;
	nacc_bootstrap_u64 page;
	size_t index;
	int ret;

	if (!result || !layout || !descriptor || !image || !kernel_root_high ||
	    !backend || !backend->zero_page || !backend->read_pte ||
	    !backend->write_pte || !backend->opaque)
		return -EINVAL;
	ret = nacc_bootstrap_physical_layout_validate(layout);
	if (ret)
		return ret;
	ret = nacc_bootstrap_physical_layout_match(descriptor,
					   sizeof(*descriptor), layout);
	if (ret)
		return ret;
	ret = nacc_agent_image_metadata_validate(image);
	if (ret)
		return ret;
	if (layout->arena.base + layout->arena.size >
		    (1ULL << NACC_ROOT_PHYSICAL_BITS) ||
	    !nacc_root_page_in_pool(layout, layout->control_root_l0.base))
		return -ERANGE;
	ret = nacc_root_initialize_ranges(ranges, layout, descriptor, image);
	if (ret)
		return ret;
	if (config) {
		ret = nacc_root_validate_live_config(layout, descriptor, ranges,
					     config);
		if (ret)
			return ret;
	}

	cursor = (struct nacc_root_cursor) {
		.next = config ? config->ptp_pool_base : layout->nacc_pool.base,
		.end = config ? config->ptp_pool_base + config->ptp_pool_size :
				layout->nacc_pool.base + layout->nacc_pool.size,
		.root = config ? config->root_physical_address :
				layout->control_root_l0.base,
		.backend = backend,
	};
	ret = nacc_root_backend_result(backend->zero_page(
		cursor.root, backend->opaque));
	if (ret)
		return ret;
	for (index = 0; index < NACC_ROOT_KERNEL_HALF_INDEX; index++) {
		ret = nacc_root_backend_result(backend->write_pte(
			cursor.root, NACC_ROOT_KERNEL_HALF_INDEX + index,
			kernel_root_high[index], backend->opaque));
		if (ret)
			return ret;
	}

	for (index = 0; index < 5; index++) {
		for (page = 0; page < ranges[index].page_count; page++) {
			virtual_address = ranges[index].virtual_base +
				page * NACC_ROOT_PAGE_SIZE;
			physical_address = ranges[index].physical_base +
				page * NACC_ROOT_PAGE_SIZE;
			ret = nacc_root_map_leaf(&cursor, layout, virtual_address,
						 physical_address,
						 ranges[index].permissions);
			if (ret)
				return ret;
			candidate.leaf_count++;
		}
	}
	if (config) {
		for (index = 0; index < config->user_mapping_count; index++) {
			const struct nacc_root_user_mapping *mapping =
				&config->user_mappings[index];

			for (page = 0; page < mapping->page_count; page++) {
				virtual_address = mapping->virtual_base +
					page * NACC_ROOT_PAGE_SIZE;
				physical_address = mapping->physical_base +
					page * NACC_ROOT_PAGE_SIZE;
				ret = nacc_root_map_leaf(
					&cursor, layout, virtual_address,
					physical_address, mapping->permissions);
				if (ret)
					return ret;
				candidate.leaf_count++;
			}
		}
	}

	candidate.root_physical_address = cursor.root;
	candidate.next_pool_physical_address = cursor.next;
	candidate.lower_ptp_count = cursor.lower_ptp_count;
	*result = candidate;
	return 0;
}

int nacc_root_build(struct nacc_root_build_result *result,
		    const struct nacc_bootstrap_physical_layout *layout,
		    const struct nacc_bootstrap_descriptor *descriptor,
		    const struct nacc_agent_image_metadata *image,
		    const nacc_bootstrap_u64 kernel_root_high[256],
		    const struct nacc_root_backend *backend)
{
	return nacc_root_build_common(result, layout, descriptor, image,
				      kernel_root_high, NULL, backend);
}

int nacc_root_build_live(struct nacc_root_build_result *result,
			 const struct nacc_bootstrap_physical_layout *layout,
			 const struct nacc_bootstrap_descriptor *descriptor,
			 const struct nacc_agent_image_metadata *image,
			 const nacc_bootstrap_u64 kernel_root_high[256],
			 const struct nacc_root_live_config *config,
			 const struct nacc_root_backend *backend)
{
	if (!config)
		return -EINVAL;
	return nacc_root_build_common(result, layout, descriptor, image,
				      kernel_root_high, config, backend);
}
