// SPDX-License-Identifier: GPL-2.0-only
/* NACC private bootstrap descriptor validator。 */

#ifdef __KERNEL__
#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/libfdt.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <asm/sparsemem.h>
#include <asm/sbi.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#include <asm/nacc_bootstrap.h>

#ifdef __KERNEL__
_Static_assert(SBI_EXT_NACC >= SBI_EXT_FIRMWARE_START &&
		       SBI_EXT_NACC <= SBI_EXT_FIRMWARE_END,
		       "NACC extension ID must stay in the SBI firmware range");
_Static_assert(SBI_EXT_NACC_CAP_ALL == NACC_BOOTSTRAP_CAP_REQUIRED,
		       "NACC SBI capability constants diverged");
#endif

bool nacc_bootstrap_capabilities_allow_bootstrap(unsigned long capabilities)
{
	return (capabilities & NACC_BOOTSTRAP_CAP_REQUIRED) ==
		       NACC_BOOTSTRAP_CAP_REQUIRED &&
	       !(capabilities & ~NACC_BOOTSTRAP_CAP_REQUIRED);
}

static bool nacc_bootstrap_range_valid(
	const struct nacc_bootstrap_range *range)
{
	if (!range->size)
		return false;
	if ((range->base | range->size) &
	    (NACC_BOOTSTRAP_PAGE_SIZE - 1))
		return false;
	if (range->base > ~(nacc_bootstrap_u64)0 - range->size)
		return false;

	return true;
}

int nacc_bootstrap_agent_memory_range_validate(nacc_bootstrap_u64 base,
						       nacc_bootstrap_u64 size)
{
	if (!base || !size)
		return -EINVAL;
	if ((base | size) & (NACC_BOOTSTRAP_PAGE_SIZE - 1))
		return -EINVAL;
	if (base > ~(nacc_bootstrap_u64)0 - size)
		return -EOVERFLOW;

	return 0;
}

int nacc_bootstrap_agent_memory_state_validate(
	const struct nacc_bootstrap_agent_memory_state *state,
	bool require_present, unsigned int physical_address_bits)
{
	nacc_bootstrap_u64 end;
	nacc_bootstrap_u64 address_limit;
	int ret;

	if (!state || !physical_address_bits || physical_address_bits > 64)
		return -EINVAL;
	if (state->matches > 1)
		return -EEXIST;
	if (!state->matches)
		return require_present ? -ENODEV : 0;
	ret = nacc_bootstrap_agent_memory_range_validate(state->range.base,
							state->range.size);
	if (ret)
		return ret;

	end = state->range.base + state->range.size;
	if (physical_address_bits < 64) {
		address_limit = (nacc_bootstrap_u64)1 << physical_address_bits;
		if (end > address_limit)
			return -ERANGE;
	}

	return 0;
}

static bool nacc_bootstrap_range_contains(
	const struct nacc_bootstrap_range *outer,
	const struct nacc_bootstrap_range *inner)
{
	return outer->base <= inner->base &&
	       inner->base + inner->size <= outer->base + outer->size;
}

static bool nacc_bootstrap_ranges_overlap(
	const struct nacc_bootstrap_range *left,
	const struct nacc_bootstrap_range *right)
{
	return left->base < right->base + right->size &&
	       right->base < left->base + left->size;
}

static bool nacc_bootstrap_virtual_range_valid(
	const struct nacc_bootstrap_range *range)
{
	if (!range->base || !range->size ||
	    ((range->base | range->size) &
	     (NACC_BOOTSTRAP_PAGE_SIZE - 1)) ||
	    range->base >= NACC_BOOTSTRAP_SV39_USER_LIMIT ||
	    range->size > NACC_BOOTSTRAP_SV39_USER_LIMIT - range->base)
		return false;

	return true;
}

static bool nacc_bootstrap_bytes_are_zero(const unsigned char *bytes,
					  size_t count)
{
	size_t index;

	for (index = 0; index < count; index++) {
		if (bytes[index])
			return false;
	}

	return true;
}

int nacc_bootstrap_physical_layout_validate(
	const struct nacc_bootstrap_physical_layout *layout)
{
	const struct nacc_bootstrap_range *roles[7];
	nacc_bootstrap_u64 bitmap_page_count;
	nacc_bootstrap_u64 bitmap_byte_count;
	nacc_bootstrap_u64 bitmap_storage_size;
	size_t index;

	if (!layout || ((uintptr_t)layout &
		       (sizeof(nacc_bootstrap_u64) - 1)))
		return -EINVAL;
	roles[0] = &layout->agent_region;
	roles[1] = &layout->bitmap_target;
	roles[2] = &layout->bitmap_backing;
	roles[3] = &layout->nacc_pool;
	roles[4] = &layout->control_root_l0;
	roles[5] = &layout->mailbox;
	roles[6] = &layout->emergency_stack;
	if (!nacc_bootstrap_range_valid(&layout->arena))
		return -EINVAL;
	for (index = 0; index < sizeof(roles) / sizeof(roles[0]); index++) {
		if (!nacc_bootstrap_range_valid(roles[index]) ||
		    !nacc_bootstrap_range_contains(&layout->arena, roles[index]))
			return -EINVAL;
	}
	if (layout->control_root_l0.size != NACC_BOOTSTRAP_PAGE_SIZE ||
	    !nacc_bootstrap_range_contains(&layout->bitmap_target,
					  &layout->nacc_pool) ||
	    !nacc_bootstrap_range_contains(&layout->nacc_pool,
					  &layout->control_root_l0))
		return -EINVAL;
	if (nacc_bootstrap_ranges_overlap(&layout->agent_region,
					  &layout->bitmap_target) ||
	    nacc_bootstrap_ranges_overlap(&layout->agent_region,
					  &layout->bitmap_backing) ||
	    nacc_bootstrap_ranges_overlap(&layout->agent_region,
					  &layout->mailbox) ||
	    nacc_bootstrap_ranges_overlap(&layout->agent_region,
					  &layout->emergency_stack) ||
	    nacc_bootstrap_ranges_overlap(&layout->bitmap_target,
					  &layout->bitmap_backing) ||
	    nacc_bootstrap_ranges_overlap(&layout->bitmap_target,
					  &layout->mailbox) ||
	    nacc_bootstrap_ranges_overlap(&layout->bitmap_target,
					  &layout->emergency_stack) ||
	    nacc_bootstrap_ranges_overlap(&layout->bitmap_backing,
					  &layout->mailbox) ||
	    nacc_bootstrap_ranges_overlap(&layout->bitmap_backing,
					  &layout->emergency_stack) ||
	    nacc_bootstrap_ranges_overlap(&layout->mailbox,
					  &layout->emergency_stack))
		return -EINVAL;
	bitmap_page_count = layout->bitmap_target.size /
		NACC_BOOTSTRAP_PAGE_SIZE;
	bitmap_byte_count = (bitmap_page_count + 3) / 4;
	bitmap_storage_size =
		(bitmap_byte_count + NACC_BOOTSTRAP_PAGE_SIZE - 1) &
		~(NACC_BOOTSTRAP_PAGE_SIZE - 1);
	if (layout->bitmap_backing.size < bitmap_storage_size)
		return -EINVAL;
	return 0;
}

int nacc_bootstrap_physical_layout_match(
	const struct nacc_bootstrap_descriptor *descriptor,
	size_t descriptor_buffer_size,
	const struct nacc_bootstrap_physical_layout *layout)
{
	const struct nacc_bootstrap_range *descriptor_ranges[7];
	const struct nacc_bootstrap_range *layout_ranges[7];
	size_t index;
	int ret;

	ret = nacc_bootstrap_physical_layout_validate(layout);
	if (ret)
		return ret;
	ret = nacc_bootstrap_validate(descriptor, descriptor_buffer_size);
	if (ret)
		return ret;
	descriptor_ranges[0] = &descriptor->agent_region;
	descriptor_ranges[1] = &descriptor->bitmap_target;
	descriptor_ranges[2] = &descriptor->bitmap_backing;
	descriptor_ranges[3] = &descriptor->nacc_pool;
	descriptor_ranges[4] = &descriptor->control_root_l0;
	descriptor_ranges[5] = &descriptor->mailbox;
	descriptor_ranges[6] = &descriptor->emergency_stack;
	layout_ranges[0] = &layout->agent_region;
	layout_ranges[1] = &layout->bitmap_target;
	layout_ranges[2] = &layout->bitmap_backing;
	layout_ranges[3] = &layout->nacc_pool;
	layout_ranges[4] = &layout->control_root_l0;
	layout_ranges[5] = &layout->mailbox;
	layout_ranges[6] = &layout->emergency_stack;
	for (index = 0; index < sizeof(descriptor_ranges) /
					 sizeof(descriptor_ranges[0]); index++) {
		if (descriptor_ranges[index]->base != layout_ranges[index]->base ||
		    descriptor_ranges[index]->size != layout_ranges[index]->size)
			return -ERANGE;
	}
	return 0;
}

int nacc_bootstrap_validate(const struct nacc_bootstrap_descriptor *descriptor,
				    size_t buffer_size)
{
	const struct nacc_bootstrap_range *ranges[7];
	struct nacc_bootstrap_range virtual_ranges[5];
	nacc_bootstrap_u64 bitmap_page_count;
	nacc_bootstrap_u64 bitmap_byte_count;
	nacc_bootstrap_u64 bitmap_storage_size;
	size_t index;
	size_t other;

	if (!descriptor || buffer_size < NACC_BOOTSTRAP_DESCRIPTOR_V1_0_SIZE)
		return -EINVAL;

	ranges[0] = &descriptor->agent_region;
	ranges[1] = &descriptor->bitmap_target;
	ranges[2] = &descriptor->bitmap_backing;
	ranges[3] = &descriptor->nacc_pool;
	ranges[4] = &descriptor->control_root_l0;
	ranges[5] = &descriptor->mailbox;
	ranges[6] = &descriptor->emergency_stack;

	if (descriptor->magic != NACC_BOOTSTRAP_MAGIC ||
	    descriptor->abi_major != NACC_BOOTSTRAP_ABI_MAJOR)
		return -EOPNOTSUPP;
	if (buffer_size < NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE ||
	    descriptor->struct_size < NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE ||
	    descriptor->struct_size > NACC_BOOTSTRAP_DESCRIPTOR_MAX_SIZE ||
	    descriptor->struct_size > buffer_size)
		return -EINVAL;
	if (descriptor->abi_minor == NACC_BOOTSTRAP_ABI_MINOR &&
	    descriptor->struct_size != NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE)
		return -EINVAL;
	if ((descriptor->feature_bits & ~NACC_BOOTSTRAP_FEATURES_V2) ||
	    (descriptor->feature_bits & NACC_BOOTSTRAP_FEATURES_V2) !=
		    NACC_BOOTSTRAP_FEATURES_V2)
		return -EOPNOTSUPP;
	if (descriptor->reserved0)
		return -EINVAL;
	if ((descriptor->delegation_exception_mask &
	     ~NACC_BOOTSTRAP_DELEGATION_EXCEPTION_MASK) ||
	    (descriptor->delegation_interrupt_mask &
	     ~NACC_BOOTSTRAP_DELEGATION_INTERRUPT_MASK))
		return -EOPNOTSUPP;
	if (!nacc_bootstrap_bytes_are_zero(
		    (const unsigned char *)descriptor->reserved,
		    sizeof(descriptor->reserved)))
		return -EINVAL;
	if (descriptor->struct_size > NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE &&
	    !nacc_bootstrap_bytes_are_zero(
		    (const unsigned char *)descriptor +
				    NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE,
			    descriptor->struct_size - NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE))
		return -EOPNOTSUPP;

	for (index = 0; index < sizeof(ranges) / sizeof(ranges[0]); index++) {
		if (!nacc_bootstrap_range_valid(ranges[index]))
			return -EINVAL;
	}
	if (!descriptor->bootstrap_sequence ||
	    !descriptor->emergency_stack_virtual_top ||
	    descriptor->emergency_stack.size >
		    descriptor->emergency_stack_virtual_top)
		return -EINVAL;
	virtual_ranges[0].base = descriptor->agent_virtual_base;
	virtual_ranges[0].size = descriptor->agent_region.size;
	virtual_ranges[1].base = descriptor->mailbox_virtual_base;
	virtual_ranges[1].size = descriptor->mailbox.size;
	virtual_ranges[2].base =
		descriptor->emergency_stack_virtual_top -
		descriptor->emergency_stack.size;
	virtual_ranges[2].size = descriptor->emergency_stack.size;
	virtual_ranges[3].base = descriptor->nacc_pool_virtual_base;
	virtual_ranges[3].size = descriptor->nacc_pool.size;
	virtual_ranges[4].base = descriptor->bitmap_backing_virtual_base;
	virtual_ranges[4].size = descriptor->bitmap_backing.size;
	for (index = 0; index < sizeof(virtual_ranges) /
					    sizeof(virtual_ranges[0]); index++) {
		if (!nacc_bootstrap_virtual_range_valid(&virtual_ranges[index]))
			return -EINVAL;
		for (other = index + 1;
		     other < sizeof(virtual_ranges) / sizeof(virtual_ranges[0]);
		     other++) {
			if (nacc_bootstrap_ranges_overlap(&virtual_ranges[index],
							  &virtual_ranges[other]))
				return -EINVAL;
		}
	}

	if (descriptor->control_root_l0.size != NACC_BOOTSTRAP_PAGE_SIZE)
		return -EINVAL;
	if (!nacc_bootstrap_range_contains(&descriptor->bitmap_target,
					  &descriptor->nacc_pool) ||
	    !nacc_bootstrap_range_contains(&descriptor->nacc_pool,
					  &descriptor->control_root_l0))
		return -EINVAL;
	/* pool/root 是 target 的受管子区间；其余 physical object 必须互斥。 */
	if (nacc_bootstrap_ranges_overlap(&descriptor->agent_region,
					  &descriptor->bitmap_target) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->agent_region,
					   &descriptor->bitmap_backing) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->agent_region,
					   &descriptor->mailbox) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->agent_region,
					   &descriptor->emergency_stack) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->bitmap_target,
					   &descriptor->bitmap_backing) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->bitmap_target,
					   &descriptor->mailbox) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->bitmap_target,
					   &descriptor->emergency_stack) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->bitmap_backing,
					   &descriptor->mailbox) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->bitmap_backing,
					   &descriptor->emergency_stack) ||
	    nacc_bootstrap_ranges_overlap(&descriptor->mailbox,
					   &descriptor->emergency_stack))
		return -EINVAL;

	/* 每个 4 KiB target page 使用一个 2-bit raw tag。 */
	bitmap_page_count = descriptor->bitmap_target.size /
		NACC_BOOTSTRAP_PAGE_SIZE;
	bitmap_byte_count = (bitmap_page_count + 3) / 4;
	bitmap_storage_size =
		(bitmap_byte_count + NACC_BOOTSTRAP_PAGE_SIZE - 1) &
		~(NACC_BOOTSTRAP_PAGE_SIZE - 1);
	if (descriptor->bitmap_backing.size < bitmap_storage_size)
		return -EINVAL;

	return 0;
}

#ifdef __KERNEL__
static unsigned long nacc_sbi_capabilities __ro_after_init;

static struct nacc_bootstrap_agent_memory_state
	nacc_agent_memory_state __ro_after_init;
static struct nacc_bootstrap_physical_layout
	nacc_physical_layout __ro_after_init;
static bool nacc_physical_layout_ready __ro_after_init;

#ifdef MAX_PHYSMEM_BITS
#define NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS MAX_PHYSMEM_BITS
#else
#define NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS (sizeof(phys_addr_t) * 8)
#endif

_Static_assert(NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS > 0 &&
	       NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS <= 64,
	       "NACC physical address width is invalid");

#define NACC_AGENT_MEMORY_COMPAT "nativecoco,nacc-agent-memory"
#define NACC_LAYOUT_COMPAT "nativecoco,nacc-layout-v1"

static const char *const nacc_layout_properties[] __initconst = {
	"nativecoco,agent-region",
	"nativecoco,bitmap-target",
	"nativecoco,bitmap-backing",
	"nativecoco,nacc-pool",
	"nativecoco,control-root-l0",
	"nativecoco,mailbox",
	"nativecoco,emergency-stack",
};

static __init bool nacc_flat_dt_node_enabled(unsigned long node)
{
	const char *status;
	int length;

	status = of_get_flat_dt_prop(node, "status", &length);
	if (!status)
		return true;
	if (length <= 0 || status[length - 1] != '\0')
		panic("NACC DTB node has malformed status property");
	return (length == sizeof("ok") && !strcmp(status, "ok")) ||
	       (length == sizeof("okay") && !strcmp(status, "okay"));
}

static __init bool nacc_flat_dt_node_effectively_enabled(unsigned long node)
{
	int current_node = node;

	while (current_node >= 0) {
		if (!nacc_flat_dt_node_enabled(current_node))
			return false;
		current_node = fdt_parent_offset(initial_boot_params, current_node);
	}
	return true;
}

static __init int nacc_reserved_memory_parent_validate(int reserved_memory)
{
	const __be32 *cells;
	const void *ranges;
	int length;

	if (reserved_memory < 0 ||
	    fdt_parent_offset(initial_boot_params, reserved_memory) != 0 ||
	    !nacc_flat_dt_node_effectively_enabled(reserved_memory) ||
	    dt_root_addr_cells < 1 || dt_root_addr_cells > 2 ||
	    dt_root_size_cells < 1 || dt_root_size_cells > 2)
		return -EINVAL;
	cells = of_get_flat_dt_prop(reserved_memory, "#address-cells", &length);
	if (!cells || length != sizeof(*cells) ||
	    be32_to_cpup(cells) != dt_root_addr_cells)
		return -EINVAL;
	cells = of_get_flat_dt_prop(reserved_memory, "#size-cells", &length);
	if (!cells || length != sizeof(*cells) ||
	    be32_to_cpup(cells) != dt_root_size_cells)
		return -EINVAL;
	ranges = of_get_flat_dt_prop(reserved_memory, "ranges", &length);
	if (!ranges || length)
		return -EINVAL;
	return 0;
}

static __init int nacc_dt_node_range(unsigned long node, const char *property,
				     struct nacc_bootstrap_range *range)
{
	const __be32 *cells;
	int length;
	int tuple_length;

	if (!range || dt_root_addr_cells < 1 || dt_root_addr_cells > 2 ||
	    dt_root_size_cells < 1 || dt_root_size_cells > 2)
		return -EINVAL;
	tuple_length = (dt_root_addr_cells + dt_root_size_cells) *
			 sizeof(*cells);
	cells = of_get_flat_dt_prop(node, property, &length);
	if (!cells || length != tuple_length)
		return -EINVAL;
	range->base = dt_mem_next_cell(dt_root_addr_cells, &cells);
	range->size = dt_mem_next_cell(dt_root_size_cells, &cells);
	return 0;
}

static __init int nacc_dt_reg_count(unsigned long node, size_t *count)
{
	const __be32 *reg;
	int length;
	int tuple_length;

	if (!count || dt_root_addr_cells < 1 || dt_root_addr_cells > 2 ||
	    dt_root_size_cells < 1 || dt_root_size_cells > 2)
		return -EINVAL;
	tuple_length = (dt_root_addr_cells + dt_root_size_cells) *
			 sizeof(*reg);
	reg = of_get_flat_dt_prop(node, "reg", &length);
	if (!reg || length <= 0 || length % tuple_length)
		return -EINVAL;
	*count = length / tuple_length;
	return 0;
}

static __init int nacc_dt_reg_range(unsigned long node, size_t index,
				    struct nacc_bootstrap_range *range)
{
	const __be32 *reg;
	size_t count;
	size_t tuple_cells;
	int length;

	if (!range || nacc_dt_reg_count(node, &count) || index >= count)
		return -EINVAL;
	reg = of_get_flat_dt_prop(node, "reg", &length);
	if (!reg)
		return -EINVAL;
	tuple_cells = dt_root_addr_cells + dt_root_size_cells;
	reg += index * tuple_cells;
	range->base = dt_mem_next_cell(dt_root_addr_cells, &reg);
	range->size = dt_mem_next_cell(dt_root_size_cells, &reg);
	if (!range->size || range->base > ~(nacc_bootstrap_u64)0 - range->size)
		return -EINVAL;
	return 0;
}

static __init bool nacc_dt_ranges_equal(
	const struct nacc_bootstrap_range *left,
	const struct nacc_bootstrap_range *right)
{
	return left->base == right->base && left->size == right->size;
}

static __init int nacc_layout_validate_ram(
	const struct nacc_bootstrap_physical_layout *layout)
{
	struct nacc_bootstrap_range range;
	const char *device_type;
	size_t containing = 0;
	size_t count;
	size_t index;
	int length;
	int node;
	int root;

	root = of_get_flat_dt_root();
	fdt_for_each_subnode(node, initial_boot_params, root) {
		if (!nacc_flat_dt_node_effectively_enabled(node))
			continue;
		device_type = of_get_flat_dt_prop(node, "device_type", &length);
		if (!device_type || length != sizeof("memory") ||
		    memcmp(device_type, "memory", sizeof("memory")))
			continue;
		if (nacc_dt_reg_count(node, &count))
			return -EINVAL;
		for (index = 0; index < count; index++) {
			if (nacc_dt_reg_range(node, index, &range))
				return -EINVAL;
			if (nacc_bootstrap_range_contains(&range, &layout->arena))
				containing++;
		}
	}
	return containing == 1 ? 0 : -EINVAL;
}

static __init int nacc_layout_validate_reservations(
	unsigned long layout_node, int reserved_memory,
	const struct nacc_bootstrap_physical_layout *layout)
{
	struct nacc_bootstrap_range range;
	u64 address;
	u64 size;
	size_t count;
	size_t index;
	int reservation_count;
	int node;

	fdt_for_each_subnode(node, initial_boot_params, reserved_memory) {
		if (node == layout_node ||
		    !nacc_flat_dt_node_effectively_enabled(node))
			continue;
		if (nacc_dt_reg_count(node, &count))
			return -EINVAL;
		for (index = 0; index < count; index++) {
			if (nacc_dt_reg_range(node, index, &range) ||
			    nacc_bootstrap_ranges_overlap(&range, &layout->arena))
				return -EINVAL;
		}
	}
	reservation_count = fdt_num_mem_rsv(initial_boot_params);
	if (reservation_count < 0)
		return -EINVAL;
	for (index = 0; index < (size_t)reservation_count; index++) {
		if (fdt_get_mem_rsv(initial_boot_params, (int)index, &address,
				    &size))
			return -EINVAL;
		range.base = address;
		range.size = size;
		if (!range.size || range.base > ~(nacc_bootstrap_u64)0 - range.size)
			return -EINVAL;
		if (nacc_dt_ranges_equal(&range, &layout->arena))
			continue;
		if (nacc_bootstrap_ranges_overlap(&range, &layout->arena))
			return -EINVAL;
	}
	return 0;
}

static __init int nacc_agent_memory_node_range(unsigned long node,
						struct nacc_bootstrap_range *range)
{
	int ret;

	ret = nacc_dt_node_range(node, "reg", range);
	if (ret)
		return ret;
	if (of_get_flat_dt_prop(node, "size", NULL))
		return -EINVAL;
	if (!of_get_flat_dt_prop(node, "no-map", NULL) ||
	    of_get_flat_dt_prop(node, "reusable", NULL))
		return -EPERM;

	return nacc_bootstrap_agent_memory_range_validate(range->base,
							 range->size);
}

static __init int nacc_layout_node_parse(
	unsigned long node, struct nacc_bootstrap_physical_layout *layout)
{
	struct nacc_bootstrap_range *roles[7];
	const void *property;
	int child;
	int length;
	size_t index;
	int ret;

	if (!layout)
		return -EINVAL;
	property = of_get_flat_dt_prop(node, "no-map", &length);
	if (!property || length)
		return -EINVAL;
	property = of_get_flat_dt_prop(node, "reusable", &length);
	if (property)
		return -EPERM;
	if (of_get_flat_dt_prop(node, "size", NULL))
		return -EINVAL;
	fdt_for_each_subnode(child, initial_boot_params, node) {
		if (nacc_flat_dt_node_effectively_enabled(child))
			return -EINVAL;
	}

	memset(layout, 0, sizeof(*layout));
	ret = nacc_dt_node_range(node, "reg", &layout->arena);
	if (ret)
		return ret;
	roles[0] = &layout->agent_region;
	roles[1] = &layout->bitmap_target;
	roles[2] = &layout->bitmap_backing;
	roles[3] = &layout->nacc_pool;
	roles[4] = &layout->control_root_l0;
	roles[5] = &layout->mailbox;
	roles[6] = &layout->emergency_stack;
	for (index = 0; index < ARRAY_SIZE(roles); index++) {
		ret = nacc_dt_node_range(node, nacc_layout_properties[index],
					 roles[index]);
		if (ret)
			return ret;
	}
	ret = nacc_bootstrap_physical_layout_validate(layout);
	if (ret)
		return ret;
	ret = nacc_layout_validate_ram(layout);
	if (ret)
		return ret;
	return nacc_layout_validate_reservations(
		node, fdt_parent_offset(initial_boot_params, node), layout);
}

struct nacc_agent_memory_preflight_context {
	int reserved_memory;
	unsigned int agent_matches;
	unsigned int layout_matches;
};

static __init int nacc_agent_memory_preflight_node(unsigned long node,
						   const char *uname, int depth,
						   void *data)
{
	struct nacc_agent_memory_preflight_context *context = data;
	struct nacc_bootstrap_physical_layout layout;
	struct nacc_bootstrap_range range;
	bool is_agent;
	bool is_layout;
	int ret;

	is_agent = of_flat_dt_is_compatible(node, NACC_AGENT_MEMORY_COMPAT);
	is_layout = of_flat_dt_is_compatible(node, NACC_LAYOUT_COMPAT);
	if ((!is_agent && !is_layout) ||
	    !nacc_flat_dt_node_effectively_enabled(node))
		return 0;
	if (fdt_parent_offset(initial_boot_params, node) !=
	    context->reserved_memory)
		panic("NACC node %s is not a direct /reserved-memory child", uname);
	ret = nacc_reserved_memory_parent_validate(context->reserved_memory);
	if (ret)
		panic("NACC /reserved-memory parent is invalid (%d)", ret);

	if (is_agent) {
		if (++context->agent_matches > 1)
			panic("NACC agent memory has duplicate enabled compatible nodes");
		ret = nacc_agent_memory_node_range(node, &range);
		if (ret)
			panic("NACC agent memory node %s is invalid (%d)", uname,
			      ret);
	}
	if (is_layout) {
		if (++context->layout_matches > 1)
			panic("NACC layout has duplicate enabled compatible nodes");
		ret = nacc_layout_node_parse(node, &layout);
		if (ret)
			panic("NACC layout node %s is invalid (%d)", uname, ret);
	}
	if (is_agent && is_layout)
		panic("NACC node %s mixes legacy and v1 compatible strings", uname);
	(void)depth;
	return 0;
}

void __init nacc_bootstrap_memory_preflight(void)
{
	struct nacc_agent_memory_preflight_context context = {};

	if (!initial_boot_params)
		return;
	context.reserved_memory = of_get_flat_dt_subnode_by_name(
		of_get_flat_dt_root(), "reserved-memory");
	if (of_scan_flat_dt(nacc_agent_memory_preflight_node, &context))
		panic("NACC DTB preflight failed");
	if (context.agent_matches && context.layout_matches)
		panic("NACC legacy agent memory and v1 layout cannot coexist");
}

static int __init nacc_agent_memory_reserved_mem_init(struct reserved_mem *rmem)
{
	struct nacc_bootstrap_agent_memory_state candidate = {};
	int ret;

	if (nacc_agent_memory_state.matches || nacc_physical_layout_ready)
		panic("NACC agent memory has duplicate enabled compatible nodes");
	if (!rmem || !rmem->fdt_node)
		panic("NACC agent memory callback received an invalid node");

	ret = nacc_agent_memory_node_range(rmem->fdt_node,
						&candidate.range);
	if (ret)
		panic("NACC agent memory callback rejected node %s (%d)",
		      rmem->name, ret);
	candidate.matches = 1;
	ret = nacc_bootstrap_agent_memory_state_validate(&candidate, true,
							 NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS);
	if (ret)
		panic("NACC agent memory callback produced invalid snapshot (%d)",
		      ret);
	nacc_agent_memory_state = candidate;
	return 0;
}

RESERVEDMEM_OF_DECLARE(nacc_agent_memory, NACC_AGENT_MEMORY_COMPAT,
			       nacc_agent_memory_reserved_mem_init);

static int __init nacc_layout_reserved_mem_init(struct reserved_mem *rmem)
{
	struct nacc_bootstrap_agent_memory_state agent_candidate = {};
	struct nacc_bootstrap_physical_layout layout_candidate;
	nacc_bootstrap_u64 address_limit;
	int ret;

	if (nacc_physical_layout_ready || nacc_agent_memory_state.matches)
		panic("NACC layout has duplicate or conflicting authority");
	if (!rmem || !rmem->fdt_node)
		panic("NACC layout callback received an invalid node");
	ret = nacc_layout_node_parse(rmem->fdt_node, &layout_candidate);
	if (ret)
		panic("NACC layout callback rejected node %s (%d)", rmem->name,
		      ret);
	if (rmem->base != layout_candidate.arena.base ||
	    rmem->size != layout_candidate.arena.size)
		panic("NACC layout reserved-memory range changed during parsing");
	address_limit = ~(nacc_bootstrap_u64)0 >>
		(64 - NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS);
	if (layout_candidate.arena.base + layout_candidate.arena.size - 1 >
	    address_limit)
		panic("NACC layout exceeds the physical address width");
	agent_candidate.matches = 1;
	agent_candidate.range = layout_candidate.agent_region;
	ret = nacc_bootstrap_agent_memory_state_validate(
		&agent_candidate, true, NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS);
	if (ret)
		panic("NACC layout produced invalid Agent snapshot (%d)", ret);

	nacc_physical_layout = layout_candidate;
	nacc_agent_memory_state = agent_candidate;
	nacc_physical_layout_ready = true;
	return 0;
}

RESERVEDMEM_OF_DECLARE(nacc_layout, NACC_LAYOUT_COMPAT,
			       nacc_layout_reserved_mem_init);

bool nacc_bootstrap_agent_memory_available(void)
{
	return nacc_agent_memory_state.matches == 1;
}

const struct nacc_bootstrap_range *nacc_bootstrap_agent_memory_snapshot(void)
{
	if (!nacc_bootstrap_agent_memory_available())
		panic("NACC agent memory snapshot is unavailable");
	return &nacc_agent_memory_state.range;
}

bool nacc_bootstrap_physical_layout_available(void)
{
	return nacc_physical_layout_ready;
}

const struct nacc_bootstrap_physical_layout *
nacc_bootstrap_physical_layout_snapshot(void)
{
	if (!nacc_bootstrap_physical_layout_available() ||
	    nacc_bootstrap_physical_layout_validate(&nacc_physical_layout))
		panic("NACC physical layout snapshot is unavailable");
	return &nacc_physical_layout;
}

static void __init nacc_bootstrap_require_physical_layout(void)
{
	int ret;

	if (!nacc_physical_layout_ready)
		panic("NACC SBI capability requires a physical layout snapshot");
	ret = nacc_bootstrap_physical_layout_validate(&nacc_physical_layout);
	if (ret)
		panic("NACC SBI capability requires a valid physical layout (%d)",
		      ret);
	ret = nacc_bootstrap_agent_memory_state_validate(
		&nacc_agent_memory_state, true,
		NACC_BOOTSTRAP_PHYSICAL_ADDRESS_BITS);
	if (ret)
		panic("NACC SBI capability requires a valid agent memory snapshot (%d)",
		      ret);
}

unsigned long nacc_bootstrap_sbi_capabilities(void)
{
	return nacc_sbi_capabilities;
}

void __init nacc_bootstrap_sbi_probe(void)
{
	struct sbiret result;

	result = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_PROBE, 0, 0, 0, 0, 0,
			  0);
	if (result.error) {
		/* 缺失 extension 不是全系统 fatal；后续入口保持 disabled。 */
		pr_info("NACC SBI extension unavailable (error %ld)\n",
			result.error);
		return;
	}

	nacc_sbi_capabilities = result.value;
	if (nacc_bootstrap_capabilities_allow_bootstrap(result.value))
		nacc_bootstrap_require_physical_layout();
	else
		pr_info("NACC SBI bootstrap capability unavailable (caps=0x%lx)\n",
			result.value);
}
#endif
