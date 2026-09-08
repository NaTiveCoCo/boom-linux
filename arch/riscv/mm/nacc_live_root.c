// SPDX-License-Identifier: GPL-2.0-only
/* NACC single-mm live ROOT_L0 的 runtime no-map pool adapter。 */

#include <linux/errno.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/nacc_agent_image.h>
#include <asm/nacc_bootstrap.h>
#include <asm/nacc_live_root.h>
#include <asm/nacc_root.h>
#include <asm/pgtable.h>

enum nacc_live_root_state {
	NACC_LIVE_ROOT_RESERVED = 1,
	NACC_LIVE_ROOT_BUILT,
	NACC_LIVE_ROOT_PUBLISHED,
};

struct nacc_live_root_handle {
	struct nacc_bootstrap_physical_layout physical_layout;
	struct nacc_root_build_result control_root;
	struct nacc_live_root_layout_result layout;
	struct nacc_root_build_result root;
	nacc_bootstrap_u64 payload_page_counts[NACC_ROOT_MAX_USER_MAPPINGS];
	nacc_bootstrap_u64 kernel_high[NACC_ROOT_KERNEL_HALF_INDEX];
	struct nacc_root_user_mapping user_mappings[NACC_ROOT_MAX_USER_MAPPINGS];
	size_t payload_mapping_count;
	enum nacc_live_root_state state;
};

static DEFINE_MUTEX(nacc_live_root_lock);
static struct nacc_live_root_handle *nacc_live_root_owner;

static bool nacc_live_root_ptp_page_valid(const struct nacc_live_root_handle *handle,
					  nacc_bootstrap_u64 physical_address)
{
	return !(physical_address & (NACC_ROOT_PAGE_SIZE - 1)) &&
	       physical_address >= handle->layout.ptp_base &&
	       physical_address <= handle->layout.ptp_base +
		       handle->layout.ptp_size - NACC_ROOT_PAGE_SIZE;
}

static void *nacc_live_root_map_page(nacc_bootstrap_u64 physical_address)
{
	void __iomem *alias;

	/* RISC-V memremap(WB) 可能为 NOMAP PFN 返回无效的 direct-map alias。 */
	alias = ioremap_prot(physical_address, NACC_ROOT_PAGE_SIZE, _PAGE_KERNEL);
	return (__force void *)alias;
}

static void nacc_live_root_unmap_page(void *alias)
{
	iounmap((__force void __iomem *)alias);
}

static int nacc_live_root_zero_page(nacc_bootstrap_u64 physical_address,
				    void *opaque)
{
	struct nacc_live_root_handle *handle = opaque;
	void *alias;

	if (!nacc_live_root_ptp_page_valid(handle, physical_address))
		return -ERANGE;
	alias = nacc_live_root_map_page(physical_address);
	if (!alias)
		return -ENOMEM;
	memset(alias, 0, NACC_ROOT_PAGE_SIZE);
	nacc_live_root_unmap_page(alias);
	return 0;
}

static int nacc_live_root_read_pte(nacc_bootstrap_u64 physical_address,
				   nacc_bootstrap_u32 index,
				   nacc_bootstrap_u64 *value, void *opaque)
{
	struct nacc_live_root_handle *handle = opaque;
	nacc_bootstrap_u64 *alias;

	if (!value || index >= NACC_ROOT_PTE_COUNT ||
	    !nacc_live_root_ptp_page_valid(handle, physical_address))
		return -EINVAL;
	alias = nacc_live_root_map_page(physical_address);
	if (!alias)
		return -ENOMEM;
	*value = READ_ONCE(alias[index]);
	nacc_live_root_unmap_page(alias);
	return 0;
}

static int nacc_live_root_write_pte(nacc_bootstrap_u64 physical_address,
				    nacc_bootstrap_u32 index,
				    nacc_bootstrap_u64 value, void *opaque)
{
	struct nacc_live_root_handle *handle = opaque;
	nacc_bootstrap_u64 *alias;

	if (index >= NACC_ROOT_PTE_COUNT ||
	    !nacc_live_root_ptp_page_valid(handle, physical_address))
		return -EINVAL;
	alias = nacc_live_root_map_page(physical_address);
	if (!alias)
		return -ENOMEM;
	WRITE_ONCE(alias[index], value);
	nacc_live_root_unmap_page(alias);
	return 0;
}

static int nacc_live_root_zero_reservation(const struct nacc_live_root_handle *handle)
{
	nacc_bootstrap_u64 physical_address;
	void *alias;

	for (physical_address = handle->layout.ptp_base;
	     physical_address < handle->layout.allocation_end;
	     physical_address += NACC_ROOT_PAGE_SIZE) {
		alias = nacc_live_root_map_page(physical_address);
		if (!alias)
			return -ENOMEM;
		memset(alias, 0, NACC_ROOT_PAGE_SIZE);
		nacc_live_root_unmap_page(alias);
	}
	return 0;
}

static void nacc_live_root_snapshot_kernel_high(nacc_bootstrap_u64 *high)
{
	size_t index;

	preempt_disable();
	for (index = 0; index < NACC_ROOT_KERNEL_HALF_INDEX; index++) {
		pgd_t *entry =
			&init_mm.pgd[NACC_ROOT_KERNEL_HALF_INDEX + index];

		high[index] = pgd_val(READ_ONCE(*entry));
	}
	preempt_enable();
}

int nacc_live_root_reserve(struct nacc_live_root_handle **handle,
			   const struct nacc_bootstrap_physical_layout *layout,
			   const struct nacc_root_build_result *control_root,
			   const struct nacc_live_root_layout_request *request)
{
	struct nacc_live_root_handle *candidate;
	struct nacc_live_root_layout_result plan;
	size_t index;
	int ret;

	if (!handle || *handle)
		return -EINVAL;
	candidate = kzalloc(sizeof(*candidate), GFP_KERNEL);
	if (!candidate)
		return -ENOMEM;
	ret = nacc_live_root_layout_plan(&plan, layout, control_root, request);
	if (ret)
		goto out_free;
	candidate->physical_layout = *layout;
	candidate->control_root = *control_root;
	candidate->layout = plan;
	candidate->payload_mapping_count = request->payload_mapping_count;
	for (index = 0; index < request->payload_mapping_count; index++)
		candidate->payload_page_counts[index] =
			request->payload_page_counts[index];
	candidate->state = NACC_LIVE_ROOT_RESERVED;

	mutex_lock(&nacc_live_root_lock);
	if (nacc_live_root_owner) {
		ret = -EBUSY;
		goto out_unlock;
	}
	ret = nacc_live_root_zero_reservation(candidate);
	if (ret)
		goto out_unlock;
	nacc_live_root_owner = candidate;
	*handle = candidate;
	mutex_unlock(&nacc_live_root_lock);
	return 0;

out_unlock:
	mutex_unlock(&nacc_live_root_lock);
out_free:
	kfree(candidate);
	return ret;
}

int nacc_live_root_build(struct nacc_live_root_handle *handle,
			 const struct nacc_bootstrap_descriptor *descriptor,
			 const struct nacc_agent_image_metadata *image,
			 const struct nacc_live_root_mapping_request *mappings,
			 size_t mapping_count)
{
	struct nacc_root_build_result result = {};
	struct nacc_root_live_config config;
	struct nacc_root_backend backend;
	size_t index;
	int scrub_ret;
	int ret;

	if (!handle || !descriptor || !image || !mappings ||
	    mapping_count != handle->payload_mapping_count)
		return -EINVAL;
	mutex_lock(&nacc_live_root_lock);
	if (nacc_live_root_owner != handle ||
	    handle->state != NACC_LIVE_ROOT_RESERVED)
		panic("NACC live root build found invalid ownership");
	for (index = 0; index < mapping_count; index++) {
		if (mappings[index].page_count !=
		    handle->payload_page_counts[index]) {
			ret = -EINVAL;
			goto out_scrub;
		}
		handle->user_mappings[index] = (struct nacc_root_user_mapping) {
			.virtual_base = mappings[index].virtual_base,
			.physical_base = handle->layout.payload_bases[index],
			.page_count = mappings[index].page_count,
			.permissions = mappings[index].permissions,
		};
	}
	nacc_live_root_snapshot_kernel_high(handle->kernel_high);
	config = (struct nacc_root_live_config) {
		.root_physical_address = handle->layout.ptp_base,
		.ptp_pool_base = handle->layout.ptp_base,
		.ptp_pool_size = handle->layout.ptp_size,
		.control_root = &handle->control_root,
		.user_mappings = handle->user_mappings,
		.user_mapping_count = mapping_count,
	};
	backend = (struct nacc_root_backend) {
		.zero_page = nacc_live_root_zero_page,
		.read_pte = nacc_live_root_read_pte,
		.write_pte = nacc_live_root_write_pte,
		.opaque = handle,
	};
	ret = nacc_root_build_live(&result, &handle->physical_layout,
				   descriptor, image, handle->kernel_high, &config,
				   &backend);
	if (ret)
		goto out_scrub;
	if (result.lower_ptp_count >=
		    handle->layout.ptp_size / NACC_ROOT_PAGE_SIZE ||
	    result.root_physical_address != handle->layout.ptp_base ||
	    result.next_pool_physical_address != handle->layout.ptp_base +
		    (result.lower_ptp_count + 1) * NACC_ROOT_PAGE_SIZE ||
	    result.next_pool_physical_address >
		    handle->layout.ptp_base + handle->layout.ptp_size)
		panic("NACC live root builder returned an invalid result");
	handle->root = result;
	/* 完整 root result 与 PTE 写入必须先于 BUILT 对 owner 可见。 */
	smp_store_release(&handle->state, NACC_LIVE_ROOT_BUILT);
	mutex_unlock(&nacc_live_root_lock);
	return 0;

out_scrub:
	scrub_ret = nacc_live_root_zero_reservation(handle);
	if (scrub_ret)
		panic("NACC live root cleanup failed (%d)", scrub_ret);
	mutex_unlock(&nacc_live_root_lock);
	return ret;
}

const struct nacc_live_root_layout_result *
nacc_live_root_layout_snapshot(const struct nacc_live_root_handle *handle)
{
	if (!handle || handle != READ_ONCE(nacc_live_root_owner))
		panic("NACC live root layout snapshot found invalid ownership");
	return &handle->layout;
}

const struct nacc_root_build_result *
nacc_live_root_result_snapshot(const struct nacc_live_root_handle *handle)
{
	enum nacc_live_root_state state;

	/* 与 build 发布 BUILT 的 release store 配对。 */
	state = handle ? smp_load_acquire(&handle->state) : 0;
	if (!handle || handle != READ_ONCE(nacc_live_root_owner) ||
	    (state != NACC_LIVE_ROOT_BUILT &&
	     state != NACC_LIVE_ROOT_PUBLISHED))
		panic("NACC live root result snapshot found invalid state");
	return &handle->root;
}

void nacc_live_root_mark_published(struct nacc_live_root_handle *handle)
{
	if (!handle)
		panic("NACC live root publish received a NULL handle");
	mutex_lock(&nacc_live_root_lock);
	if (nacc_live_root_owner != handle ||
	    handle->state != NACC_LIVE_ROOT_BUILT)
		panic("NACC live root publish found invalid ownership");
	/* caller 的 root 安装与 SFENCE.VMA 必须先于 PUBLISHED 可见。 */
	smp_store_release(&handle->state, NACC_LIVE_ROOT_PUBLISHED);
	mutex_unlock(&nacc_live_root_lock);
}

void nacc_live_root_release_unpublished(struct nacc_live_root_handle *handle)
{
	int ret;

	if (!handle)
		panic("NACC live root release received a NULL handle");
	mutex_lock(&nacc_live_root_lock);
	if (nacc_live_root_owner != handle ||
	    (handle->state != NACC_LIVE_ROOT_RESERVED &&
	     handle->state != NACC_LIVE_ROOT_BUILT))
		panic("NACC live root release found invalid ownership");
	ret = nacc_live_root_zero_reservation(handle);
	if (ret)
		panic("NACC live root release scrub failed (%d)", ret);
	nacc_live_root_owner = NULL;
	mutex_unlock(&nacc_live_root_lock);
	memzero_explicit(handle, sizeof(*handle));
	kfree(handle);
}
