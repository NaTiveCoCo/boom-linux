// SPDX-License-Identifier: GPL-2.0-only
/* NACC initial control ROOT_L0 的 RISC-V early-boot adapter。 */

#include <linux/cache.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>

#include <asm/csr.h>
#include <asm/early_ioremap.h>
#include <asm/nacc_agent_image.h>
#include <asm/nacc_bootstrap.h>
#include <asm/nacc_root.h>
#include <asm/pgtable.h>

#define NACC_ROOT_SATP_MODE_MASK (0xfULL << SATP_MODE_SHIFT)

struct nacc_root_early_backend {
	const struct nacc_bootstrap_physical_layout *layout;
};

static struct nacc_bootstrap_descriptor nacc_runtime_descriptor
	__ro_after_init;
static struct nacc_root_build_result nacc_runtime_root __ro_after_init;
static bool nacc_runtime_root_ready __ro_after_init;
static u64 nacc_kernel_root_high[256] __initdata;

static bool __init nacc_root_early_page_valid(
	const struct nacc_root_early_backend *backend, u64 physical_address)
{
	const struct nacc_bootstrap_range *pool = &backend->layout->nacc_pool;

	return !(physical_address & (PAGE_SIZE - 1)) &&
	       physical_address >= pool->base &&
	       physical_address <= pool->base + pool->size - PAGE_SIZE;
}

static int __init nacc_root_early_zero_page(u64 physical_address, void *opaque)
{
	struct nacc_root_early_backend *backend = opaque;
	void *alias;

	if (!nacc_root_early_page_valid(backend, physical_address))
		return -ERANGE;
	alias = early_memremap(physical_address, PAGE_SIZE);
	if (!alias)
		return -ENOMEM;
	memset(alias, 0, PAGE_SIZE);
	early_memunmap(alias, PAGE_SIZE);
	return 0;
}

static int __init nacc_root_early_read_pte(u64 physical_address, u32 index,
				   u64 *value, void *opaque)
{
	struct nacc_root_early_backend *backend = opaque;
	u64 *alias;

	if (!value || index >= NACC_ROOT_PTE_COUNT ||
	    !nacc_root_early_page_valid(backend, physical_address))
		return -EINVAL;
	alias = early_memremap(physical_address, PAGE_SIZE);
	if (!alias)
		return -ENOMEM;
	*value = READ_ONCE(alias[index]);
	early_memunmap(alias, PAGE_SIZE);
	return 0;
}

static int __init nacc_root_early_write_pte(u64 physical_address, u32 index,
				    u64 value, void *opaque)
{
	struct nacc_root_early_backend *backend = opaque;
	u64 *alias;

	if (index >= NACC_ROOT_PTE_COUNT ||
	    !nacc_root_early_page_valid(backend, physical_address))
		return -EINVAL;
	alias = early_memremap(physical_address, PAGE_SIZE);
	if (!alias)
		return -ENOMEM;
	WRITE_ONCE(alias[index], value);
	early_memunmap(alias, PAGE_SIZE);
	return 0;
}

bool nacc_root_is_ready(void)
{
	return nacc_runtime_root_ready;
}

const struct nacc_bootstrap_descriptor *nacc_root_descriptor_snapshot(void)
{
	if (!nacc_root_is_ready() ||
	    nacc_bootstrap_validate(&nacc_runtime_descriptor,
				    sizeof(nacc_runtime_descriptor)))
		panic("NACC runtime descriptor is unavailable");
	return &nacc_runtime_descriptor;
}

void __init nacc_root_prepare(void)
{
	const struct nacc_bootstrap_physical_layout *layout;
	const struct nacc_agent_image_metadata *image;
	struct nacc_bootstrap_descriptor descriptor;
	struct nacc_root_build_result result = {};
	struct nacc_root_early_backend early_backend;
	struct nacc_root_backend backend;
	u64 active_satp;
	size_t index;
	int ret;

	if (!nacc_bootstrap_capabilities_allow_bootstrap(
		    nacc_bootstrap_sbi_capabilities()))
		return;
	if (nacc_runtime_root_ready)
		panic("NACC control root preparation repeated");
	active_satp = csr_read(CSR_SATP);
	if (satp_mode != SATP_MODE_39 || pgtable_l4_enabled ||
	    (active_satp & NACC_ROOT_SATP_MODE_MASK) != SATP_MODE_39)
		panic("NACC control root requires active Sv39");

	layout = nacc_bootstrap_physical_layout_snapshot();
	image = nacc_agent_image_metadata_snapshot();
	ret = nacc_bootstrap_descriptor_build(&descriptor, layout, 1);
	if (ret)
		panic("NACC runtime descriptor build failed (%d)", ret);
	for (index = 0; index < ARRAY_SIZE(nacc_kernel_root_high); index++)
		nacc_kernel_root_high[index] = pgd_val(READ_ONCE(
			init_mm.pgd[NACC_ROOT_KERNEL_HALF_INDEX + index]));

	early_backend.layout = layout;
	backend = (struct nacc_root_backend) {
		.zero_page = nacc_root_early_zero_page,
		.read_pte = nacc_root_early_read_pte,
		.write_pte = nacc_root_early_write_pte,
		.opaque = &early_backend,
	};
	ret = nacc_root_build(&result, layout, &descriptor, image,
			      nacc_kernel_root_high, &backend);
	if (ret)
		panic("NACC control root build failed (%d)", ret);
	if (result.root_physical_address != layout->control_root_l0.base ||
	    !result.lower_ptp_count || !result.leaf_count)
		panic("NACC control root result invariant failed");

	/* 后续 activation 与 M audit 只能观察完整的 control root。 */
	mb();
	nacc_runtime_descriptor = descriptor;
	nacc_runtime_root = result;
	nacc_runtime_root_ready = true;
	pr_info("NACC Sv39 control root prepared (%llu lower PTP, %llu leaves)\n",
		(unsigned long long)result.lower_ptp_count,
		(unsigned long long)result.leaf_count);
}
