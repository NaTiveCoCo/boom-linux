// SPDX-License-Identifier: GPL-2.0-only
/* NACC initial Sv39 control ROOT_L0 pure builder contract test。 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../arch/riscv/include/asm/nacc_root.h"
#include "../kselftest.h"

struct fake_page_store {
	uint64_t base;
	uint64_t size;
	unsigned char *bytes;
	unsigned int writes;
	unsigned int fail_write;
};

static int fake_page_offset(struct fake_page_store *store, uint64_t address,
			    uint64_t *offset)
{
	if ((address & (NACC_ROOT_PAGE_SIZE - 1)) || address < store->base ||
	    address > store->base + store->size - NACC_ROOT_PAGE_SIZE)
		return -ERANGE;
	*offset = address - store->base;
	return 0;
}

static int fake_zero_page(uint64_t address, void *opaque)
{
	struct fake_page_store *store = opaque;
	uint64_t offset;
	int ret;

	ret = fake_page_offset(store, address, &offset);
	if (ret)
		return ret;
	memset(store->bytes + offset, 0, NACC_ROOT_PAGE_SIZE);
	return 0;
}

static int fake_read_pte(uint64_t address, uint32_t index, uint64_t *value,
			 void *opaque)
{
	struct fake_page_store *store = opaque;
	uint64_t offset;
	int ret;

	if (!value || index >= NACC_ROOT_PTE_COUNT)
		return -EINVAL;
	ret = fake_page_offset(store, address, &offset);
	if (ret)
		return ret;
	memcpy(value, store->bytes + offset + index * sizeof(*value),
	       sizeof(*value));
	return 0;
}

static int fake_write_pte(uint64_t address, uint32_t index, uint64_t value,
			  void *opaque)
{
	struct fake_page_store *store = opaque;
	uint64_t offset;
	int ret;

	if (index >= NACC_ROOT_PTE_COUNT)
		return -EINVAL;
	if (store->fail_write && ++store->writes == store->fail_write)
		return -EIO;
	ret = fake_page_offset(store, address, &offset);
	if (ret)
		return ret;
	memcpy(store->bytes + offset + index * sizeof(value), &value,
	       sizeof(value));
	return 0;
}

static void initialize_layout(struct nacc_bootstrap_physical_layout *layout)
{
	memset(layout, 0, sizeof(*layout));
	layout->arena.base = UINT64_C(0x08000000);
	layout->arena.size = UINT64_C(0x50000000);
	layout->agent_region.base = UINT64_C(0x10000000);
	layout->agent_region.size = UINT64_C(0x01000000);
	layout->bitmap_target.base = UINT64_C(0x20000000);
	layout->bitmap_target.size = 64 * NACC_ROOT_PAGE_SIZE;
	layout->nacc_pool.base = layout->bitmap_target.base +
		32 * NACC_ROOT_PAGE_SIZE;
	layout->nacc_pool.size = 32 * NACC_ROOT_PAGE_SIZE;
	layout->control_root_l0.base = layout->nacc_pool.base +
		5 * NACC_ROOT_PAGE_SIZE;
	layout->control_root_l0.size = NACC_ROOT_PAGE_SIZE;
	layout->bitmap_backing.base = UINT64_C(0x30000000);
	layout->bitmap_backing.size = NACC_ROOT_PAGE_SIZE;
	layout->mailbox.base = UINT64_C(0x40000000);
	layout->mailbox.size = NACC_ROOT_PAGE_SIZE;
	layout->emergency_stack.base = UINT64_C(0x50000000);
	layout->emergency_stack.size = NACC_ROOT_PAGE_SIZE;
}

static void initialize_image(struct nacc_agent_image_metadata *image)
{
	memset(image, 0, sizeof(*image));
	image->magic = NACC_LINUX_AGENT_IMAGE_MAGIC;
	image->abi_major = NACC_LINUX_AGENT_IMAGE_ABI_MAJOR;
	image->abi_minor = NACC_LINUX_AGENT_IMAGE_ABI_MINOR;
	image->descriptor_size = NACC_LINUX_AGENT_IMAGE_DESCRIPTOR_SIZE;
	image->artifact_size = UINT64_C(0x9000);
	image->required_features = NACC_LINUX_AGENT_IMAGE_REQUIRED_FEATURES;
	image->bss_size = UINT64_C(0x2ff8);
	image->stack_size = NACC_ROOT_PAGE_SIZE;
	image->stack_alignment = NACC_ROOT_PAGE_SIZE;
	image->segments[0] = (struct nacc_agent_image_segment) {
		.file_offset = UINT64_C(0x1000),
		.file_size = UINT64_C(0x1040),
		.memory_size = UINT64_C(0x1040),
		.flags = NACC_LINUX_AGENT_IMAGE_RX_FLAGS,
		.alignment = NACC_ROOT_PAGE_SIZE,
	};
	image->segments[1] = (struct nacc_agent_image_segment) {
		.file_offset = UINT64_C(0x3000),
		.virtual_offset = UINT64_C(0x2000),
		.file_size = 8,
		.memory_size = UINT64_C(0x3000),
		.flags = NACC_LINUX_AGENT_IMAGE_RW_FLAGS,
		.alignment = NACC_ROOT_PAGE_SIZE,
	};
	image->stack_top_offset = UINT64_C(0x5000);
	image->boot_context_offset = UINT64_C(0x3000);
	image->bootstrap_handshake_offset = UINT64_C(0x124);
}

static int walk_leaf(struct fake_page_store *store, uint64_t root,
		     uint64_t virtual_address, uint64_t *pte)
{
	uint64_t table = root;
	uint64_t value;
	uint32_t level;
	uint32_t index;
	int ret;

	for (level = 3; level > 0; level--) {
		index = (virtual_address >> (12 + (level - 1) * 9)) & 511;
		ret = fake_read_pte(table, index, &value, store);
		if (ret || !value)
			return ret ? ret : -ENOENT;
		if (level == 1) {
			*pte = value;
			return 0;
		}
		if ((value & 0x3ff) != NACC_ROOT_PTE_VALID)
			return -EINVAL;
		table = (value >> 10) << 12;
	}
	return -EINVAL;
}

static uint64_t pte_physical_address(uint64_t pte)
{
	return (pte >> 10) << 12;
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
	struct nacc_bootstrap_descriptor descriptor;
	struct nacc_agent_image_metadata image;
	struct nacc_root_build_result result = {};
	struct nacc_root_build_result control_result;
	struct nacc_root_build_result sentinel;
	struct nacc_root_backend backend;
	struct nacc_root_live_config live_config;
	struct nacc_root_user_mapping mappings[2];
	struct fake_page_store store;
	uint64_t high[256];
	uint64_t pte;
	size_t index;
	int ret;
	int plan = 36;

	ksft_print_header();
	ksft_set_plan(plan);
	initialize_layout(&layout);
	initialize_image(&image);
	ret = nacc_bootstrap_descriptor_build(&descriptor, &layout, 1);
	if (ret)
		ksft_exit_fail_msg("fixture descriptor failed: %d\n", ret);
	store = (struct fake_page_store) {
		.base = layout.nacc_pool.base,
		.size = layout.nacc_pool.size,
		.bytes = malloc(layout.nacc_pool.size),
	};
	if (!store.bytes)
		ksft_exit_fail_msg("cannot allocate fake page store\n");
	memset(store.bytes, 0xa5, store.size);
	backend = (struct nacc_root_backend) {
		.zero_page = fake_zero_page,
		.read_pte = fake_read_pte,
		.write_pte = fake_write_pte,
		.opaque = &store,
	};
	for (index = 0; index < 256; index++)
		high[index] = UINT64_C(0x8000000000000000) | index;

	ret = nacc_root_build(&result, &layout, &descriptor, &image, high,
			      &backend);
	report_contract(ret == 0, "canonical control root is built");
	report_contract(result.root_physical_address ==
			layout.control_root_l0.base,
			"result publishes the declared root");
	report_contract(result.lower_ptp_count == 8,
			"builder allocates the exact lower PTP count");
	report_contract(result.next_pool_physical_address ==
			layout.nacc_pool.base + 9 * NACC_ROOT_PAGE_SIZE,
			"allocation cursor accounts for the skipped root page");
	report_contract(result.leaf_count == 39,
			"builder emits the exact initial leaf count");
	ret = fake_read_pte(result.root_physical_address, 256, &pte, &store);
	report_contract(!ret && pte == high[0],
			"kernel root high half is copied raw");
	ret = fake_read_pte(result.root_physical_address, 255, &pte, &store);
	report_contract(!ret && !pte, "unused user-half root entry stays zero");
	ret = fake_read_pte(result.root_physical_address, 12, &pte, &store);
	report_contract(!ret && !pte, "emergency workspace is not mapped");
	ret = walk_leaf(&store, result.root_physical_address,
			descriptor.agent_virtual_base, &pte);
	report_contract(!ret && pte_physical_address(pte) ==
			layout.agent_region.base &&
			(pte & 0xff) == (NACC_ROOT_PTE_VALID |
			NACC_ROOT_PTE_READ | NACC_ROOT_PTE_EXECUTE |
			NACC_ROOT_PTE_ACCESSED),
			"Agent RX leaf has exact PA and permissions");
	ret = walk_leaf(&store, result.root_physical_address,
			descriptor.agent_virtual_base + NACC_ROOT_PAGE_SIZE,
			&pte);
	report_contract(!ret && pte_physical_address(pte) ==
			layout.agent_region.base + NACC_ROOT_PAGE_SIZE,
			"non-page-aligned RX memory is rounded up");
	ret = walk_leaf(&store, result.root_physical_address,
			descriptor.agent_virtual_base +
			image.segments[1].virtual_offset, &pte);
	report_contract(!ret && (pte & 0xff) ==
			(NACC_ROOT_PTE_VALID | NACC_ROOT_PTE_READ |
			 NACC_ROOT_PTE_WRITE | NACC_ROOT_PTE_ACCESSED |
			 NACC_ROOT_PTE_DIRTY),
			"Agent RW leaf has exact writable permissions");
	ret = walk_leaf(&store, result.root_physical_address,
			descriptor.nacc_pool_virtual_base +
			(layout.control_root_l0.base - layout.nacc_pool.base),
			&pte);
	report_contract(!ret && pte_physical_address(pte) ==
			layout.control_root_l0.base,
			"pool management mapping aliases the declared root");
	report_contract(!(pte & (NACC_ROOT_PTE_USER | NACC_ROOT_PTE_GLOBAL)),
			"initial leaves never set U or G");
	ret = walk_leaf(&store, result.root_physical_address,
			descriptor.mailbox_virtual_base, &pte);
	report_contract(!ret && pte_physical_address(pte) ==
			layout.mailbox.base &&
			(pte & 0xff) == (NACC_ROOT_PTE_VALID |
			 NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE |
			 NACC_ROOT_PTE_ACCESSED | NACC_ROOT_PTE_DIRTY),
			"mailbox leaf has exact PA and writable permissions");
	ret = walk_leaf(&store, result.root_physical_address,
			descriptor.bitmap_backing_virtual_base, &pte);
	report_contract(!ret && pte_physical_address(pte) ==
			layout.bitmap_backing.base &&
			(pte & 0xff) == (NACC_ROOT_PTE_VALID |
			 NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE |
			 NACC_ROOT_PTE_ACCESSED | NACC_ROOT_PTE_DIRTY),
			"bitmap backing leaf has exact PA and writable permissions");

	control_result = result;
	mappings[0] = (struct nacc_root_user_mapping) {
		.virtual_base = UINT64_C(0x00400000),
		.physical_base = layout.nacc_pool.base + 30 * NACC_ROOT_PAGE_SIZE,
		.page_count = 1,
		.permissions = NACC_ROOT_PTE_READ | NACC_ROOT_PTE_EXECUTE |
			NACC_ROOT_PTE_USER,
	};
	mappings[1] = (struct nacc_root_user_mapping) {
		.virtual_base = UINT64_C(0x00800000),
		.physical_base = layout.nacc_pool.base + 31 * NACC_ROOT_PAGE_SIZE,
		.page_count = 1,
		.permissions = NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE |
			NACC_ROOT_PTE_USER,
	};
	live_config = (struct nacc_root_live_config) {
		.root_physical_address = result.next_pool_physical_address,
		.ptp_pool_base = result.next_pool_physical_address,
		.ptp_pool_size = 12 * NACC_ROOT_PAGE_SIZE,
		.control_root = &control_result,
		.user_mappings = mappings,
		.user_mapping_count = 2,
	};
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(!ret && result.root_physical_address ==
			live_config.root_physical_address,
			"live builder publishes its independent ROOT_L0");
	ret = walk_leaf(&store, result.root_physical_address,
			mappings[0].virtual_base, &pte);
	report_contract(!ret && pte_physical_address(pte) ==
			mappings[0].physical_base &&
			(pte & 0xff) == (NACC_ROOT_PTE_VALID |
			 NACC_ROOT_PTE_READ | NACC_ROOT_PTE_EXECUTE |
			 NACC_ROOT_PTE_USER | NACC_ROOT_PTE_ACCESSED),
			"live RX mapping has exact AU permissions");
	ret = walk_leaf(&store, result.root_physical_address,
			mappings[1].virtual_base, &pte);
	report_contract(!ret && pte_physical_address(pte) ==
			mappings[1].physical_base &&
			(pte & 0xff) == (NACC_ROOT_PTE_VALID |
			 NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE |
			 NACC_ROOT_PTE_USER | NACC_ROOT_PTE_ACCESSED |
			 NACC_ROOT_PTE_DIRTY),
			"live RW mapping has exact AU permissions");
	ret = fake_read_pte(result.root_physical_address, 256, &pte, &store);
	report_contract(!ret && pte == high[0],
			"live root preserves the kernel high half");

	sentinel = result;
	live_config.ptp_pool_base = layout.control_root_l0.base;
	live_config.root_physical_address = layout.control_root_l0.base;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(ret == -EINVAL &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"live builder rejects reuse of the control root allocation");
	live_config.ptp_pool_base = live_config.control_root->
		next_pool_physical_address;
	live_config.root_physical_address = live_config.ptp_pool_base;
	mappings[0].permissions = NACC_ROOT_PTE_EXECUTE | NACC_ROOT_PTE_USER;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(!ret,
			"live builder accepts an execute-only AU mapping");
	mappings[0].permissions = NACC_ROOT_PTE_READ | NACC_ROOT_PTE_WRITE |
		NACC_ROOT_PTE_EXECUTE | NACC_ROOT_PTE_USER;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(!ret,
			"live builder preserves a writable executable AU mapping");
	mappings[0].permissions = NACC_ROOT_PTE_READ | NACC_ROOT_PTE_EXECUTE |
		NACC_ROOT_PTE_USER;
	mappings[0].physical_base = live_config.ptp_pool_base;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(ret == -EINVAL,
			"live builder rejects payload aliases into its PTP slice");
	mappings[0].physical_base = layout.bitmap_target.base;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(ret == -EINVAL,
			"live builder rejects payload outside the dedicated NACC pool");
	mappings[0].physical_base = layout.nacc_pool.base;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(ret == -EINVAL,
			"live builder rejects payload aliases into control PTP pages");
	mappings[0].physical_base = layout.nacc_pool.base +
		30 * NACC_ROOT_PAGE_SIZE;
	mappings[1].physical_base = mappings[0].physical_base;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(ret == -EEXIST,
			"live builder rejects duplicate payload physical pages");
	mappings[1].physical_base = layout.nacc_pool.base +
		31 * NACC_ROOT_PAGE_SIZE;
	mappings[1].virtual_base = descriptor.agent_virtual_base;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(ret == -EINVAL,
			"live builder rejects AU overlap with Agent mappings");
	mappings[1].virtual_base = descriptor.agent_virtual_base +
		8 * NACC_ROOT_PAGE_SIZE;
	ret = nacc_root_build_live(&result, &layout, &descriptor, &image, high,
				   &live_config, &backend);
	report_contract(ret == -EINVAL,
			"live builder rejects AU overlap with the reserved Agent window");
	mappings[1].virtual_base = UINT64_C(0x00800000);

	sentinel = (struct nacc_root_build_result) {
		.root_physical_address = UINT64_MAX,
		.next_pool_physical_address = UINT64_MAX,
		.lower_ptp_count = UINT64_MAX,
		.leaf_count = UINT64_MAX,
	};
	result = sentinel;
	store.fail_write = 1;
	store.writes = 0;
	ret = nacc_root_build(&result, &layout, &descriptor, &image, high,
			      &backend);
	report_contract(ret == -EIO, "backend write failure is preserved");
	report_contract(!memcmp(&result, &sentinel, sizeof(result)),
			"backend failure does not publish result");
	store.fail_write = 0;

	initialize_layout(&layout);
	layout.nacc_pool.size = 8 * NACC_ROOT_PAGE_SIZE;
	layout.control_root_l0.base = layout.nacc_pool.base +
		5 * NACC_ROOT_PAGE_SIZE;
	descriptor.nacc_pool = layout.nacc_pool;
	descriptor.control_root_l0 = layout.control_root_l0;
	result = sentinel;
	ret = nacc_root_build(&result, &layout, &descriptor, &image, high,
			      &backend);
	report_contract(ret == -ENOSPC, "undersized pool fails closed");
	report_contract(!memcmp(&result, &sentinel, sizeof(result)),
			"pool exhaustion does not publish result");

	initialize_layout(&layout);
	layout.agent_region.size = 2 * NACC_ROOT_PAGE_SIZE;
	ret = nacc_bootstrap_descriptor_build(&descriptor, &layout, 1);
	if (ret)
		ksft_exit_fail_msg("fixture descriptor rebuild failed: %d\n", ret);
	initialize_image(&image);
	result = sentinel;
	ret = nacc_root_build(&result, &layout, &descriptor, &image, high,
			      &backend);
	report_contract(ret == -ERANGE,
			"Agent segment outside declared region is rejected");
	report_contract(!memcmp(&result, &sentinel, sizeof(result)),
			"invalid Agent range does not publish result");

	initialize_layout(&layout);
	layout.arena.base = UINT64_C(1) << 56;
	layout.agent_region.base = layout.arena.base;
	layout.bitmap_target.base = layout.arena.base + UINT64_C(0x10000000);
	layout.nacc_pool.base = layout.bitmap_target.base;
	layout.control_root_l0.base = layout.nacc_pool.base +
		5 * NACC_ROOT_PAGE_SIZE;
	layout.bitmap_backing.base = layout.arena.base + UINT64_C(0x20000000);
	layout.mailbox.base = layout.arena.base + UINT64_C(0x30000000);
	layout.emergency_stack.base = layout.arena.base + UINT64_C(0x40000000);
	ret = nacc_bootstrap_descriptor_build(&descriptor, &layout, 1);
	if (ret)
		ksft_exit_fail_msg("high-PA descriptor build failed: %d\n", ret);
	result = sentinel;
	ret = nacc_root_build(&result, &layout, &descriptor, &image, high,
			      &backend);
	report_contract(ret == -ERANGE,
			"physical arena outside Sv39 PTE width is rejected");
	report_contract(!memcmp(&result, &sentinel, sizeof(result)),
			"invalid physical width does not publish result");

	free(store.bytes);
	ksft_finished();
	return 0;
}
