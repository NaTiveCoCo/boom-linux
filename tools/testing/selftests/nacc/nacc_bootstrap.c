// SPDX-License-Identifier: GPL-2.0-only
/* NACC private bootstrap ABI 的 host-buildable contract test。 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../../../arch/riscv/include/asm/nacc_bootstrap.h"
#include "../kselftest.h"

static void initialize_descriptor(struct nacc_bootstrap_descriptor *descriptor)
{
	memset(descriptor, 0, sizeof(*descriptor));
	descriptor->magic = NACC_BOOTSTRAP_MAGIC;
	descriptor->abi_major = NACC_BOOTSTRAP_ABI_MAJOR;
	descriptor->abi_minor = NACC_BOOTSTRAP_ABI_MINOR;
	descriptor->struct_size = NACC_BOOTSTRAP_DESCRIPTOR_V2_SIZE;
	descriptor->feature_bits = NACC_BOOTSTRAP_FEATURES_V2;
	descriptor->agent_region.base = UINT64_C(0x10000000);
	descriptor->agent_region.size = UINT64_C(0x01000000);
	descriptor->bitmap_target.base = UINT64_C(0x20000000);
	descriptor->bitmap_target.size = UINT64_C(0x01000000);
	descriptor->bitmap_backing.base = UINT64_C(0x30000000);
	descriptor->bitmap_backing.size = NACC_BOOTSTRAP_PAGE_SIZE;
	descriptor->nacc_pool.base = UINT64_C(0x20000000);
	descriptor->nacc_pool.size = UINT64_C(0x01000000);
	descriptor->control_root_l0.base = UINT64_C(0x20000000);
	descriptor->control_root_l0.size = NACC_BOOTSTRAP_PAGE_SIZE;
	descriptor->mailbox.base = UINT64_C(0x40000000);
	descriptor->mailbox.size = NACC_BOOTSTRAP_PAGE_SIZE;
	descriptor->emergency_stack.base = UINT64_C(0x50000000);
	descriptor->emergency_stack.size = NACC_BOOTSTRAP_PAGE_SIZE;
	descriptor->agent_virtual_base = UINT64_C(0x100000000);
	descriptor->mailbox_virtual_base = UINT64_C(0x200000000);
	descriptor->emergency_stack_virtual_top = UINT64_C(0x300001000);
	descriptor->bootstrap_sequence = 1;
	descriptor->nacc_pool_virtual_base = UINT64_C(0x400000000);
	descriptor->bitmap_backing_virtual_base = UINT64_C(0x500000000);
}

static void initialize_physical_layout(
	struct nacc_bootstrap_physical_layout *layout)
{
	struct nacc_bootstrap_descriptor descriptor;

	initialize_descriptor(&descriptor);
	memset(layout, 0, sizeof(*layout));
	layout->arena.base = UINT64_C(0x08000000);
	layout->arena.size = UINT64_C(0x50000000);
	layout->agent_region = descriptor.agent_region;
	layout->bitmap_target = descriptor.bitmap_target;
	layout->bitmap_backing = descriptor.bitmap_backing;
	layout->nacc_pool = descriptor.nacc_pool;
	layout->control_root_l0 = descriptor.control_root_l0;
	layout->mailbox = descriptor.mailbox;
	layout->emergency_stack = descriptor.emergency_stack;
}

static void report_contract(int condition, const char *name)
{
	if (condition)
		ksft_test_result_pass("%s\n", name);
	else
		ksft_test_result_fail("%s\n", name);
}

int main(void)
{
	union {
		uint64_t alignment;
		unsigned char bytes[sizeof(struct nacc_bootstrap_physical_layout) + 1];
	} layout_storage;
	struct nacc_bootstrap_descriptor descriptor;
	struct nacc_bootstrap_physical_layout layout;
	struct nacc_bootstrap_agent_memory_state memory_state = {};
	int plan = 71;

	ksft_print_header();
	ksft_set_plan(plan);

	report_contract(sizeof(struct nacc_bootstrap_range) == 16 &&
				 sizeof(struct nacc_bootstrap_descriptor) == 232 &&
				 offsetof(struct nacc_bootstrap_descriptor,
					  agent_virtual_base) == 184 &&
				 offsetof(struct nacc_bootstrap_descriptor,
					  nacc_pool_virtual_base) == 216,
				"OpenSBI v2.0 descriptor layout is 232 bytes");

	initialize_descriptor(&descriptor);
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) == 0,
				"valid descriptor is accepted");
	report_contract(nacc_bootstrap_validate(NULL, sizeof(descriptor)) == -EINVAL,
				"null descriptor is rejected");

	descriptor.magic ^= 1;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EOPNOTSUPP, "wrong magic is rejected");
	initialize_descriptor(&descriptor);
	descriptor.abi_major++;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EOPNOTSUPP, "unsupported major is rejected");
	initialize_descriptor(&descriptor);
	descriptor.abi_major = 1;
	descriptor.abi_minor = 1;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EOPNOTSUPP, "pre-production v1.1 is rejected");
	initialize_descriptor(&descriptor);
	descriptor.feature_bits = NACC_BOOTSTRAP_FEATURES_V2 << 1;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EOPNOTSUPP, "unknown feature is rejected");
	initialize_descriptor(&descriptor);
	descriptor.feature_bits = 0;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EOPNOTSUPP,
			"missing management VA feature is rejected");
	initialize_descriptor(&descriptor);
	descriptor.reserved[0] = 1;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "non-zero reserved field is rejected");
	initialize_descriptor(&descriptor);
	descriptor.struct_size = NACC_BOOTSTRAP_DESCRIPTOR_V1_0_SIZE;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "truncated v1 descriptor is rejected");
	initialize_descriptor(&descriptor);
	descriptor.agent_region.size = 0;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "empty physical range is rejected");
	initialize_descriptor(&descriptor);
	descriptor.agent_virtual_base = descriptor.mailbox_virtual_base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "overlapping virtual ranges are rejected");
	initialize_descriptor(&descriptor);
	descriptor.nacc_pool_virtual_base++;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "unaligned NACC pool VA is rejected");
	initialize_descriptor(&descriptor);
	descriptor.nacc_pool_virtual_base = descriptor.agent_virtual_base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "NACC pool VA overlap is rejected");
	initialize_descriptor(&descriptor);
	descriptor.bitmap_backing_virtual_base =
		descriptor.nacc_pool_virtual_base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "bitmap backing VA overlap is rejected");
	initialize_descriptor(&descriptor);
	descriptor.bitmap_backing_virtual_base =
		NACC_BOOTSTRAP_SV39_USER_LIMIT - descriptor.bitmap_backing.size +
		NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL,
			"bitmap backing VA beyond user half is rejected");
	initialize_descriptor(&descriptor);
	descriptor.control_root_l0.base = UINT64_C(0x21000000);
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "root outside NACC pool is rejected");
	initialize_descriptor(&descriptor);
	descriptor.bitmap_backing.size = 0;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "undersized bitmap backing is rejected");
	initialize_descriptor(&descriptor);
	descriptor.mailbox.base = descriptor.bitmap_target.base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "mailbox overlapping target is rejected");
	initialize_descriptor(&descriptor);
	descriptor.emergency_stack.base = descriptor.bitmap_target.base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL,
			"emergency stack overlapping target is rejected");
	initialize_descriptor(&descriptor);
	descriptor.mailbox.base = descriptor.bitmap_backing.base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL, "mailbox overlapping backing is rejected");
	initialize_descriptor(&descriptor);
	descriptor.emergency_stack.base = descriptor.bitmap_backing.base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL,
			"emergency stack overlapping backing is rejected");
	initialize_descriptor(&descriptor);
	descriptor.emergency_stack.base = descriptor.mailbox.base;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EINVAL,
			"mailbox and emergency stack overlap is rejected");
	initialize_descriptor(&descriptor);
	descriptor.delegation_exception_mask =
		NACC_BOOTSTRAP_DELEGATION_EXCEPTION_MASK;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				0, "supported exception delegation is accepted");
	descriptor.delegation_exception_mask |= UINT64_C(1) << 63;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EOPNOTSUPP,
			"unsupported exception delegation is rejected");
	initialize_descriptor(&descriptor);
	descriptor.delegation_interrupt_mask =
		NACC_BOOTSTRAP_DELEGATION_INTERRUPT_MASK;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				0, "supported interrupt delegation is accepted");
	descriptor.delegation_interrupt_mask |= UINT64_C(1) << 63;
	report_contract(nacc_bootstrap_validate(&descriptor, sizeof(descriptor)) ==
				-EOPNOTSUPP,
			"unsupported interrupt delegation is rejected");
	report_contract(!nacc_bootstrap_capabilities_allow_bootstrap(0),
				"absent capability set stays fail-closed");
	report_contract(!nacc_bootstrap_capabilities_allow_bootstrap(
				NACC_BOOTSTRAP_CAP_PROBE),
				"probe-only capability set stays fail-closed");
	report_contract(nacc_bootstrap_capabilities_allow_bootstrap(
				NACC_BOOTSTRAP_CAP_REQUIRED),
				"complete capability set is recognized");
	report_contract(!nacc_bootstrap_capabilities_allow_bootstrap(
		NACC_BOOTSTRAP_CAP_REQUIRED | (1UL << 63)),
				"unknown capability bit stays fail-closed");

	report_contract(nacc_bootstrap_agent_memory_range_validate(0,
							 NACC_BOOTSTRAP_PAGE_SIZE) == -EINVAL,
				"zero physical base is rejected");
	report_contract(nacc_bootstrap_agent_memory_range_validate(
							 NACC_BOOTSTRAP_PAGE_SIZE, 0) == -EINVAL,
				"zero physical size is rejected");
	report_contract(nacc_bootstrap_agent_memory_range_validate(
							 NACC_BOOTSTRAP_PAGE_SIZE + 1,
							 NACC_BOOTSTRAP_PAGE_SIZE) == -EINVAL,
				"unaligned physical base is rejected");
	report_contract(nacc_bootstrap_agent_memory_range_validate(
							 NACC_BOOTSTRAP_PAGE_SIZE,
							 NACC_BOOTSTRAP_PAGE_SIZE + 1) == -EINVAL,
				"unaligned physical size is rejected");
	report_contract(nacc_bootstrap_agent_memory_range_validate(
							 UINT64_MAX - NACC_BOOTSTRAP_PAGE_SIZE + 1,
							 NACC_BOOTSTRAP_PAGE_SIZE) == -EOVERFLOW,
				"physical range overflow is rejected");

	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, false, 56) == 0,
				"absent memory state is accepted before capability gating");
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 NULL, false, 56) == -EINVAL,
				"null memory state is rejected");
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, false, 0) == -EINVAL,
				"zero physical address width is rejected");
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, false, 65) == -EINVAL,
				"oversized physical address width is rejected");
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, true, 56) == -ENODEV,
				"full capability rejects absent memory state");
	memory_state.matches = 2;
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, true, 56) == -EEXIST,
				"duplicate memory state is rejected");
	memory_state.matches = 1;
	memory_state.range.base = 0;
	memory_state.range.size = NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, true, 56) == -EINVAL,
				"memory snapshot with zero base is rejected");
	memory_state.range.base = UINT64_MAX - NACC_BOOTSTRAP_PAGE_SIZE + 1;
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, true, 56) == -EOVERFLOW,
				"memory snapshot range overflow is preserved");
	memory_state.range.base = UINT64_C(0x100000000);
	memory_state.range.size = NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, true, 32) == -ERANGE,
				"memory above physical address width is rejected");
	report_contract(nacc_bootstrap_agent_memory_state_validate(
							 &memory_state, true, 56) == 0,
				"valid memory snapshot satisfies full capability gating");

	report_contract(sizeof(struct nacc_bootstrap_physical_layout) == 128,
				"physical layout is 128 bytes");
	initialize_physical_layout(&layout);
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == 0,
				"valid physical layout is accepted");
	report_contract(nacc_bootstrap_physical_layout_validate(NULL) == -EINVAL,
				"null physical layout is rejected");
	initialize_physical_layout(&layout);
	layout.arena.size = 0;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"empty physical layout arena is rejected");
	initialize_physical_layout(&layout);
	layout.arena.base++;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"unaligned physical layout arena is rejected");
	initialize_physical_layout(&layout);
	layout.arena.base = UINT64_MAX - NACC_BOOTSTRAP_PAGE_SIZE + 1;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"overflowing physical layout arena is rejected");
	initialize_physical_layout(&layout);
	layout.agent_region.base = layout.arena.base - NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"role outside physical layout arena is rejected");
	initialize_physical_layout(&layout);
	layout.mailbox.base = layout.bitmap_target.base;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"overlapping physical layout roles are rejected");
	initialize_physical_layout(&layout);
	layout.bitmap_backing.size = 0;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"undersized physical layout bitmap is rejected");
	initialize_physical_layout(&layout);
	layout.control_root_l0.size = 2 * NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"multi-page physical layout control root is rejected");
	initialize_physical_layout(&layout);
	layout.nacc_pool.base = layout.bitmap_target.base +
		layout.bitmap_target.size;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"pool outside physical layout target is rejected");
	initialize_physical_layout(&layout);
	layout.control_root_l0.base = layout.nacc_pool.base +
		layout.nacc_pool.size;
	report_contract(nacc_bootstrap_physical_layout_validate(&layout) == -EINVAL,
				"control root outside physical layout pool is rejected");
	report_contract(nacc_bootstrap_physical_layout_validate(
		(const struct nacc_bootstrap_physical_layout *)
			(layout_storage.bytes + 1)) == -EINVAL,
				"misaligned physical layout pointer is rejected");

	initialize_descriptor(&descriptor);
	initialize_physical_layout(&layout);
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == 0,
				"descriptor exactly matches physical layout");
	report_contract(nacc_bootstrap_physical_layout_match(
					NULL, sizeof(descriptor), &layout) == -EINVAL,
				"null descriptor cannot match physical layout");
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor) - 1, &layout) ==
				-EINVAL,
				"short descriptor cannot match physical layout");
	descriptor.magic ^= 1;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) ==
				-EOPNOTSUPP,
				"descriptor validation error is preserved during match");
	initialize_descriptor(&descriptor);
	layout.arena.size = 0;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -EINVAL,
				"layout validation error is preserved during match");
	initialize_physical_layout(&layout);
	initialize_descriptor(&descriptor);
	descriptor.agent_region.base += NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -ERANGE,
				"Agent role mismatch is rejected");
	initialize_descriptor(&descriptor);
	descriptor.bitmap_target.base -= NACC_BOOTSTRAP_PAGE_SIZE;
	descriptor.bitmap_target.size += NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -ERANGE,
				"bitmap target role mismatch is rejected");
	initialize_descriptor(&descriptor);
	descriptor.bitmap_backing.base += NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -ERANGE,
				"bitmap backing role mismatch is rejected");
	initialize_descriptor(&descriptor);
	descriptor.nacc_pool.size -= NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -ERANGE,
				"NACC pool role mismatch is rejected");
	initialize_descriptor(&descriptor);
	descriptor.control_root_l0.base += NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -ERANGE,
				"control root role mismatch is rejected");
	initialize_descriptor(&descriptor);
	descriptor.mailbox.base += NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -ERANGE,
				"mailbox role mismatch is rejected");
	initialize_descriptor(&descriptor);
	descriptor.emergency_stack.base += NACC_BOOTSTRAP_PAGE_SIZE;
	report_contract(nacc_bootstrap_physical_layout_match(
					&descriptor, sizeof(descriptor), &layout) == -ERANGE,
				"emergency stack role mismatch is rejected");

	return 0;
}
