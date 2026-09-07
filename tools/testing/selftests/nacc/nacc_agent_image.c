// SPDX-License-Identifier: GPL-2.0-only
/* NACC Agent build-time metadata 的 host-buildable contract test。 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "../../../../arch/riscv/include/asm/nacc_agent_image.h"
#include "../kselftest.h"

static void initialize_metadata(struct nacc_agent_image_metadata *metadata)
{
	memset(metadata, 0, sizeof(*metadata));
	metadata->magic = NACC_LINUX_AGENT_IMAGE_MAGIC;
	metadata->abi_major = NACC_LINUX_AGENT_IMAGE_ABI_MAJOR;
	metadata->abi_minor = NACC_LINUX_AGENT_IMAGE_ABI_MINOR;
	metadata->descriptor_size = NACC_LINUX_AGENT_IMAGE_DESCRIPTOR_SIZE;
	metadata->artifact_size = UINT64_C(0x9000);
	metadata->entry_offset = 0;
	metadata->required_features = NACC_LINUX_AGENT_IMAGE_REQUIRED_FEATURES;
	metadata->bss_size = UINT64_C(0x2ff8);
	metadata->stack_size = NACC_LINUX_AGENT_IMAGE_PAGE_SIZE;
	metadata->stack_alignment = NACC_LINUX_AGENT_IMAGE_PAGE_SIZE;
	metadata->segments[0] = (struct nacc_agent_image_segment) {
		.file_offset = UINT64_C(0x1000),
		.virtual_offset = 0,
		.file_size = UINT64_C(0x1040),
		.memory_size = UINT64_C(0x1040),
		.flags = NACC_LINUX_AGENT_IMAGE_RX_FLAGS,
		.alignment = NACC_LINUX_AGENT_IMAGE_PAGE_SIZE,
	};
	metadata->segments[1] = (struct nacc_agent_image_segment) {
		.file_offset = UINT64_C(0x3000),
		.virtual_offset = UINT64_C(0x2000),
		.file_size = 8,
		.memory_size = UINT64_C(0x3000),
		.flags = NACC_LINUX_AGENT_IMAGE_RW_FLAGS,
		.alignment = NACC_LINUX_AGENT_IMAGE_PAGE_SIZE,
	};
	metadata->stack_top_offset = UINT64_C(0x5000);
	metadata->boot_context_offset = UINT64_C(0x3000);
	metadata->bootstrap_handshake_offset = UINT64_C(0x124);
	metadata->artifact_digest[0] = 1;
	metadata->descriptor_digest[0] = 1;
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
	struct nacc_agent_image_metadata metadata;
	int plan = 18;

	ksft_print_header();
	ksft_set_plan(plan);

	initialize_metadata(&metadata);
	report_contract(nacc_agent_image_metadata_validate(&metadata) == 0,
			"canonical metadata is accepted");
	report_contract(nacc_agent_image_metadata_validate(NULL) == -EINVAL,
			"null metadata is rejected");
	metadata.magic ^= 1;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"wrong magic is rejected");
	initialize_metadata(&metadata);
	metadata.abi_minor++;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"wrong ABI minor is rejected");
	initialize_metadata(&metadata);
	metadata.artifact_size = 0;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"empty artifact is rejected");
	initialize_metadata(&metadata);
	metadata.required_features ^= 1;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"missing feature is rejected");
	initialize_metadata(&metadata);
	metadata.segments[0].flags = NACC_LINUX_AGENT_IMAGE_RW_FLAGS;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"wrong RX flags are rejected");
	initialize_metadata(&metadata);
	metadata.segments[1].memory_size = 0;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"empty RW memory is rejected");
	initialize_metadata(&metadata);
	metadata.segments[0].alignment = 3 * NACC_LINUX_AGENT_IMAGE_PAGE_SIZE;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"non-power-of-two alignment is rejected");
	initialize_metadata(&metadata);
	metadata.segments[1].file_offset = UINT64_C(0x2000);
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"overlapping file segments are rejected");
	initialize_metadata(&metadata);
	metadata.segments[1].virtual_offset = UINT64_C(0x1000);
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"overlapping memory segments are rejected");
	initialize_metadata(&metadata);
	metadata.entry_offset = 1;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"misaligned entry is rejected");
	initialize_metadata(&metadata);
	metadata.entry_offset = metadata.segments[0].file_size;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"entry outside RX file content is rejected");
	initialize_metadata(&metadata);
	metadata.bss_size++;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"wrong BSS size is rejected");
	initialize_metadata(&metadata);
	metadata.stack_size = metadata.bss_size + 1;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"stack larger than BSS is rejected");
	initialize_metadata(&metadata);
	metadata.stack_top_offset += NACC_LINUX_AGENT_IMAGE_PAGE_SIZE;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"wrong stack top is rejected");
	initialize_metadata(&metadata);
	metadata.boot_context_offset += NACC_LINUX_AGENT_IMAGE_PAGE_SIZE;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"detached boot context is rejected");
	initialize_metadata(&metadata);
	metadata.bootstrap_handshake_offset |= 1;
	report_contract(nacc_agent_image_metadata_validate(&metadata) == -EINVAL,
			"misaligned handshake is rejected");
	ksft_finished();
	return 0;
}
