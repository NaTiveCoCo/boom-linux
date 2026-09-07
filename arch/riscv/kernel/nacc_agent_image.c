// SPDX-License-Identifier: GPL-2.0-only
/* Canonical Agent build-time image metadata consumer。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <generated/nacc-agent-image-metadata.h>
#else
#include <errno.h>
#include <stddef.h>
#endif

#include <asm/nacc_agent_image.h>

static bool nacc_agent_image_power_of_two(nacc_agent_image_u64 value)
{
	return value && !(value & (value - 1));
}

int nacc_agent_image_metadata_validate(
	const struct nacc_agent_image_metadata *metadata)
{
	const struct nacc_agent_image_segment *text;
	const struct nacc_agent_image_segment *data;
	nacc_agent_image_u64 stack_bottom;
	size_t index;

	if (!metadata)
		return -EINVAL;
	if (metadata->magic != NACC_LINUX_AGENT_IMAGE_MAGIC ||
	    metadata->abi_major != NACC_LINUX_AGENT_IMAGE_ABI_MAJOR ||
	    metadata->abi_minor != NACC_LINUX_AGENT_IMAGE_ABI_MINOR ||
	    metadata->descriptor_size != NACC_LINUX_AGENT_IMAGE_DESCRIPTOR_SIZE ||
	    !metadata->artifact_size ||
	    metadata->artifact_size > NACC_LINUX_AGENT_IMAGE_MAX_ARTIFACT_SIZE ||
	    metadata->required_features !=
		    NACC_LINUX_AGENT_IMAGE_REQUIRED_FEATURES)
		return -EINVAL;

	for (index = 0; index < NACC_LINUX_AGENT_IMAGE_SEGMENT_COUNT; index++) {
		const struct nacc_agent_image_segment *segment =
			&metadata->segments[index];

		if (!segment->file_size ||
		    segment->file_size > segment->memory_size ||
		    !nacc_agent_image_power_of_two(segment->alignment) ||
		    segment->alignment < NACC_LINUX_AGENT_IMAGE_PAGE_SIZE ||
		    segment->alignment > NACC_LINUX_AGENT_IMAGE_MAX_ALIGNMENT ||
		    (segment->file_offset & (segment->alignment - 1)) ||
		    (segment->virtual_offset & (segment->alignment - 1)) ||
		    segment->file_offset >= metadata->artifact_size ||
		    segment->file_size >
			    metadata->artifact_size - segment->file_offset ||
		    segment->virtual_offset >= NACC_LINUX_AGENT_IMAGE_MAX_REGION_SIZE ||
		    segment->memory_size > NACC_LINUX_AGENT_IMAGE_MAX_REGION_SIZE -
			    segment->virtual_offset)
			return -EINVAL;
	}

	text = &metadata->segments[0];
	data = &metadata->segments[1];
	if (text->flags != NACC_LINUX_AGENT_IMAGE_RX_FLAGS ||
	    data->flags != NACC_LINUX_AGENT_IMAGE_RW_FLAGS ||
	    text->virtual_offset || text->file_offset >= data->file_offset ||
	    text->virtual_offset >= data->virtual_offset ||
	    text->file_offset + text->file_size > data->file_offset ||
	    text->virtual_offset + text->memory_size > data->virtual_offset ||
	    (metadata->entry_offset & 1) ||
	    metadata->entry_offset < text->virtual_offset ||
	    metadata->entry_offset - text->virtual_offset >= text->file_size)
		return -EINVAL;

	if (!metadata->bss_size ||
	    metadata->bss_size > NACC_LINUX_AGENT_IMAGE_MAX_BSS_SIZE ||
	    metadata->bss_size != data->memory_size - data->file_size ||
	    !metadata->stack_size ||
	    metadata->stack_size > NACC_LINUX_AGENT_IMAGE_MAX_STACK_SIZE ||
	    metadata->stack_size > metadata->bss_size ||
	    !nacc_agent_image_power_of_two(metadata->stack_alignment) ||
	    metadata->stack_alignment < NACC_LINUX_AGENT_IMAGE_PAGE_SIZE ||
	    metadata->stack_alignment > NACC_LINUX_AGENT_IMAGE_MAX_ALIGNMENT ||
	    metadata->stack_top_offset != data->virtual_offset + data->memory_size ||
	    metadata->stack_top_offset < metadata->stack_size)
		return -EINVAL;

	stack_bottom = metadata->stack_top_offset - metadata->stack_size;
	if (stack_bottom < data->virtual_offset + data->file_size ||
	    (metadata->stack_top_offset & (metadata->stack_alignment - 1)) ||
	    (stack_bottom & (metadata->stack_alignment - 1)) ||
	    (metadata->boot_context_offset &
		    (NACC_LINUX_AGENT_IMAGE_PAGE_SIZE - 1)) ||
	    metadata->boot_context_offset + NACC_LINUX_AGENT_IMAGE_BOOT_CONTEXT_SIZE !=
		    stack_bottom ||
	    metadata->boot_context_offset < data->virtual_offset + data->file_size ||
	    (metadata->bootstrap_handshake_offset & 3) ||
	    metadata->bootstrap_handshake_offset < text->virtual_offset ||
	    text->file_size < 4 ||
	    metadata->bootstrap_handshake_offset - text->virtual_offset >
		    text->file_size - 4)
		return -EINVAL;

	return 0;
}

#ifdef __KERNEL__
_Static_assert(NACC_AGENT_IMAGE_MAGIC == NACC_LINUX_AGENT_IMAGE_MAGIC,
	       "generated Agent image magic changed");
_Static_assert(NACC_AGENT_IMAGE_ABI_MAJOR == NACC_LINUX_AGENT_IMAGE_ABI_MAJOR &&
	       NACC_AGENT_IMAGE_ABI_MINOR == NACC_LINUX_AGENT_IMAGE_ABI_MINOR,
	       "generated Agent image ABI changed");
_Static_assert(NACC_AGENT_IMAGE_DESCRIPTOR_SIZE ==
	       NACC_LINUX_AGENT_IMAGE_DESCRIPTOR_SIZE,
	       "generated Agent descriptor size changed");
_Static_assert(NACC_AGENT_IMAGE_SEGMENT_COUNT ==
	       NACC_LINUX_AGENT_IMAGE_SEGMENT_COUNT,
	       "generated Agent segment count changed");
_Static_assert(NACC_AGENT_IMAGE_REQUIRED_FEATURES ==
	       NACC_LINUX_AGENT_IMAGE_REQUIRED_FEATURES,
	       "generated Agent required features changed");

static const struct nacc_agent_image_metadata nacc_agent_image_metadata = {
	.magic = NACC_AGENT_IMAGE_MAGIC,
	.abi_major = NACC_AGENT_IMAGE_ABI_MAJOR,
	.abi_minor = NACC_AGENT_IMAGE_ABI_MINOR,
	.descriptor_size = NACC_AGENT_IMAGE_DESCRIPTOR_SIZE,
	.artifact_size = NACC_AGENT_IMAGE_ARTIFACT_SIZE,
	.entry_offset = NACC_AGENT_IMAGE_ENTRY_OFFSET,
	.required_features = NACC_AGENT_IMAGE_REQUIRED_FEATURES,
	.bss_size = NACC_AGENT_IMAGE_BSS_SIZE,
	.stack_size = NACC_AGENT_IMAGE_STACK_SIZE,
	.stack_alignment = NACC_AGENT_IMAGE_STACK_ALIGNMENT,
	.segments = {
		{
			.file_offset = NACC_AGENT_IMAGE_SEGMENT_0_FILE_OFFSET,
			.virtual_offset = NACC_AGENT_IMAGE_SEGMENT_0_VIRTUAL_OFFSET,
			.file_size = NACC_AGENT_IMAGE_SEGMENT_0_FILE_SIZE,
			.memory_size = NACC_AGENT_IMAGE_SEGMENT_0_MEMORY_SIZE,
			.flags = NACC_AGENT_IMAGE_SEGMENT_0_FLAGS,
			.alignment = NACC_AGENT_IMAGE_SEGMENT_0_ALIGNMENT,
		},
		{
			.file_offset = NACC_AGENT_IMAGE_SEGMENT_1_FILE_OFFSET,
			.virtual_offset = NACC_AGENT_IMAGE_SEGMENT_1_VIRTUAL_OFFSET,
			.file_size = NACC_AGENT_IMAGE_SEGMENT_1_FILE_SIZE,
			.memory_size = NACC_AGENT_IMAGE_SEGMENT_1_MEMORY_SIZE,
			.flags = NACC_AGENT_IMAGE_SEGMENT_1_FLAGS,
			.alignment = NACC_AGENT_IMAGE_SEGMENT_1_ALIGNMENT,
		},
	},
	.stack_top_offset = NACC_AGENT_IMAGE_STACK_TOP_OFFSET,
	.boot_context_offset = NACC_AGENT_IMAGE_BOOT_CONTEXT_OFFSET,
	.bootstrap_handshake_offset = NACC_AGENT_IMAGE_HANDSHAKE_OFFSET,
	.artifact_digest = NACC_AGENT_IMAGE_ARTIFACT_DIGEST_BYTES,
	.descriptor_digest = NACC_AGENT_IMAGE_DESCRIPTOR_DIGEST_BYTES,
};

const struct nacc_agent_image_metadata *nacc_agent_image_metadata_snapshot(void)
{
	if (nacc_agent_image_metadata_validate(&nacc_agent_image_metadata))
		panic("NACC generated Agent image metadata is invalid");
	return &nacc_agent_image_metadata;
}
#endif
