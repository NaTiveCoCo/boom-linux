// SPDX-License-Identifier: GPL-2.0-only
#include <asm/nacc_enter.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failed;
static int test_number;

static void report_contract(int condition, const char *description)
{
	test_number++;
	if (!condition)
		failed = 1;
	printf("%s %d %s\n", condition ? "ok" : "not ok", test_number,
	       description);
}

static struct nacc_enter_message_request valid_request(const uint8_t *code,
							size_t code_length)
{
	return (struct nacc_enter_message_request) {
		.pool_base = UINT64_C(0x70000000),
		.pool_size = UINT64_C(0x01000000),
		.live_root_physical_address = UINT64_C(0x70010000),
		.ptp_page_count = 12,
		.code_physical_address = UINT64_C(0x7001c000),
		.stack_physical_address = UINT64_C(0x7001d000),
		.entry_offset = 0,
		.sequence = 1,
		.agent_handle = 2,
		.mm_handle = 3,
		.thread_handle = 4,
		.service_handle = 5,
		.object_generation = 6,
		.code_prefix = code,
		.code_prefix_length = code_length,
	};
}

int main(void)
{
	uint8_t mailbox[NACC_ENTER_MAILBOX_SIZE];
	uint8_t unaligned_mailbox[NACC_ENTER_MAILBOX_SIZE + 1];
	uint8_t code[NACC_ENTER_MAX_CODE_PREFIX];
	struct nacc_runtime_mailbox_descriptor *descriptor = (void *)mailbox;
	struct nacc_runtime_enter_payload *payload;
	struct nacc_enter_message_request request;
	uint8_t sentinel[NACC_ENTER_MAILBOX_SIZE];
	int ret;

	printf("TAP version 13\n1..16\n");
	memset(code, 0xa5, sizeof(code));
	memset(mailbox, 0x5a, sizeof(mailbox));
	request = valid_request(code, 16);
	ret = nacc_enter_message_build(mailbox, sizeof(mailbox), &request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(!ret && descriptor->header.magic ==
			NACC_RUNTIME_MAILBOX_MAGIC &&
			descriptor->header.struct_size == sizeof(*descriptor),
			"builder emits the exact runtime ABI header");
	report_contract(descriptor->opcode == NACC_RUNTIME_ENTER_OPCODE &&
			descriptor->flags == NACC_RUNTIME_MAILBOX_FLAG_REQUEST &&
			descriptor->status == 0,
			"builder emits a strict ENTER request");
	report_contract(descriptor->payload_offset == sizeof(*descriptor) &&
			descriptor->payload_length == sizeof(*payload) +
				request.code_prefix_length,
			"payload range exactly describes the code prefix");
	report_contract(payload->live_root_physical_address ==
			request.live_root_physical_address &&
			payload->ptp_base == request.live_root_physical_address &&
			payload->ptp_page_count == request.ptp_page_count,
			"payload identifies the reserved live root slice");
	report_contract(payload->code_virtual_address ==
			NACC_ENTER_CODE_VIRTUAL_ADDRESS &&
			payload->stack_virtual_address ==
				NACC_ENTER_STACK_VIRTUAL_ADDRESS &&
			payload->stack_pointer == NACC_ENTER_STACK_POINTER,
			"payload fixes the minimal code and stack virtual layout");
	report_contract(!memcmp((uint8_t *)payload + sizeof(*payload), code,
				request.code_prefix_length),
			"builder copies the exact code prefix");
	report_contract(mailbox[sizeof(mailbox) - 1] == 0,
			"builder clears unused mailbox bytes");

	request = valid_request(code, sizeof(code));
	ret = nacc_enter_message_build(mailbox, sizeof(mailbox), &request);
	report_contract(!ret && descriptor->payload_offset +
				descriptor->payload_length == sizeof(mailbox),
			"maximum code prefix exactly fills the mailbox");
	memcpy(sentinel, mailbox, sizeof(mailbox));
	request.code_prefix_length = NACC_ENTER_MAX_CODE_PREFIX + 1;
	ret = nacc_enter_message_build(mailbox, sizeof(mailbox), &request);
	report_contract(ret == -EINVAL && !memcmp(mailbox, sentinel,
						 sizeof(mailbox)),
			"oversized code prefix fails without changing mailbox");
	request = valid_request(code, sizeof(code));
	request.entry_offset = request.code_prefix_length;
	report_contract(nacc_enter_message_build(mailbox, sizeof(mailbox),
						 &request) == -EINVAL,
			"entry outside the prefix is rejected");
	request = valid_request(code, sizeof(code));
	request.code_physical_address = request.live_root_physical_address +
		NACC_ENTER_PAGE_SIZE;
	report_contract(nacc_enter_message_build(mailbox, sizeof(mailbox),
						 &request) == -EINVAL,
			"payload cannot overlap the PTP slice");
	request = valid_request(code, sizeof(code));
	request.stack_physical_address = request.code_physical_address;
	report_contract(nacc_enter_message_build(mailbox, sizeof(mailbox),
						 &request) == -EINVAL,
			"code and stack physical pages must be distinct");
	request = valid_request(code, sizeof(code));
	report_contract(nacc_enter_message_build(mailbox, sizeof(mailbox) - 1,
						 &request) == -EINVAL,
			"mailbox must match the canonical one-page size");
	request = valid_request(code, sizeof(code));
	memcpy(mailbox, &request, sizeof(request));
	memcpy(sentinel, mailbox, sizeof(mailbox));
	report_contract(nacc_enter_message_build(mailbox, sizeof(mailbox),
						 (void *)mailbox) == -EINVAL &&
			!memcmp(mailbox, sentinel, sizeof(mailbox)),
			"request cannot alias the output mailbox");
	request = valid_request(mailbox + 512, 16);
	memcpy(sentinel, mailbox, sizeof(mailbox));
	report_contract(nacc_enter_message_build(mailbox, sizeof(mailbox),
						 &request) == -EINVAL &&
			!memcmp(mailbox, sentinel, sizeof(mailbox)),
			"code prefix cannot alias the output mailbox");
	request = valid_request(code, 16);
	report_contract(nacc_enter_message_build(unaligned_mailbox + 1,
						 sizeof(mailbox), &request) == -EINVAL,
			"mailbox must provide descriptor alignment");
	return failed;
}
