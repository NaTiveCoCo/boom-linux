// SPDX-License-Identifier: GPL-2.0-only
#include <asm/nacc_runtime_lifecycle.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failed;
static int test_number;

static _Alignas(NACC_ENTER_MAILBOX_SIZE)
	uint8_t mailbox[NACC_ENTER_MAILBOX_SIZE];

static void report_contract(int condition, const char *description)
{
	test_number++;
	if (!condition)
		failed = 1;
	printf("%s %d %s\n", condition ? "ok" : "not ok", test_number,
	       description);
}

static struct nacc_runtime_object_ref object_ref(uint64_t value)
{
	return (struct nacc_runtime_object_ref) {
		.handle = value,
		.generation = value + 100,
	};
}

static struct nacc_runtime_lifecycle_request request_for(uint32_t opcode)
{
	struct nacc_runtime_lifecycle_request request = {
		.opcode = opcode,
		.sequence = 17,
	};

	if (opcode != NACC_RUNTIME_AGENT_CREATE_OPCODE)
		request.agent = object_ref(1);
	if (opcode == NACC_RUNTIME_MM_RETIRE_OPCODE ||
	    opcode == NACC_RUNTIME_TASK_ATTACH_OPCODE)
		request.mm = object_ref(2);
	if (opcode == NACC_RUNTIME_TASK_ATTACH_OPCODE ||
	    opcode == NACC_RUNTIME_TASK_RETIRE_OPCODE)
		request.thread = object_ref(3);
	return request;
}

static struct nacc_runtime_mailbox_descriptor *build_request(
	const struct nacc_runtime_lifecycle_request *request)
{
	if (nacc_runtime_lifecycle_message_build(mailbox, sizeof(mailbox),
					 request))
		return NULL;
	return (struct nacc_runtime_mailbox_descriptor *)mailbox;
}

static struct nacc_runtime_mailbox_descriptor *build_response(
	const struct nacc_runtime_lifecycle_request *request)
{
	struct nacc_runtime_mailbox_descriptor *descriptor =
		build_request(request);

	if (!descriptor)
		return NULL;
	descriptor->flags = NACC_RUNTIME_MAILBOX_FLAG_RESPONSE;
	descriptor->payload_length = 0;
	return descriptor;
}

static void test_request_builders(void)
{
	struct nacc_runtime_lifecycle_request request =
		request_for(NACC_RUNTIME_AGENT_CREATE_OPCODE);
	struct nacc_runtime_mailbox_descriptor *descriptor =
		build_request(&request);
	struct nacc_runtime_lifecycle_payload *payload;
	uint8_t saved[NACC_ENTER_MAILBOX_SIZE];

	report_contract(descriptor &&
			descriptor->header.abi_minor == NACC_RUNTIME_ABI_MINOR &&
			(descriptor->header.features &
			 NACC_RUNTIME_FEATURE_LIFECYCLE_CREATE_ATTACH),
			"AGENT_CREATE emits ABI 1.3 lifecycle feature");
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->payload_length == sizeof(*payload) &&
			!descriptor->agent_handle &&
			!payload->agent_generation,
			"AGENT_CREATE carries a zero parent identity");

	request = request_for(NACC_RUNTIME_MM_CREATE_OPCODE);
	descriptor = build_request(&request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->agent_handle == request.agent.handle &&
			payload->agent_generation == request.agent.generation &&
			!descriptor->mm_handle && !payload->mm_generation,
			"MM_CREATE carries the exact Agent identity");

	request = request_for(NACC_RUNTIME_TASK_CREATE_OPCODE);
	descriptor = build_request(&request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->agent_handle == request.agent.handle &&
			payload->agent_generation == request.agent.generation &&
			!descriptor->thread_handle &&
			!payload->thread_generation,
			"TASK_CREATE carries the exact Agent identity");

	request = request_for(NACC_RUNTIME_TASK_ATTACH_OPCODE);
	descriptor = build_request(&request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->agent_handle == request.agent.handle &&
			descriptor->mm_handle == request.mm.handle &&
			descriptor->thread_handle == request.thread.handle &&
			payload->agent_generation == request.agent.generation &&
			payload->mm_generation == request.mm.generation &&
			payload->thread_generation == request.thread.generation,
			"TASK_ATTACH carries all three exact identities");

	request = request_for(NACC_RUNTIME_AGENT_RETIRE_OPCODE);
	descriptor = build_request(&request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->agent_handle == request.agent.handle &&
			!descriptor->mm_handle && !descriptor->thread_handle &&
			payload->agent_generation == request.agent.generation &&
			!payload->mm_generation && !payload->thread_generation,
			"AGENT_RETIRE carries the exact Agent identity");

	request = request_for(NACC_RUNTIME_MM_RETIRE_OPCODE);
	descriptor = build_request(&request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->agent_handle == request.agent.handle &&
			descriptor->mm_handle == request.mm.handle &&
			!descriptor->thread_handle &&
			payload->agent_generation == request.agent.generation &&
			payload->mm_generation == request.mm.generation &&
			!payload->thread_generation,
			"MM_RETIRE carries the exact Agent and mm identities");

	request = request_for(NACC_RUNTIME_TASK_RETIRE_OPCODE);
	descriptor = build_request(&request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->agent_handle == request.agent.handle &&
			!descriptor->mm_handle &&
			descriptor->thread_handle == request.thread.handle &&
			payload->agent_generation == request.agent.generation &&
			!payload->mm_generation &&
			payload->thread_generation == request.thread.generation,
			"unattached TASK_RETIRE carries a zero mm identity");
	request.mm = object_ref(2);
	descriptor = build_request(&request);
	payload = (void *)(mailbox + descriptor->payload_offset);
	report_contract(descriptor->mm_handle == request.mm.handle &&
			payload->mm_generation == request.mm.generation,
			"attached TASK_RETIRE carries the exact mm identity");

	memcpy(saved, mailbox, sizeof(saved));
	request.thread.generation = 0;
	report_contract(nacc_runtime_lifecycle_message_build(
				mailbox, sizeof(mailbox), &request) == -EINVAL &&
			!memcmp(saved, mailbox, sizeof(saved)),
			"partial identity fails without changing mailbox");
	request = request_for(NACC_RUNTIME_TASK_RETIRE_OPCODE);
	request.mm.handle = 2;
	memcpy(saved, mailbox, sizeof(saved));
	report_contract(nacc_runtime_lifecycle_message_build(
				mailbox, sizeof(mailbox), &request) == -EINVAL &&
			!memcmp(saved, mailbox, sizeof(saved)),
			"partial retire mm identity fails without changing mailbox");

	request = request_for(NACC_RUNTIME_AGENT_CREATE_OPCODE);
	memcpy(mailbox, &request, sizeof(request));
	memcpy(saved, mailbox, sizeof(saved));
	report_contract(nacc_runtime_lifecycle_message_build(
				mailbox, sizeof(mailbox), (void *)mailbox) ==
				-EINVAL &&
			!memcmp(saved, mailbox, sizeof(saved)),
			"request cannot alias the mailbox");

	request = request_for(NACC_RUNTIME_AGENT_CREATE_OPCODE);
	request.sequence = 0;
	report_contract(nacc_runtime_lifecycle_message_build(
				mailbox, sizeof(mailbox), &request) == -EINVAL,
			"zero request sequence is rejected");
}

static void test_success_responses(void)
{
	struct nacc_runtime_lifecycle_request request;
	struct nacc_runtime_lifecycle_result result;
	struct nacc_runtime_mailbox_descriptor *descriptor;

	request = request_for(NACC_RUNTIME_AGENT_CREATE_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = 9;
	descriptor->object_generation = 109;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.agent.handle == 9 &&
			result.agent.generation == 109,
			"AGENT_CREATE response returns a new Agent identity");

	request = request_for(NACC_RUNTIME_MM_CREATE_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->mm_handle = 10;
	descriptor->object_generation = 110;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.agent.generation == request.agent.generation &&
			result.mm.handle == 10 && result.mm.generation == 110,
			"MM_CREATE response preserves Agent and returns mm");

	request = request_for(NACC_RUNTIME_TASK_CREATE_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->thread_handle = 11;
	descriptor->object_generation = 111;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.thread.handle == 11 &&
			result.thread.generation == 111,
			"TASK_CREATE response returns a new task identity");

	request = request_for(NACC_RUNTIME_TASK_ATTACH_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->mm_handle = request.mm.handle;
	descriptor->thread_handle = request.thread.handle;
	descriptor->object_generation = request.thread.generation;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.mm.generation == request.mm.generation &&
			result.thread.generation == request.thread.generation,
			"TASK_ATTACH response confirms the exact task generation");

	request = request_for(NACC_RUNTIME_AGENT_RETIRE_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->object_generation = request.agent.generation;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.agent.handle == request.agent.handle &&
			result.agent.generation == request.agent.generation &&
			!result.mm.handle && !result.thread.handle,
			"AGENT_RETIRE response confirms the retired Agent");

	request = request_for(NACC_RUNTIME_MM_RETIRE_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->mm_handle = request.mm.handle;
	descriptor->object_generation = request.mm.generation;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.mm.handle == request.mm.handle &&
			result.mm.generation == request.mm.generation,
			"MM_RETIRE response confirms the retired mm");

	request = request_for(NACC_RUNTIME_TASK_RETIRE_OPCODE);
	request.mm = object_ref(2);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->mm_handle = request.mm.handle;
	descriptor->thread_handle = request.thread.handle;
	descriptor->object_generation = request.thread.generation;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.mm.generation == request.mm.generation &&
			result.thread.generation == request.thread.generation,
			"TASK_RETIRE response confirms the retired task");
	request.mm = (struct nacc_runtime_object_ref) { 0 };
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->thread_handle = request.thread.handle;
	descriptor->object_generation = request.thread.generation;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			!result.mm.handle && !result.mm.generation &&
			result.thread.generation == request.thread.generation,
			"unattached TASK_RETIRE response keeps mm identity zero");

	request = request_for(NACC_RUNTIME_MM_CREATE_OPCODE);
	descriptor = build_response(&request);
	descriptor->status = NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY;
	descriptor->agent_handle = 0;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) &&
			result.status == NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY &&
			!result.agent.handle && !result.mm.handle,
			"capacity response keeps every identity zero");
}

static void test_response_rejection(void)
{
	struct nacc_runtime_lifecycle_request request =
		request_for(NACC_RUNTIME_AGENT_CREATE_OPCODE);
	struct nacc_runtime_lifecycle_result result;
	struct nacc_runtime_lifecycle_result sentinel;
	struct nacc_runtime_mailbox_descriptor *descriptor;

#define EXPECT_PROTOCOL_FAILURE(mutation, description)                         \
	do {                                                                     \
		descriptor = build_response(&request);                            \
		descriptor->agent_handle = 9;                                     \
		descriptor->object_generation = 109;                              \
		mutation;                                                          \
		memset(&result, 0x5a, sizeof(result));                             \
		sentinel = result;                                                 \
		report_contract(nacc_runtime_lifecycle_response_validate(          \
				mailbox, sizeof(mailbox), &request, &result) ==       \
				-EPROTO &&                                          \
			!memcmp(&result, &sentinel, sizeof(result)), description);       \
	} while (0)

	EXPECT_PROTOCOL_FAILURE(descriptor->sequence++,
				"wrong response sequence is rejected atomically");
	EXPECT_PROTOCOL_FAILURE(descriptor->header.abi_minor = 2,
				"pre-1.3 lifecycle response is rejected");
	EXPECT_PROTOCOL_FAILURE(
		descriptor->header.features &=
			~NACC_RUNTIME_FEATURE_LIFECYCLE_CREATE_ATTACH,
		"missing lifecycle feature is rejected");
	EXPECT_PROTOCOL_FAILURE(descriptor->header.features |= 1ULL << 63,
				"unknown response feature is rejected");
	EXPECT_PROTOCOL_FAILURE(descriptor->header.reserved[0] = 1,
				"nonzero header reserved word is rejected");
	EXPECT_PROTOCOL_FAILURE(descriptor->reserved[0] = 1,
				"nonzero descriptor reserved word is rejected");
	EXPECT_PROTOCOL_FAILURE(descriptor->object_generation = 0,
				"zero success generation is rejected");
	EXPECT_PROTOCOL_FAILURE(descriptor->status = -2,
				"unknown lifecycle status is rejected");
	EXPECT_PROTOCOL_FAILURE(descriptor->payload_length = 1,
				"response payload is rejected");

	descriptor = build_response(&request);
	descriptor->agent_handle = 9;
	descriptor->object_generation = 109;
	descriptor->header.abi_minor++;
	descriptor->header.struct_size += 8;
	descriptor->payload_offset = descriptor->header.struct_size;
	report_contract(!nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result),
			"future minor appended descriptor remains compatible");

	request = request_for(NACC_RUNTIME_TASK_ATTACH_OPCODE);
	descriptor = build_response(&request);
	descriptor->status = NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY;
	descriptor->agent_handle = 0;
	descriptor->mm_handle = 0;
	descriptor->thread_handle = 0;
	report_contract(nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) ==
				-EPROTO,
			"TASK_ATTACH cannot report allocation capacity");

	request = request_for(NACC_RUNTIME_AGENT_RETIRE_OPCODE);
	descriptor = build_response(&request);
	descriptor->status = NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY;
	report_contract(nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) ==
				-EPROTO,
			"retire cannot report allocation capacity");

	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->object_generation = request.agent.generation + 1;
	memset(&result, 0x5a, sizeof(result));
	sentinel = result;
	report_contract(nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) ==
				-EPROTO &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"retire wrong target generation is rejected");

	request = request_for(NACC_RUNTIME_MM_RETIRE_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->mm_handle = request.mm.handle + 1;
	descriptor->object_generation = request.mm.generation;
	memset(&result, 0x5a, sizeof(result));
	sentinel = result;
	report_contract(nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) ==
				-EPROTO &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"retire wrong echoed handle is rejected atomically");

	request = request_for(NACC_RUNTIME_TASK_ATTACH_OPCODE);
	descriptor = build_response(&request);
	descriptor->agent_handle = request.agent.handle;
	descriptor->mm_handle = request.mm.handle;
	descriptor->thread_handle = request.thread.handle + 1;
	descriptor->object_generation = request.thread.generation;
	report_contract(nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request, &result) ==
				-EPROTO,
			"TASK_ATTACH wrong parent handle is rejected");

	descriptor->thread_handle = request.thread.handle;
	report_contract(nacc_runtime_lifecycle_response_validate(
				mailbox, sizeof(mailbox), &request,
				(void *)&request) == -EINVAL,
			"result cannot alias the expected request");
}

int main(void)
{
	printf("TAP version 13\n");
	test_request_builders();
	test_success_responses();
	test_response_rejection();
	printf("1..%d\n", test_number);
	return failed;
}
