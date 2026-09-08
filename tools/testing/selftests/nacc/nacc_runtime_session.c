// SPDX-License-Identifier: GPL-2.0-only
#include <asm/nacc_runtime_session.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failed;
static int test_number;
static _Alignas(NACC_ENTER_MAILBOX_SIZE)
	uint8_t shared_mailbox[NACC_ENTER_MAILBOX_SIZE];

static void report_contract(int condition, const char *description)
{
	test_number++;
	if (!condition)
		failed = 1;
	printf("%s %d %s\n", condition ? "ok" : "not ok", test_number,
	       description);
}

static struct nacc_runtime_lifecycle_request agent_create(uint64_t sequence)
{
	return (struct nacc_runtime_lifecycle_request) {
		.opcode = NACC_RUNTIME_AGENT_CREATE_OPCODE,
		.sequence = sequence,
	};
}

static void build_success_response(
	const struct nacc_runtime_lifecycle_request *request)
{
	struct nacc_runtime_mailbox_descriptor *descriptor =
		(void *)shared_mailbox;

	if (nacc_runtime_lifecycle_message_build(
		    shared_mailbox, sizeof(shared_mailbox), request))
		return;
	descriptor->flags = NACC_RUNTIME_MAILBOX_FLAG_RESPONSE;
	descriptor->payload_length = 0;
	descriptor->agent_handle = 9;
	descriptor->object_generation = 109;
}

static void test_success_and_reuse(void)
{
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session session = {};
	struct nacc_runtime_lifecycle_request request = agent_create(17);
	struct nacc_runtime_lifecycle_result result = {};
	uint64_t reserved[5] = {};

	build_success_response(&request);
	report_contract(!nacc_linux_runtime_session_initialize(&session, 17),
			"session initializes with the first runtime sequence");
	report_contract(!nacc_linux_runtime_session_arm(&session, &request),
			"one lifecycle request becomes pending");
	request.opcode = 0xffff;
	report_contract(session.pending_request.opcode ==
			NACC_RUNTIME_AGENT_CREATE_OPCODE,
			"armed request is isolated from source mutation");
	request = agent_create(17);
	report_contract(!nacc_linux_runtime_session_response_capture(
			&session, shared_mailbox, sizeof(shared_mailbox),
			request.sequence,
			request.opcode, reserved),
			"matching completion captures the full mailbox page");
	memset(shared_mailbox, 0xa5, sizeof(shared_mailbox));
	report_contract(nacc_linux_runtime_session_complete(
			&session, request.sequence, (void *)&session) == -EINVAL &&
			session.state == NACC_RUNTIME_SESSION_CAPTURED,
			"result cannot alias session-owned state");
	report_contract(!nacc_linux_runtime_session_complete(
			&session, request.sequence, &result) &&
			result.agent.handle == 9 &&
			result.agent.generation == 109 &&
			session.next_sequence == 18 &&
			session.state == NACC_RUNTIME_SESSION_IDLE,
			"captured response survives slot reuse and advances sequence");
	report_contract(nacc_linux_runtime_session_complete(
			&session, request.sequence, &result) == -EALREADY,
			"duplicate completion cannot consume the next sequence");

	request = agent_create(18);
	report_contract(!nacc_linux_runtime_session_arm(&session, &request),
			"completed session accepts exactly the next sequence");
	build_success_response(&request);
	report_contract(nacc_linux_runtime_session_response_capture(
			&session, shared_mailbox, sizeof(shared_mailbox), 17,
			request.opcode, reserved) == -ESTALE &&
			session.state == NACC_RUNTIME_SESSION_PENDING,
			"stale completion cannot capture a reused session");
	report_contract(!nacc_linux_runtime_session_response_capture(
			&session, shared_mailbox, sizeof(shared_mailbox), 18,
			request.opcode, reserved) &&
			nacc_linux_runtime_session_complete(
				&session, 17, &result) == -ESTALE &&
			session.state == NACC_RUNTIME_SESSION_CAPTURED &&
			!nacc_linux_runtime_session_complete(
				&session, 18, &result) &&
			session.next_sequence == 19,
			"stale caller cannot consume a captured newer response");
}

static void test_rejections(void)
{
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session session = {};
	struct nacc_runtime_lifecycle_request request = agent_create(23);
	uint8_t sentinel[NACC_ENTER_MAILBOX_SIZE];
	uint64_t reserved[5] = {};
	struct nacc_runtime_lifecycle_request invalid = agent_create(23);

	memset(sentinel, 0, sizeof(sentinel));
	build_success_response(&request);
	report_contract(!nacc_linux_runtime_session_initialize(&session, 23) &&
			session.state == NACC_RUNTIME_SESSION_IDLE,
			"rejection fixture initializes idle");
	request.sequence = 22;
	report_contract(nacc_linux_runtime_session_arm(&session, &request) ==
			-ESTALE && session.state == NACC_RUNTIME_SESSION_IDLE,
			"stale request cannot occupy an idle session");
	request.sequence = 23;
	invalid.opcode = 0xffff;
	report_contract(nacc_linux_runtime_session_arm(&session, &invalid) ==
			-EINVAL && session.state == NACC_RUNTIME_SESSION_IDLE,
			"invalid lifecycle request cannot occupy the session");
	report_contract(nacc_linux_runtime_session_arm(
			&session, (const void *)&session) == -EINVAL &&
			session.state == NACC_RUNTIME_SESSION_IDLE,
			"request cannot alias session state");
	report_contract(!nacc_linux_runtime_session_arm(&session, &request),
			"rejection fixture reaches pending state");
	report_contract(nacc_linux_runtime_session_arm(&session, &request) ==
			-EBUSY,
			"a second pending request is rejected");
	report_contract(nacc_linux_runtime_session_response_capture(
			&session, shared_mailbox, sizeof(shared_mailbox), 22,
			request.opcode, reserved) == -ESTALE &&
			!memcmp(session.response_snapshot, sentinel,
				sizeof(sentinel)),
			"stale completion fails without changing snapshot");
	report_contract(!nacc_linux_runtime_session_response_capture(
			&session, shared_mailbox, sizeof(shared_mailbox), 23,
			request.opcode, reserved),
			"exact completion succeeds after rejected attempts");
	report_contract(nacc_linux_runtime_session_response_capture(
			&session, shared_mailbox, sizeof(shared_mailbox), 23,
			request.opcode, reserved) == -EALREADY,
			"duplicate completion is rejected");
}

static void test_protocol_failures(void)
{
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session future_session = {};
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session reserved_session = {};
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session opcode_session = {};
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session overflow_session = {};
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session future_arm_session = {};
	_Alignas(NACC_ENTER_MAILBOX_SIZE)
		struct nacc_linux_runtime_session future_complete_session = {};
	struct nacc_runtime_lifecycle_request request = agent_create(31);
	struct nacc_runtime_lifecycle_result result;
	struct nacc_runtime_lifecycle_result sentinel;
	uint64_t reserved[5] = {};

	request = agent_create(32);
	report_contract(!nacc_linux_runtime_session_initialize(
			&future_arm_session, 31) &&
			nacc_linux_runtime_session_arm(
				&future_arm_session, &request) == -EPROTO &&
			future_arm_session.state == NACC_RUNTIME_SESSION_FAILED,
			"future request makes the session fail closed");

	request = agent_create(31);
	build_success_response(&request);
	report_contract(!nacc_linux_runtime_session_initialize(
			&future_complete_session, 31) &&
			!nacc_linux_runtime_session_arm(
				&future_complete_session, &request) &&
			!nacc_linux_runtime_session_response_capture(
				&future_complete_session, shared_mailbox,
				sizeof(shared_mailbox), 31, request.opcode,
				reserved) &&
			nacc_linux_runtime_session_complete(
				&future_complete_session, 32, &result) ==
				-EPROTO &&
			future_complete_session.state ==
				NACC_RUNTIME_SESSION_FAILED,
			"future completion caller makes the session fail closed");

	build_success_response(&request);
	report_contract(!nacc_linux_runtime_session_initialize(
			&future_session, 31) &&
			!nacc_linux_runtime_session_arm(&future_session, &request) &&
			nacc_linux_runtime_session_response_capture(
				&future_session, shared_mailbox,
				sizeof(shared_mailbox), 32, request.opcode,
				reserved) == -EPROTO &&
			future_session.state == NACC_RUNTIME_SESSION_FAILED,
			"future completion makes the session fail closed");

	reserved[0] = 1;
	report_contract(!nacc_linux_runtime_session_initialize(
			&reserved_session, 31) &&
			!nacc_linux_runtime_session_arm(&reserved_session, &request) &&
			nacc_linux_runtime_session_response_capture(
				&reserved_session, shared_mailbox,
				sizeof(shared_mailbox), 31, request.opcode,
				reserved) == -EPROTO &&
			reserved_session.state == NACC_RUNTIME_SESSION_FAILED,
			"nonzero reserved register makes the session fail closed");

	reserved[0] = 0;
	build_success_response(&request);
	report_contract(!nacc_linux_runtime_session_initialize(
			&opcode_session, 31) &&
			!nacc_linux_runtime_session_arm(&opcode_session, &request) &&
			nacc_linux_runtime_session_response_capture(
				&opcode_session, shared_mailbox,
				sizeof(shared_mailbox), 31,
				(1ULL << 32) | request.opcode, reserved) ==
				-EPROTO &&
			opcode_session.state == NACC_RUNTIME_SESSION_FAILED,
			"high opcode bits make the session fail closed");

	request = agent_create(UINT64_MAX);
	build_success_response(&request);
	memset(&result, 0x5a, sizeof(result));
	sentinel = result;
	report_contract(!nacc_linux_runtime_session_initialize(
			&overflow_session, UINT64_MAX) &&
			!nacc_linux_runtime_session_arm(&overflow_session, &request) &&
			!nacc_linux_runtime_session_response_capture(
				&overflow_session, shared_mailbox,
				sizeof(shared_mailbox), UINT64_MAX,
				request.opcode, reserved) &&
			nacc_linux_runtime_session_complete(
				&overflow_session, UINT64_MAX, &result) ==
				-EOVERFLOW &&
			overflow_session.state == NACC_RUNTIME_SESSION_FAILED &&
			!memcmp(&result, &sentinel, sizeof(result)),
			"sequence overflow fails without publishing a result");
}

int main(void)
{
	printf("TAP version 13\n");
	test_success_and_reuse();
	test_rejections();
	test_protocol_failures();
	printf("1..%d\n", test_number);
	return failed;
}
