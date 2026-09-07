// SPDX-License-Identifier: GPL-2.0-only
/* NACC single-hart Linux bootstrap session pure core contract test。 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "../../../../arch/riscv/include/asm/nacc_bootstrap_session.h"
#include "../kselftest.h"

#define TEST_CONTEXT UINT64_C(0x0000000100003000)
#define TEST_SEQUENCE UINT64_C(7)
#define TEST_TP UINT64_C(0xffffffc080040000)
#define TEST_OLD_SATP UINT64_C(0x8000000000080000)
#define TEST_CONTROL_SATP UINT64_C(0x8000000000020005)
#define TEST_COOKIE UINT64_C(0x123456789abcdef0)

static void report_contract(bool condition, const char *name)
{
	if (condition)
		ksft_test_result_pass("%s\n", name);
	else
		ksft_test_result_fail("%s\n", name);
}

static int arm(struct nacc_linux_bootstrap_session *session)
{
	return nacc_linux_bootstrap_session_arm(
		session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
		TEST_OLD_SATP, TEST_CONTROL_SATP);
}

static struct nacc_linux_bootstrap_ready_request valid_ready(void)
{
	return (struct nacc_linux_bootstrap_ready_request) {
		.context_address = TEST_CONTEXT,
		.context_size = NACC_LINUX_FIRST_ENTRY_CONTEXT_SIZE,
		.bootstrap_sequence = TEST_SEQUENCE,
		.handshake_cookie = TEST_COOKIE,
		.current_thread_pointer = TEST_TP,
	};
}

static void test_arm_validation(void)
{
	struct nacc_linux_bootstrap_session session = {};
	struct nacc_linux_bootstrap_session dirty = { .reserved = 1 };
	int ret;

	report_contract(nacc_linux_bootstrap_session_arm(
			NULL, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			TEST_OLD_SATP, TEST_CONTROL_SATP) == -EINVAL,
			 "NULL session cannot be armed");
	ret = arm(&session);
	report_contract(!ret && session.state == NACC_LINUX_SESSION_ARMED &&
			 session.context_size == NACC_LINUX_FIRST_ENTRY_CONTEXT_SIZE,
			 "canonical session arms exactly once");
	report_contract(arm(&session) == -EALREADY,
			 "rearming a populated session is rejected");
	report_contract(nacc_linux_bootstrap_session_arm(
			&dirty, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			TEST_OLD_SATP, TEST_CONTROL_SATP) == -EINVAL &&
			 dirty.state == NACC_LINUX_SESSION_FAILED,
			 "reserved session state is rejected");

	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT + 1, TEST_SEQUENCE, TEST_TP,
			TEST_OLD_SATP, TEST_CONTROL_SATP) == -EINVAL,
			 "misaligned context is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, NACC_BOOTSTRAP_SV39_USER_LIMIT,
			TEST_SEQUENCE, TEST_TP, TEST_OLD_SATP,
			TEST_CONTROL_SATP) == -EINVAL,
			 "context outside the Sv39 user half is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, 0, TEST_TP, TEST_OLD_SATP,
			TEST_CONTROL_SATP) == -EINVAL,
			 "zero sequence is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_CONTEXT,
			TEST_OLD_SATP, TEST_CONTROL_SATP) == -EINVAL,
			 "non-kernel thread pointer is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP + 1,
			TEST_OLD_SATP, TEST_CONTROL_SATP) == -EINVAL,
			 "misaligned thread pointer is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			0, TEST_CONTROL_SATP) == -EINVAL,
			 "non-Sv39 old satp is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			NACC_LINUX_SESSION_SATP_MODE_SV39,
			TEST_CONTROL_SATP) == -EINVAL,
			 "old satp without a root PPN is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			TEST_OLD_SATP, NACC_LINUX_SESSION_SATP_MODE_SV39) ==
			-EINVAL,
			 "control satp without a root PPN is rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			TEST_OLD_SATP,
			NACC_LINUX_SESSION_SATP_MODE_SV39 | (1ULL << 44)) ==
			-EINVAL,
			 "control satp ASID cannot replace a root PPN");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			TEST_OLD_SATP, TEST_OLD_SATP) == -EINVAL,
			 "identical old and control roots are rejected");
	memset(&session, 0, sizeof(session));
	report_contract(nacc_linux_bootstrap_session_arm(
			&session, TEST_CONTEXT, TEST_SEQUENCE, TEST_TP,
			TEST_OLD_SATP, TEST_OLD_SATP ^ (1ULL << 44)) == -EINVAL,
			 "one root PPN with different ASIDs is rejected");
}

static void test_ready_validation(void)
{
	struct nacc_linux_bootstrap_session session = {};
	struct nacc_linux_bootstrap_ready_request request = valid_ready();
	struct nacc_linux_bootstrap_ready_request changed;
	int ret;

	ret = arm(&session);
	if (ret)
		ksft_exit_fail_msg("ready fixture arm failed: %d\n", ret);
	report_contract(nacc_linux_bootstrap_session_ready_validate(
			NULL, &request) == -EINVAL,
			 "READY validation rejects a NULL session");
	report_contract(nacc_linux_bootstrap_session_ready_validate(
			&session, NULL) == -EINVAL,
			 "READY validation rejects a NULL request");
	report_contract(!nacc_linux_bootstrap_session_ready_validate(
			&session, &request), "canonical READY request validates");

#define REJECT_CHANGED(_field, _value, _name) do { \
	changed = request; \
	changed._field = (_value); \
	report_contract(nacc_linux_bootstrap_session_ready_validate( \
			&session, &changed) == -EINVAL, (_name)); \
} while (0)
	REJECT_CHANGED(context_address, TEST_CONTEXT + NACC_BOOTSTRAP_PAGE_SIZE,
		       "READY context mismatch is rejected");
	REJECT_CHANGED(context_size, NACC_LINUX_FIRST_ENTRY_CONTEXT_SIZE - 8,
		       "READY context size mismatch is rejected");
	REJECT_CHANGED(bootstrap_sequence, TEST_SEQUENCE + 1,
		       "READY sequence mismatch is rejected");
	REJECT_CHANGED(handshake_cookie, 0,
		       "READY zero cookie is rejected");
	REJECT_CHANGED(current_thread_pointer, TEST_TP + 8,
		       "READY thread pointer mismatch is rejected");
	changed = request;
	changed.reserved[2] = 1;
	report_contract(nacc_linux_bootstrap_session_ready_validate(
			&session, &changed) == -EINVAL,
			 "READY reserved arguments are rejected");
#undef REJECT_CHANGED

	ret = nacc_linux_bootstrap_session_ready_commit(&session, &request);
	report_contract(!ret &&
			nacc_linux_bootstrap_session_is_ready(&session) &&
			session.handshake_cookie == TEST_COOKIE,
			 "valid READY commits the immutable cookie");
	report_contract(nacc_linux_bootstrap_session_ready_commit(
			&session, &request) == -EALREADY,
			 "duplicate READY is rejected");
	report_contract(nacc_linux_bootstrap_session_fail(&session) == -EALREADY,
			 "READY session cannot transition to failed");
}

static void test_failure_transition(void)
{
	struct nacc_linux_bootstrap_session session = {};
	struct nacc_linux_bootstrap_ready_request request = valid_ready();
	int ret;

	ret = arm(&session);
	if (ret)
		ksft_exit_fail_msg("failure fixture arm failed: %d\n", ret);
	report_contract(nacc_linux_bootstrap_session_fail(NULL) == -EINVAL,
			 "failure transition rejects a NULL session");
	ret = nacc_linux_bootstrap_session_fail(&session);
	report_contract(!ret && session.state == NACC_LINUX_SESSION_FAILED &&
			 !nacc_linux_bootstrap_session_is_ready(&session),
			 "armed session has one sticky failure transition");
	report_contract(nacc_linux_bootstrap_session_fail(&session) == -EALREADY,
			 "failed session cannot fail twice");
	report_contract(nacc_linux_bootstrap_session_ready_commit(
			&session, &request) == -EALREADY,
			 "failed session cannot accept READY");
}

int main(void)
{
	ksft_print_header();
	ksft_set_plan(32);
	report_contract(!nacc_linux_bootstrap_session_is_ready(NULL),
			 "NULL session is never READY");
	test_arm_validation();
	test_ready_validation();
	test_failure_transition();
	ksft_finished();
}
