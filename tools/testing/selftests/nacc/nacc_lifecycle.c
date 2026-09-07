// SPDX-License-Identifier: GPL-2.0-only
/* NACC Agent aggregate 与 per-exec transaction pure core contract test。 */

#include <errno.h>
#include <stdint.h>

#include <linux/nacc_lifecycle.h>
#include "../kselftest.h"

#define COOKIE UINT64_C(0x91a2b3c4d5e6f701)
#define GENERATION UINT64_C(7)
#define TARGET_ONE UINT64_C(0xffffffc080004000)
#define TARGET_TWO UINT64_C(0xffffffc080008000)

static int failures;

static void check(int condition, const char *name)
{
	if (condition)
		ksft_test_result_pass("%s\n", name);
	else {
		ksft_test_result_fail("%s\n", name);
		failures++;
	}
}

static struct nacc_lifecycle_agent new_agent(void)
{
	struct nacc_lifecycle_agent agent = {};

	if (nacc_lifecycle_create(&agent, COOKIE, GENERATION))
		ksft_exit_fail_msg("cannot create lifecycle fixture\n");
	return agent;
}

static uint64_t prepare(struct nacc_lifecycle_agent *agent,
			struct nacc_lifecycle_exec *tx, uint64_t target)
{
	uint64_t value = 0;

	if (nacc_lifecycle_prepare(agent, tx, COOKIE, GENERATION,
				   target, &value))
		ksft_exit_fail_msg("cannot prepare lifecycle fixture\n");
	return value;
}

static void test_generation_and_create(void)
{
	struct nacc_lifecycle_generation source = {};
	struct nacc_lifecycle_generation exhausted = { .last = UINT64_MAX };
	struct nacc_lifecycle_agent agent = {};
	struct nacc_lifecycle_agent dirty = { .agent_cookie = 1 };
	uint64_t value = 0;

	check(!nacc_lifecycle_next_generation(&source, &value) && value == 1,
	      "generation source starts at one");
	check(!nacc_lifecycle_next_generation(&source, &value) && value == 2,
	      "generation source never reuses a value");
	check(nacc_lifecycle_next_generation(&exhausted, &value) == -EOVERFLOW,
	      "generation wrap fails closed");
	check(nacc_lifecycle_create(NULL, COOKIE, GENERATION) == -EINVAL,
	      "CREATE rejects a NULL object");
	check(nacc_lifecycle_create(&dirty, COOKIE, GENERATION) == -EINVAL,
	      "CREATE rejects dirty storage");
	check(!nacc_lifecycle_create(&agent, COOKIE, GENERATION) &&
	      nacc_lifecycle_query_status(&agent) ==
		      NACC_LIFECYCLE_AGENT_CREATED,
	      "CREATE publishes a queryable Agent identity");
	check(nacc_lifecycle_create(&agent, COOKIE, GENERATION) == -EALREADY,
	      "CREATE cannot reuse a live object");
}

static void test_rollback_and_reprepare(void)
{
	struct nacc_lifecycle_agent agent = new_agent();
	struct nacc_lifecycle_exec tx = {};
	uint64_t first = 0, second = 0;

	check(nacc_lifecycle_prepare(&agent, &tx, COOKIE, GENERATION + 1,
				     TARGET_ONE, &first) == -ESTALE,
	      "PREPARE rejects a stale Agent generation");
	check(!nacc_lifecycle_prepare(&agent, &tx, COOKIE, GENERATION,
				      TARGET_ONE, &first) && first == 1 &&
	      agent.prepared_count == 1 && agent.transaction_count == 1,
	      "PREPARE allocates a one-shot generation");
	check(nacc_lifecycle_prepare(&agent, &tx, COOKIE, GENERATION,
				     TARGET_TWO, &second) == -EBUSY,
	      "PREPARE cannot replace a live transaction");
	check(nacc_lifecycle_abort_prepare(&agent, &tx, TARGET_ONE,
					   first + 1) == -ESTALE,
	      "rollback rejects a stale prepare generation");
	check(!nacc_lifecycle_abort_prepare(&agent, &tx, TARGET_ONE, first) &&
	      !agent.prepared_count && !agent.transaction_count &&
	      tx.state == NACC_LIFECYCLE_EXEC_EMPTY,
	      "pre-PONR failure rolls back instead of failing the Agent");
	check(!nacc_lifecycle_prepare(&agent, &tx, COOKIE, GENERATION,
				      TARGET_ONE, &second) && second > first,
	      "fresh reprepare cannot replay the aborted capability");
}

static void test_multiple_transactions_and_destroy(void)
{
	struct nacc_lifecycle_agent agent = new_agent();
	struct nacc_lifecycle_agent other = {};
	struct nacc_lifecycle_exec first = {}, second = {};
	uint64_t first_gen = prepare(&agent, &first, TARGET_ONE);
	uint64_t second_gen = prepare(&agent, &second, TARGET_TWO);

	if (nacc_lifecycle_create(&other, COOKIE + 1, GENERATION + 1))
		ksft_exit_fail_msg("cannot create second Agent fixture\n");

	check(agent.transaction_count == 2 && agent.prepared_count == 2 &&
	      nacc_lifecycle_query_status(&agent) == 2,
	      "Agent aggregate tracks multiple prepared transactions");
	check(!nacc_lifecycle_activate(&agent, &first, TARGET_ONE, first_gen) &&
	      agent.active_count == 1 && agent.prepared_count == 1 &&
	      nacc_lifecycle_query_status(&agent) == 3,
	      "one transaction activates without consuming another");
	check(nacc_lifecycle_abort_prepare(&other, &second, TARGET_TWO,
					   second_gen) == -ESTALE,
	      "transaction cannot be consumed through another Agent");
	check(!nacc_lifecycle_begin_destroy(&agent, COOKIE, GENERATION) &&
	      nacc_lifecycle_query_status(&agent) ==
		      NACC_LIFECYCLE_AGENT_DESTROYING,
	      "destroy closes the new-transaction gate before drain");
	{
		struct nacc_lifecycle_exec third = {};
		uint64_t third_generation = 0;

		check(nacc_lifecycle_prepare(&agent, &third, COOKIE, GENERATION,
					     TARGET_ONE, &third_generation) ==
		      -ESHUTDOWN,
		      "DESTROYING rejects new prepare transactions");
	}
	check(!nacc_lifecycle_abort_prepare(&agent, &second, TARGET_TWO,
					    second_gen),
	      "prepared target early exit rolls back independently");
	check(nacc_lifecycle_target_exited(&agent, &first, TARGET_ONE,
					   first_gen + 1) == -ESTALE,
	      "terminal event rejects a stale prepare generation");
	check(!nacc_lifecycle_target_exited(&agent, &first, TARGET_ONE,
					    first_gen) &&
	      first.state == NACC_LIFECYCLE_EXEC_EXITED &&
	      !agent.active_count && agent.transaction_count == 1,
	      "active target exit becomes a retireable transaction");
	check(nacc_lifecycle_finish_destroy(&agent) == -EBUSY,
	      "destroy cannot finish before terminal transaction retirement");
	check(nacc_lifecycle_retire_exec(&other, &first, TARGET_ONE,
					 first_gen) == -ESTALE,
	      "terminal transaction cannot retire through another Agent");
	check(nacc_lifecycle_retire_exec(&agent, &first, TARGET_ONE,
					 first_gen + 1) == -ESTALE,
	      "retirement rejects a stale prepare generation");
	check(!nacc_lifecycle_retire_exec(&agent, &first, TARGET_ONE,
					  first_gen) &&
	      !agent.transaction_count,
	      "transaction retirement releases its Agent reference");
	check(!nacc_lifecycle_finish_destroy(&agent) &&
	      nacc_lifecycle_query_status(&agent) == NACC_LIFECYCLE_AGENT_DEAD &&
	      agent.agent_cookie == COOKIE && agent.agent_generation == GENERATION,
	      "destroy reaches DEAD while preserving stale-replay identity");
	check(nacc_lifecycle_create(&agent, COOKIE, GENERATION) == -EALREADY,
	      "DEAD storage cannot replay the same Agent identity");
}

static void test_failure_scopes(void)
{
	struct nacc_lifecycle_agent agent = new_agent();
	struct nacc_lifecycle_exec tx = {};
	uint64_t generation = prepare(&agent, &tx, TARGET_ONE);

	if (nacc_lifecycle_activate(&agent, &tx, TARGET_ONE, generation))
		ksft_exit_fail_msg("cannot activate failure fixture\n");
	check(!nacc_lifecycle_target_failed_and_exited(
		       &agent, &tx, TARGET_ONE, generation, ENOEXEC) &&
	      tx.state == NACC_LIFECYCLE_EXEC_FAILED &&
	      tx.failure_errno == ENOEXEC && !agent.active_count,
	      "post-activation failure is transaction-local");
	check(nacc_lifecycle_query_status(&agent) ==
	      NACC_LIFECYCLE_AGENT_CREATED,
	      "one failed task does not relabel the Agent aggregate");
	check(!nacc_lifecycle_retire_exec(&agent, &tx, TARGET_ONE, generation),
	      "failed transaction can retire");
	check(!nacc_lifecycle_agent_fail(&agent, EIO) &&
	      nacc_lifecycle_query_status(&agent) ==
		      NACC_LIFECYCLE_AGENT_FAILED &&
	      agent.failure_errno == EIO,
	      "Agent-wide invariant failure has a distinct terminal state");
	check(nacc_lifecycle_prepare(&agent, &tx, COOKIE, GENERATION,
				     TARGET_ONE, &generation) == -ESHUTDOWN,
	      "FAILED Agent rejects new transactions");
	check(!nacc_lifecycle_begin_destroy(&agent, COOKIE, GENERATION),
	      "drained FAILED Agent can begin destroy");
	check(!nacc_lifecycle_finish_destroy(&agent) &&
	      nacc_lifecycle_query_status(&agent) == NACC_LIFECYCLE_AGENT_DEAD,
	      "FAILED Agent reaches DEAD only through destroy drain");
}

int main(void)
{
	ksft_print_header();
	ksft_set_plan(34);
	test_generation_and_create();
	test_rollback_and_reprepare();
	test_multiple_transactions_and_destroy();
	test_failure_scopes();
	ksft_finished();
	return failures ? KSFT_FAIL : KSFT_PASS;
}
