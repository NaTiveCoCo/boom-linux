// SPDX-License-Identifier: GPL-2.0-only
/* NACC lifecycle 的 host-buildable pure core；调用方串行化同一对象。 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <stddef.h>
#include <string.h>
#endif

#include <linux/nacc_lifecycle.h>

static int nacc_lifecycle_match_agent(const struct nacc_lifecycle_agent *agent,
	nacc_lifecycle_u64 cookie, nacc_lifecycle_u64 generation)
{
	if (!agent || !cookie || !generation)
		return -EINVAL;
	if (agent->state == NACC_LIFECYCLE_AGENT_EMPTY)
		return -ENOENT;
	if (agent->agent_cookie != cookie || agent->agent_generation != generation)
		return -ESTALE;
	return 0;
}

static int nacc_lifecycle_match_exec_owner(
	const struct nacc_lifecycle_agent *agent,
	const struct nacc_lifecycle_exec *tx)
{
	if (!agent || !tx)
		return -EINVAL;
	if (tx->agent_cookie != agent->agent_cookie ||
	    tx->agent_generation != agent->agent_generation)
		return -ESTALE;
	return 0;
}

static int nacc_lifecycle_match_exec(const struct nacc_lifecycle_agent *agent,
	const struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 generation)
{
	int ret = nacc_lifecycle_match_exec_owner(agent, tx);

	if (ret)
		return ret;
	if (!target || !generation)
		return -EINVAL;
	if (tx->target_identity != target || tx->prepare_generation != generation)
		return -ESTALE;
	return 0;
}

int nacc_lifecycle_next_generation(struct nacc_lifecycle_generation *source,
				   nacc_lifecycle_u64 *generation)
{
	if (!source || !generation)
		return -EINVAL;
	if (source->last == ~(nacc_lifecycle_u64)0)
		return -EOVERFLOW;
	source->last++;
	*generation = source->last;
	return 0;
}

int nacc_lifecycle_create(struct nacc_lifecycle_agent *agent,
	nacc_lifecycle_u64 cookie, nacc_lifecycle_u64 generation)
{
	if (!agent || !cookie || !generation)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_EMPTY)
		return -EALREADY;
	if (agent->failure_errno || agent->agent_cookie || agent->agent_generation ||
	    agent->last_prepare_generation || agent->transaction_count ||
	    agent->prepared_count || agent->committed_count || agent->active_count)
		return -EINVAL;
	agent->agent_cookie = cookie;
	agent->agent_generation = generation;
	agent->state = NACC_LIFECYCLE_AGENT_CREATED;
	return 0;
}

int nacc_lifecycle_prepare(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 cookie,
	nacc_lifecycle_u64 generation, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 *prepare_generation)
{
	int ret = nacc_lifecycle_match_agent(agent, cookie, generation);

	if (ret)
		return ret;
	if (!tx || !target || !prepare_generation)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED)
		return -ESHUTDOWN;
	if (tx->state != NACC_LIFECYCLE_EXEC_EMPTY)
		return -EBUSY;
	if (tx->failure_errno || tx->agent_cookie || tx->agent_generation ||
	    tx->target_identity || tx->prepare_generation)
		return -EINVAL;
	if (agent->last_prepare_generation == ~(nacc_lifecycle_u64)0 ||
	    agent->transaction_count == ~(nacc_lifecycle_u32)0 ||
	    agent->prepared_count == ~(nacc_lifecycle_u32)0)
		return -EOVERFLOW;
	agent->last_prepare_generation++;
	tx->agent_cookie = cookie;
	tx->agent_generation = generation;
	tx->target_identity = target;
	tx->prepare_generation = agent->last_prepare_generation;
	tx->state = NACC_LIFECYCLE_EXEC_PREPARED;
	agent->transaction_count++;
	agent->prepared_count++;
	*prepare_generation = tx->prepare_generation;
	return 0;
}

int nacc_lifecycle_abort_prepare(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 generation)
{
	int ret;

	if (!agent || !tx)
		return -EINVAL;
	if (tx->state != NACC_LIFECYCLE_EXEC_PREPARED)
		return -EALREADY;
	ret = nacc_lifecycle_match_exec(agent, tx, target, generation);
	if (ret)
		return ret;
	if (!agent->transaction_count || !agent->prepared_count)
		return -EINVAL;
	agent->transaction_count--;
	agent->prepared_count--;
	memset(tx, 0, sizeof(*tx));
	return 0;
}

int nacc_lifecycle_activate(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 generation)
{
	int ret;

	if (!agent || !tx)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED &&
	    agent->state != NACC_LIFECYCLE_AGENT_DESTROYING)
		return -ESHUTDOWN;
	if (tx->state != NACC_LIFECYCLE_EXEC_COMMITTED)
		return -EALREADY;
	ret = nacc_lifecycle_match_exec(agent, tx, target, generation);
	if (ret)
		return ret;
	if (!agent->committed_count ||
	    agent->active_count == ~(nacc_lifecycle_u32)0)
		return -EINVAL;
	agent->committed_count--;
	agent->active_count++;
	tx->state = NACC_LIFECYCLE_EXEC_ACTIVE;
	return 0;
}

int nacc_lifecycle_commit_exec(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 generation)
{
	int ret;

	if (!agent || !tx)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED)
		return -ESHUTDOWN;
	if (tx->state != NACC_LIFECYCLE_EXEC_PREPARED)
		return -EALREADY;
	ret = nacc_lifecycle_match_exec(agent, tx, target, generation);
	if (ret)
		return ret;
	if (!agent->prepared_count ||
	    agent->committed_count == ~(nacc_lifecycle_u32)0)
		return -EINVAL;
	agent->prepared_count--;
	agent->committed_count++;
	tx->state = NACC_LIFECYCLE_EXEC_COMMITTED;
	return 0;
}

int nacc_lifecycle_commit_reexec(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 *prepare_generation)
{
	int ret;

	if (!agent || !tx || !target || !prepare_generation)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED)
		return -ESHUTDOWN;
	if (tx->state != NACC_LIFECYCLE_EXEC_ACTIVE)
		return -EALREADY;
	ret = nacc_lifecycle_match_exec_owner(agent, tx);
	if (ret)
		return ret;
	if (tx->target_identity != target)
		return -ESTALE;
	if (!agent->active_count || tx->failure_errno ||
	    agent->last_prepare_generation < tx->prepare_generation)
		return -EINVAL;
	if (agent->last_prepare_generation == ~(nacc_lifecycle_u64)0)
		return -EOVERFLOW;
	agent->last_prepare_generation++;
	tx->prepare_generation = agent->last_prepare_generation;
	tx->state = NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED;
	*prepare_generation = tx->prepare_generation;
	return 0;
}

int nacc_lifecycle_activate_reexec(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 generation)
{
	int ret;

	if (!agent || !tx)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED &&
	    agent->state != NACC_LIFECYCLE_AGENT_DESTROYING)
		return -ESHUTDOWN;
	if (tx->state != NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED)
		return -EALREADY;
	ret = nacc_lifecycle_match_exec(agent, tx, target, generation);
	if (ret)
		return ret;
	if (!agent->active_count || tx->failure_errno)
		return -EINVAL;
	tx->state = NACC_LIFECYCLE_EXEC_ACTIVE;
	return 0;
}

int nacc_lifecycle_target_failed_and_exited(
	struct nacc_lifecycle_agent *agent, struct nacc_lifecycle_exec *tx,
	nacc_lifecycle_u64 target, nacc_lifecycle_u64 generation,
	int failure_errno)
{
	int ret;

	if (!agent || !tx || !target || failure_errno <= 0)
		return -EINVAL;
	if (tx->state != NACC_LIFECYCLE_EXEC_COMMITTED &&
	    tx->state != NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED &&
	    tx->state != NACC_LIFECYCLE_EXEC_ACTIVE)
		return -EALREADY;
	ret = nacc_lifecycle_match_exec(agent, tx, target, generation);
	if (ret)
		return ret;
	if (tx->state == NACC_LIFECYCLE_EXEC_COMMITTED) {
		if (!agent->committed_count)
			return -EINVAL;
		agent->committed_count--;
	} else {
		if (!agent->active_count)
			return -EINVAL;
		agent->active_count--;
	}
	tx->failure_errno = failure_errno;
	tx->state = NACC_LIFECYCLE_EXEC_FAILED;
	return 0;
}

int nacc_lifecycle_target_exited(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 generation)
{
	int ret;

	if (!agent || !tx || !target)
		return -EINVAL;
	if (tx->state != NACC_LIFECYCLE_EXEC_ACTIVE)
		return -EALREADY;
	ret = nacc_lifecycle_match_exec(agent, tx, target, generation);
	if (ret)
		return ret;
	if (!agent->active_count)
		return -EINVAL;
	agent->active_count--;
	tx->state = NACC_LIFECYCLE_EXEC_EXITED;
	return 0;
}

int nacc_lifecycle_retire_exec(struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *tx, nacc_lifecycle_u64 target,
	nacc_lifecycle_u64 generation)
{
	int ret;

	if (!agent || !tx)
		return -EINVAL;
	if (tx->state != NACC_LIFECYCLE_EXEC_EXITED &&
	    tx->state != NACC_LIFECYCLE_EXEC_FAILED)
		return -EBUSY;
	ret = nacc_lifecycle_match_exec(agent, tx, target, generation);
	if (ret)
		return ret;
	if (!agent->transaction_count)
		return -EINVAL;
	agent->transaction_count--;
	memset(tx, 0, sizeof(*tx));
	return 0;
}

int nacc_lifecycle_begin_destroy(struct nacc_lifecycle_agent *agent,
	nacc_lifecycle_u64 cookie, nacc_lifecycle_u64 generation)
{
	int ret = nacc_lifecycle_match_agent(agent, cookie, generation);

	if (ret)
		return ret;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED &&
	    agent->state != NACC_LIFECYCLE_AGENT_FAILED)
		return -EALREADY;
	agent->state = NACC_LIFECYCLE_AGENT_DESTROYING;
	return 0;
}

int nacc_lifecycle_finish_destroy(struct nacc_lifecycle_agent *agent)
{
	if (!agent)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_DESTROYING)
		return -EALREADY;
	if (agent->transaction_count || agent->prepared_count ||
	    agent->committed_count || agent->active_count)
		return -EBUSY;
	agent->state = NACC_LIFECYCLE_AGENT_DEAD;
	return 0;
}

int nacc_lifecycle_agent_fail(struct nacc_lifecycle_agent *agent,
	int failure_errno)
{
	if (!agent || failure_errno <= 0)
		return -EINVAL;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED)
		return -EALREADY;
	agent->failure_errno = failure_errno;
	agent->state = NACC_LIFECYCLE_AGENT_FAILED;
	return 0;
}

nacc_lifecycle_u32
nacc_lifecycle_query_status(const struct nacc_lifecycle_agent *agent)
{
	if (!agent)
		return NACC_LIFECYCLE_AGENT_EMPTY;
	if (agent->state != NACC_LIFECYCLE_AGENT_CREATED)
		return agent->state;
	if (agent->active_count)
		return NACC_LIFECYCLE_AGENT_ACTIVE;
	if (agent->prepared_count || agent->committed_count)
		return NACC_LIFECYCLE_AGENT_PREPARED;
	return NACC_LIFECYCLE_AGENT_CREATED;
}
