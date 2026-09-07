/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC Agent aggregate 与 per-exec transaction 的内部 lifecycle 契约。 */
#ifndef _LINUX_NACC_LIFECYCLE_H
#define _LINUX_NACC_LIFECYCLE_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u32 nacc_lifecycle_u32;
typedef u64 nacc_lifecycle_u64;
#else
#include <stdint.h>
typedef uint32_t nacc_lifecycle_u32;
typedef uint64_t nacc_lifecycle_u64;
#endif

/* 数值与 UAPI enum nacc_agent_status 保持一致。 */
enum nacc_lifecycle_agent_state {
	NACC_LIFECYCLE_AGENT_EMPTY = 0,
	NACC_LIFECYCLE_AGENT_CREATED = 1,
	NACC_LIFECYCLE_AGENT_PREPARED = 2,
	NACC_LIFECYCLE_AGENT_ACTIVE = 3,
	NACC_LIFECYCLE_AGENT_DESTROYING = 4,
	NACC_LIFECYCLE_AGENT_DEAD = 5,
	NACC_LIFECYCLE_AGENT_FAILED = 6,
};

enum nacc_lifecycle_exec_state {
	NACC_LIFECYCLE_EXEC_EMPTY = 0,
	NACC_LIFECYCLE_EXEC_PREPARED,
	NACC_LIFECYCLE_EXEC_COMMITTED,
	NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED,
	NACC_LIFECYCLE_EXEC_ACTIVE,
	NACC_LIFECYCLE_EXEC_EXITED,
	NACC_LIFECYCLE_EXEC_FAILED,
};

struct nacc_lifecycle_generation {
	nacc_lifecycle_u64 last;
};

struct nacc_lifecycle_agent {
	nacc_lifecycle_u32 state;
	int failure_errno;
	nacc_lifecycle_u64 agent_cookie;
	nacc_lifecycle_u64 agent_generation;
	nacc_lifecycle_u64 last_prepare_generation;
	nacc_lifecycle_u32 transaction_count;
	nacc_lifecycle_u32 prepared_count;
	nacc_lifecycle_u32 committed_count;
	nacc_lifecycle_u32 active_count;
};

/* target_identity 代表持有引用的 kernel task identity，不是 numeric PID。 */
struct nacc_lifecycle_exec {
	nacc_lifecycle_u32 state;
	int failure_errno;
	nacc_lifecycle_u64 agent_cookie;
	nacc_lifecycle_u64 agent_generation;
	nacc_lifecycle_u64 target_identity;
	nacc_lifecycle_u64 prepare_generation;
};

int nacc_lifecycle_next_generation(struct nacc_lifecycle_generation *source,
				   nacc_lifecycle_u64 *generation);
int nacc_lifecycle_create(struct nacc_lifecycle_agent *agent,
			  nacc_lifecycle_u64 agent_cookie,
			  nacc_lifecycle_u64 agent_generation);
int nacc_lifecycle_prepare(struct nacc_lifecycle_agent *agent,
			   struct nacc_lifecycle_exec *transaction,
			   nacc_lifecycle_u64 agent_cookie,
			   nacc_lifecycle_u64 agent_generation,
			   nacc_lifecycle_u64 target_identity,
			   nacc_lifecycle_u64 *prepare_generation);
int nacc_lifecycle_abort_prepare(struct nacc_lifecycle_agent *agent,
				 struct nacc_lifecycle_exec *transaction,
				 nacc_lifecycle_u64 target_identity,
				 nacc_lifecycle_u64 prepare_generation);
int nacc_lifecycle_commit_exec(struct nacc_lifecycle_agent *agent,
			       struct nacc_lifecycle_exec *transaction,
			       nacc_lifecycle_u64 target_identity,
			       nacc_lifecycle_u64 prepare_generation);
int nacc_lifecycle_commit_reexec(struct nacc_lifecycle_agent *agent,
				 struct nacc_lifecycle_exec *transaction,
				 nacc_lifecycle_u64 target_identity,
				 nacc_lifecycle_u64 *prepare_generation);
int nacc_lifecycle_activate_reexec(struct nacc_lifecycle_agent *agent,
				   struct nacc_lifecycle_exec *transaction,
				   nacc_lifecycle_u64 target_identity,
				   nacc_lifecycle_u64 prepare_generation);
int nacc_lifecycle_activate(struct nacc_lifecycle_agent *agent,
			    struct nacc_lifecycle_exec *transaction,
			    nacc_lifecycle_u64 target_identity,
			    nacc_lifecycle_u64 prepare_generation);
int nacc_lifecycle_target_failed_and_exited(
	struct nacc_lifecycle_agent *agent,
	struct nacc_lifecycle_exec *transaction,
	nacc_lifecycle_u64 target_identity,
	nacc_lifecycle_u64 prepare_generation, int failure_errno);
int nacc_lifecycle_target_exited(struct nacc_lifecycle_agent *agent,
				 struct nacc_lifecycle_exec *transaction,
				 nacc_lifecycle_u64 target_identity,
				 nacc_lifecycle_u64 prepare_generation);
int nacc_lifecycle_retire_exec(struct nacc_lifecycle_agent *agent,
			       struct nacc_lifecycle_exec *transaction,
			       nacc_lifecycle_u64 target_identity,
			       nacc_lifecycle_u64 prepare_generation);
int nacc_lifecycle_begin_destroy(struct nacc_lifecycle_agent *agent,
				 nacc_lifecycle_u64 agent_cookie,
				 nacc_lifecycle_u64 agent_generation);
int nacc_lifecycle_finish_destroy(struct nacc_lifecycle_agent *agent);
int nacc_lifecycle_agent_fail(struct nacc_lifecycle_agent *agent,
			      int failure_errno);
nacc_lifecycle_u32
nacc_lifecycle_query_status(const struct nacc_lifecycle_agent *agent);

#endif /* _LINUX_NACC_LIFECYCLE_H */
