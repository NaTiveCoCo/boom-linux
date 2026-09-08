/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC exec 与 task exit lifecycle hooks。 */
#ifndef _LINUX_NACC_EXEC_H
#define _LINUX_NACC_EXEC_H

#include <linux/types.h>

struct file;
struct nacc_prepare_object;

struct nacc_exec_attempt {
	struct nacc_prepare_object *prepare;
	u64 prepare_generation;
	bool captured;
};

#ifdef CONFIG_NACC
void nacc_exec_attempt_begin(struct nacc_exec_attempt *attempt);
void nacc_exec_attempt_release(struct nacc_exec_attempt *attempt);
int nacc_exec_commit(const struct nacc_exec_attempt *attempt);
int nacc_exec_prepare_elf(const struct nacc_exec_attempt *attempt,
			  struct file *executable,
			  bool fixed_executable, bool direct_executable,
			  bool has_interpreter, u32 load_segment_count,
			  u32 executable_load_segment_count,
			  u32 executable_flags, u64 executable_file_offset,
			  u64 executable_virtual_address,
			  u64 executable_file_size,
			  u64 executable_memory_size, u64 entry);
bool nacc_exec_abort(const struct nacc_exec_attempt *attempt);
int nacc_exec_bind_mm(const struct nacc_exec_attempt *attempt);
void nacc_exec_activate(const struct nacc_exec_attempt *attempt);
bool nacc_exec_is_active_current(void);
void nacc_exec_record_failure(const struct nacc_exec_attempt *attempt,
			      int failure_errno);
void nacc_exec_exit_current(void);
#else
static inline void nacc_exec_attempt_begin(struct nacc_exec_attempt *attempt)
{
	attempt->prepare = NULL;
	attempt->prepare_generation = 0;
	attempt->captured = true;
}

static inline void nacc_exec_attempt_release(struct nacc_exec_attempt *attempt)
{
	attempt->captured = false;
}

static inline int nacc_exec_commit(const struct nacc_exec_attempt *attempt)
{
	(void)attempt;
	return 0;
}

static inline int nacc_exec_prepare_elf(
	const struct nacc_exec_attempt *attempt, struct file *executable,
	bool fixed_executable, bool direct_executable,
	bool has_interpreter, u32 load_segment_count,
	u32 executable_load_segment_count, u32 executable_flags,
	u64 executable_file_offset, u64 executable_virtual_address,
	u64 executable_file_size, u64 executable_memory_size, u64 entry)
{
	(void)attempt;
	(void)executable;
	(void)fixed_executable;
	(void)direct_executable;
	(void)has_interpreter;
	(void)load_segment_count;
	(void)executable_load_segment_count;
	(void)executable_flags;
	(void)executable_file_offset;
	(void)executable_virtual_address;
	(void)executable_file_size;
	(void)executable_memory_size;
	(void)entry;
	return 0;
}

static inline bool nacc_exec_abort(const struct nacc_exec_attempt *attempt)
{
	(void)attempt;
	return false;
}

static inline int nacc_exec_bind_mm(const struct nacc_exec_attempt *attempt)
{
	(void)attempt;
	return 0;
}

static inline void nacc_exec_activate(const struct nacc_exec_attempt *attempt)
{
	(void)attempt;
}

static inline bool nacc_exec_is_active_current(void)
{
	return false;
}

static inline void nacc_exec_record_failure(
	const struct nacc_exec_attempt *attempt, int failure_errno)
{
	(void)attempt;
	(void)failure_errno;
}

static inline void nacc_exec_exit_current(void)
{
}
#endif

#endif /* _LINUX_NACC_EXEC_H */
