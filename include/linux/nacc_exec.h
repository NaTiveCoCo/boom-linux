/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC exec 与 task exit lifecycle hooks。 */
#ifndef _LINUX_NACC_EXEC_H
#define _LINUX_NACC_EXEC_H

#include <linux/types.h>

#ifdef CONFIG_NACC
int nacc_exec_commit_current(void);
int nacc_exec_prepare_elf_current(bool fixed_executable, bool has_interpreter,
				  u32 load_segment_count,
				  u32 executable_load_segment_count,
				  u32 executable_flags,
				  u64 executable_file_offset,
				  u64 executable_virtual_address,
				  u64 executable_file_size,
				  u64 executable_memory_size, u64 entry);
bool nacc_exec_abort_current(void);
void nacc_exec_bind_mm_current(void);
void nacc_exec_activate_current(void);
bool nacc_exec_is_active_current(void);
void nacc_exec_record_failure_current(int failure_errno);
void nacc_exec_exit_current(void);
#else
static inline int nacc_exec_commit_current(void)
{
	return 0;
}

static inline int nacc_exec_prepare_elf_current(
	bool fixed_executable, bool has_interpreter, u32 load_segment_count,
	u32 executable_load_segment_count, u32 executable_flags,
	u64 executable_file_offset, u64 executable_virtual_address,
	u64 executable_file_size, u64 executable_memory_size, u64 entry)
{
	(void)fixed_executable;
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

static inline bool nacc_exec_abort_current(void)
{
	return false;
}

static inline void nacc_exec_bind_mm_current(void)
{
}

static inline void nacc_exec_activate_current(void)
{
}

static inline bool nacc_exec_is_active_current(void)
{
	return false;
}

static inline void nacc_exec_record_failure_current(int failure_errno)
{
	(void)failure_errno;
}

static inline void nacc_exec_exit_current(void)
{
}
#endif

#endif /* _LINUX_NACC_EXEC_H */
