/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC exec 与 task exit lifecycle hooks。 */
#ifndef _LINUX_NACC_EXEC_H
#define _LINUX_NACC_EXEC_H

#include <linux/types.h>

#ifdef CONFIG_NACC
int nacc_exec_commit_current(void);
bool nacc_exec_abort_current(void);
void nacc_exec_bind_mm_current(void);
void nacc_exec_activate_current(void);
void nacc_exec_record_failure_current(int failure_errno);
void nacc_exec_exit_current(void);
#else
static inline int nacc_exec_commit_current(void)
{
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

static inline void nacc_exec_record_failure_current(int failure_errno)
{
	(void)failure_errno;
}

static inline void nacc_exec_exit_current(void)
{
}
#endif

#endif /* _LINUX_NACC_EXEC_H */
