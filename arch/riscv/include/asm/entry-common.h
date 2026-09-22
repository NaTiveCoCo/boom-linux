/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_RISCV_ENTRY_COMMON_H
#define _ASM_RISCV_ENTRY_COMMON_H

#include <asm/stacktrace.h>
#include <asm/nacc.h>
#include <asm/nacre_registration.h>
#include <asm/thread_info.h>
#include <asm/vector.h>

static inline void arch_exit_to_user_mode_prepare(struct pt_regs *regs,
						  unsigned long ti_work)
{
	/* Cancel skipped exec requests and validate the final handoff state only. */
	if (unlikely(current->thread.nacre_flag != NACRE_IDLE))
		nacre_user_return_prepare(regs);

	if (ti_work & _TIF_RISCV_V_DEFER_RESTORE) {
		clear_thread_flag(TIF_RISCV_V_DEFER_RESTORE);
		/*
		 * We are already called with irq disabled, so go without
		 * keeping track of riscv_v_flags.
		 */
		riscv_v_vstate_restore(&current->thread.vstate, regs);
	}
}

#define arch_exit_to_user_mode_prepare arch_exit_to_user_mode_prepare

static inline void arch_exit_to_user_mode_work(struct pt_regs *regs,
					       unsigned long ti_work)
{
	if ((ti_work & _TIF_NOTIFY_RESUME) &&
	    current->thread.nacc_flag == NACC_FORKED)
		nacc_attach_forked_child_if_needed();
}

#define arch_exit_to_user_mode_work arch_exit_to_user_mode_work

void handle_page_fault(struct pt_regs *regs);
void handle_break(struct pt_regs *regs);

#ifdef CONFIG_RISCV_MISALIGNED
int handle_misaligned_load(struct pt_regs *regs);
int handle_misaligned_store(struct pt_regs *regs);
#else
static inline int handle_misaligned_load(struct pt_regs *regs)
{
	return -1;
}
static inline int handle_misaligned_store(struct pt_regs *regs)
{
	return -1;
}
#endif

#endif /* _ASM_RISCV_ENTRY_COMMON_H */
