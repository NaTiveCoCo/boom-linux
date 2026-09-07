// SPDX-License-Identifier: GPL-2.0-only
/*
 * NACC AS -> Linux synchronous service entry。
 *
 * BOOTSTRAP_READY 是一次性 AS→Linux handoff；其他 runtime service 尚未接通。
 */

#include <linux/entry-common.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/mm.h>

#include <asm/asm-prototypes.h>
#include <asm/csr.h>
#include <asm/nacc_bootstrap_session.h>
#include <asm/ptrace.h>

#define NACC_AS_LINUX_BOOTSTRAP_READY	0x8000UL
#define NACC_ECALL_INSN_SIZE		4UL
#define NACC_SV39_USER_LIMIT		(1UL << 38)

asmlinkage __visible noinstr void do_trap_ecall_as(struct pt_regs *regs)
{
	irqentry_state_t state;

	if (unlikely(regs->cause != EXC_AS_ECALL ||
		     !(regs->status & SR_SPP) ||
		     !(regs->asstatus & SR_ASSTATUS_SPA) || regs->badaddr ||
		     (regs->epc & 1) ||
		     regs->epc > NACC_SV39_USER_LIMIT - NACC_ECALL_INSN_SIZE))
		panic("NACC ECALL_FROM_AS trap invariant violated");

	/*
	 * SPA 在 ret_from_exception 回写前仍是 hart-local live CSR state；当前
	 * non-blocking stub 不允许在这里调度到另一个 task。
	 */
	state = irqentry_nmi_enter(regs);
	regs->epc += NACC_ECALL_INSN_SIZE;
	regs->orig_a0 = regs->a0;

	switch (regs->a7) {
	case NACC_AS_LINUX_BOOTSTRAP_READY:
		regs->a0 = nacc_linux_bootstrap_ready(regs);
		break;
	default:
		regs->a0 = -ENOSYS;
		break;
	}

	irqentry_nmi_exit(regs, state);
}
