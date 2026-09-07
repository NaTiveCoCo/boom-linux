// SPDX-License-Identifier: GPL-2.0-only
/*
 * NACC AS -> Linux synchronous service entry。
 *
 * 当前只接通 ECALL_FROM_AS 的架构 trap/return 边界。Linux early-init 与
 * bootstrap service 尚未注册时，BOOTSTRAP_READY 必须明确失败，不能把
 * cause 可达误报为 confidential bootstrap 成功。
 */

#include <linux/entry-common.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/mm.h>

#include <asm/asm-prototypes.h>
#include <asm/csr.h>
#include <asm/ptrace.h>

#define NACC_AS_LINUX_BOOTSTRAP_READY	0x8000UL
#define NACC_FIRST_ENTRY_CONTEXT_V2_SIZE	400UL
#define NACC_ECALL_INSN_SIZE		4UL
#define NACC_SV39_USER_LIMIT		(1UL << 38)

static __always_inline long nacc_bootstrap_ready(struct pt_regs *regs)
{
	if (!regs->a0 || regs->a0 & (PAGE_SIZE - 1) ||
	    regs->a0 >= NACC_SV39_USER_LIMIT ||
	    regs->a0 > NACC_SV39_USER_LIMIT - PAGE_SIZE ||
	    regs->a1 != NACC_FIRST_ENTRY_CONTEXT_V2_SIZE || !regs->a2 ||
	    !regs->a3 || regs->a4 || regs->a5 || regs->a6)
		return -EINVAL;

	/* bootstrap state/backend 尚未接入，不能提前确认 Agent ACTIVE。 */
	return -EOPNOTSUPP;
}

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
		regs->a0 = nacc_bootstrap_ready(regs);
		break;
	default:
		regs->a0 = -ENOSYS;
		break;
	}

	irqentry_nmi_exit(regs, state);
}
