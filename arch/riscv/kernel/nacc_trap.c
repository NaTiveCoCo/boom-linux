// SPDX-License-Identifier: GPL-2.0-only
/*
 * NACC AS -> Linux synchronous service entry。
 *
 * BOOTSTRAP_READY 是一次性 AS→Linux handoff；EXIT 是最小 runtime terminal
 * handoff。其他 runtime service 尚未接通。
 */

#include <linux/entry-common.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/mm.h>
#include <linux/nacc_exec.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>

#include <asm/asm-prototypes.h>
#include <asm/csr.h>
#include <asm/nacc_bootstrap_session.h>
#include <asm/nacc_runtime.h>
#include <asm/ptrace.h>

#define NACC_AS_LINUX_BOOTSTRAP_READY	0x8000UL
#define NACC_AS_LINUX_EXIT		0x8050UL
#define NACC_AS_LINUX_RUNTIME_TRACE	0x80feUL
#define NACC_ECALL_INSN_SIZE		4UL
#define NACC_SV39_USER_LIMIT		(1UL << 38)

static void nacc_linux_runtime_exit(struct pt_regs *regs)
{
	unsigned long stack_top;

	/* irqentry_nmi 区间不能取得 lifecycle mutex；owner 在 continuation 校验。 */
	if (regs->a0 || regs->a1 || regs->a2 || regs->a3 || regs->a4 ||
	    regs->a5 || regs->a6)
		panic("NACC AS EXIT request invariant failed");
	stack_top = (unsigned long)task_stack_page(current) + THREAD_SIZE;
	current->thread_info.kernel_sp = stack_top;
	regs->epc = (unsigned long)nacc_linux_runtime_exit_resume;
	regs->sp = stack_top;
	regs->tp = (unsigned long)current;
	regs->status &= ~(SR_SIE | SR_SPIE | SR_SUM | SR_FS_VS);
	regs->status |= SR_SPP;
	regs->asstatus &= ~SR_ASSTATUS_SPA;
}

asmlinkage __visible __noreturn void nacc_linux_runtime_exit_complete(void)
{
	if (!nacc_exec_is_active_current() ||
	    (csr_read(CSR_ASSTATUS) & SR_ASSTATUS_SPA))
		panic("NACC Linux runtime exit continuation invariant failed");
	local_irq_enable();
	do_exit(0);
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
		regs->a0 = nacc_linux_bootstrap_ready(regs);
		break;
	case NACC_AS_LINUX_RUNTIME_RESPONSE_OPCODE:
		nacc_linux_runtime_response(regs);
		break;
	case NACC_AS_LINUX_EXIT:
		nacc_linux_runtime_exit(regs);
		break;
	case NACC_AS_LINUX_RUNTIME_TRACE:
		if (regs->a0 > 6 || regs->a1 || regs->a2 ||
		    regs->a3 || regs->a4 || regs->a5 || regs->a6)
			panic("NACC Agent ENTER trace invariant failed");
		pr_info("NACC Agent ENTER stage %lu\n", regs->a0);
		regs->a0 = 0;
		break;
	default:
		regs->a0 = -ENOSYS;
		break;
	}

	irqentry_nmi_exit(regs, state);
}
