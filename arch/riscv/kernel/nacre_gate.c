// SPDX-License-Identifier: GPL-2.0-only
#include <linux/entry-common.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <asm/asm-prototypes.h>
#include <asm/nacre_registration.h>

/* Each native handler owns its user-entry/exit accounting and scheduling. */
asmlinkage void noinstr nacre_gate_dispatch(unsigned long cid, unsigned long pid,
					  struct pt_regs *regs)
{
	instrumentation_begin();
	BUG_ON(current->thread.nacre_flag != NACRE_HANDOFF ||
	       current->thread.nacre_cid != cid || current->pid != pid ||
	       regs != current_pt_regs() || !user_mode(regs) ||
	       (regs->status & SR_SIE) || !(regs->status & SR_SPIE));
	instrumentation_end();
	switch (regs->cause) {
	case CAUSE_IRQ_FLAG | IRQ_S_TIMER:
		/* do_irq acknowledges/rearms the timer before irqentry_exit. */
		do_irq(regs);
		break;
	case EXC_SYSCALL:
		do_trap_ecall_u(regs);
		break;
	case EXC_INST_PAGE_FAULT:
	case EXC_LOAD_PAGE_FAULT:
	case EXC_STORE_PAGE_FAULT:
		do_page_fault(regs);
		break;
	default:
		instrumentation_begin();
		panic("NACRE unsupported AU cause=%lx", regs->cause);
		instrumentation_end();
	}
}
