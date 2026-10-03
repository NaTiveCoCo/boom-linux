// SPDX-License-Identifier: GPL-2.0-only
#include <linux/entry-common.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <asm/sbi.h>
#include <asm/asm-prototypes.h>
#include <asm/nacre_registration.h>

/* Each native handler owns its user-entry/exit accounting and scheduling. */
asmlinkage void noinstr nacre_gate_dispatch(unsigned long cid, unsigned long pid,
					  struct pt_regs *regs, unsigned long kind,
                                          unsigned long value, unsigned long buffer,
                                          unsigned long count)
{
	instrumentation_begin();
	BUG_ON(current->thread.nacre_flag != NACRE_HANDOFF ||
	       current->thread.nacre_cid != cid || current->pid != pid ||
	       regs != current_pt_regs());
    /* AS exports only scalars; all accesses to Linux's frame execute in S. */
    memset(regs, 0, sizeof(*regs));
    regs->status = SR_SPIE;
    switch (kind) {
    case 63: case 64: case 94:
        regs->cause = EXC_SYSCALL;
        regs->a7 = kind;
        regs->a0 = regs->orig_a0 = value;
        regs->a1 = buffer;
        regs->a2 = count;
        break;
    case EXC_INST_PAGE_FAULT: case EXC_LOAD_PAGE_FAULT: case EXC_STORE_PAGE_FAULT:
        regs->cause = kind;
        regs->badaddr = value;
        break;
    case CAUSE_IRQ_FLAG | IRQ_S_TIMER:
        regs->cause = kind;
        break;
    default:
        panic("NACRE invalid public service kind=%lx", kind);
    }
	instrumentation_end();
    /* Only a fault needs M to authorize and verify page-table changes. */
    bool fault = kind == EXC_INST_PAGE_FAULT || kind == EXC_LOAD_PAGE_FAULT ||
                 kind == EXC_STORE_PAGE_FAULT;
    instrumentation_begin();
    if (fault && sbi_ecall(NACRE_SBI_REGISTER_EXT, 20, 0, 0, 0, 0, 0, 0).error) {
        syscall_enter_from_user_mode(regs, -1);
        do_group_exit(SIGKILL);
    }
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
    instrumentation_begin();
    if (fault && sbi_ecall(NACRE_SBI_REGISTER_EXT, 21, 0, 0, 0, 0, 0, 0).error) {
        syscall_enter_from_user_mode(regs, -1);
        do_group_exit(SIGKILL);
    }
    instrumentation_end();
}
