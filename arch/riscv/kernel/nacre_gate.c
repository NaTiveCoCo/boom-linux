// SPDX-License-Identifier: GPL-2.0-only
#include <linux/entry-common.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <asm/sbi.h>
#include <asm/asm-prototypes.h>
#include <asm/nacre_registration.h>
#include <asm/uaccess.h>
#include <asm/stat.h>
#include <asm/termbits.h>
#include <linux/utsname.h>

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
    /* The gate saved AU's public FS before disabling FP in S. */
    unsigned long fs = (regs - 1)->status & SR_FS;
    /* AS exports only scalars; all accesses to Linux's frame execute in S. */
    memset(regs, 0, sizeof(*regs));
    regs->status = SR_SPIE | fs;
    switch (kind) {
    case 17: case 24: case 25: case 29: case 56: case 57: case 73: case 80:
    case 134: case 160: case 172: case 173: case 174: case 175: case 176: case 177: {
        unsigned long args[6];
        static_assert(sizeof(struct stat) == 128);
        static_assert(sizeof(struct termios) == 36);
        static_assert(sizeof(struct new_utsname) == 390);
        /* The fixed argument area and pointees are in the sealed public buffer. */
        BUG_ON(copy_from_user(args, (void __user *)value, sizeof(args)));
        regs->cause = EXC_SYSCALL;
        regs->a7 = kind;
        regs->a0 = regs->orig_a0 = args[0];
        regs->a1 = args[1];
        regs->a2 = args[2];
        regs->a3 = args[3];
        regs->a4 = args[4];
        regs->a5 = args[5];
        break;
    }
    case 63: case 64: case 94: case 214: case 226:
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
    /* Faults and address-range changes need the original AS request's M authorization. */
    bool fault = kind == EXC_INST_PAGE_FAULT || kind == EXC_LOAD_PAGE_FAULT ||
                 kind == EXC_STORE_PAGE_FAULT;
    bool memory = kind == 214 || kind == 226;
    instrumentation_begin();
    if ((fault || memory) && sbi_ecall(NACRE_SBI_REGISTER_EXT, 20, 0, 0, 0, 0, 0, 0).error) {
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
    if ((fault || memory) &&
        sbi_ecall(NACRE_SBI_REGISTER_EXT, 21, memory ? regs->a0 : 0, 0, 0, 0, 0, 0).error) {
        syscall_enter_from_user_mode(regs, -1);
        do_group_exit(SIGKILL);
    }
    instrumentation_end();
}
