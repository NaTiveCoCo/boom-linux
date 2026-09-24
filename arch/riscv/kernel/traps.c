// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/randomize_kstack.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
#include <linux/kdebug.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/uprobes.h>
#include <asm/uprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/kexec.h>
#include <linux/entry-common.h>

#include <asm/asm-prototypes.h>
#include <asm/bug.h>
#include <asm/cfi.h>
#include <asm/csr.h>
#include <asm/nacc.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/thread_info.h>
#include <asm/vector.h>
#include <asm/irq_stack.h>

int show_unhandled_signals = 1;

static DEFINE_SPINLOCK(die_lock);

/* Legacy callers remain unsupported; AS services use the stvec gate. */
asmlinkage __visible void nacc_delegate_entry(struct pt_regs *regs,
                                            unsigned long kind,
                                            unsigned long cause)
{
	panic("Legacy NaCC delegate ABI is unavailable");
}

static int copy_code(struct pt_regs *regs, u16 *val, const u16 *insns)
{
	const void __user *uaddr = (__force const void __user *)insns;

	if (!user_mode(regs))
		return get_kernel_nofault(*val, insns);

	/* The user space code from other tasks cannot be accessed. */
	if (regs != task_pt_regs(current))
		return -EPERM;

	return copy_from_user_nofault(val, uaddr, sizeof(*val));
}

static void dump_instr(const char *loglvl, struct pt_regs *regs)
{
	char str[sizeof("0000 ") * 12 + 2 + 1], *p = str;
	const u16 *insns = (u16 *)instruction_pointer(regs);
	long bad;
	u16 val;
	int i;

	for (i = -10; i < 2; i++) {
		bad = copy_code(regs, &val, &insns[i]);
		if (!bad) {
			p += sprintf(p, i == 0 ? "(%04hx) " : "%04hx ", val);
		} else {
			printk("%sCode: Unable to access instruction at 0x%px.\n",
			       loglvl, &insns[i]);
			return;
		}
	}
	printk("%sCode: %s\n", loglvl, str);
}

void die(struct pt_regs *regs, const char *str)
{
	static int die_counter;
	int ret;
	long cause;
	unsigned long flags;

	oops_enter();

	spin_lock_irqsave(&die_lock, flags);
	console_verbose();
	bust_spinlocks(1);

	pr_emerg("%s [#%d]\n", str, ++die_counter);
	print_modules();
	if (regs) {
		show_regs(regs);
		dump_instr(KERN_EMERG, regs);
	}

	cause = regs ? regs->cause : -1;
	ret = notify_die(DIE_OOPS, str, regs, 0, cause, SIGSEGV);

	if (kexec_should_crash(current))
		crash_kexec(regs);

	bust_spinlocks(0);
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&die_lock, flags);
	oops_exit();

	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");
	if (ret != NOTIFY_STOP)
		make_task_dead(SIGSEGV);
}

void do_trap(struct pt_regs *regs, int signo, int code, unsigned long addr)
{
	struct task_struct *tsk = current;

	if (show_unhandled_signals && unhandled_signal(tsk, signo)
	    && printk_ratelimit()) {
		pr_info("%s[%d]: unhandled signal %d code 0x%x at 0x" REG_FMT,
			tsk->comm, task_pid_nr(tsk), signo, code, addr);
		print_vma_addr(KERN_CONT " in ", instruction_pointer(regs));
		pr_cont("\n");
		__show_regs(regs);
		dump_instr(KERN_INFO, regs);
	}

	force_sig_fault(signo, code, (void __user *)addr);
}

static void do_trap_error(struct pt_regs *regs, int signo, int code,
	unsigned long addr, const char *str)
{
	current->thread.bad_cause = regs->cause;

	if (user_mode(regs)) {
		do_trap(regs, signo, code, addr);
	} else {
		if (!fixup_exception(regs))
			die(regs, str);
	}
}

#if defined(CONFIG_XIP_KERNEL) && defined(CONFIG_RISCV_ALTERNATIVE)
#define __trap_section __noinstr_section(".xip.traps")
#else
#define __trap_section noinstr
#endif
#define DO_ERROR_INFO(name, signo, code, str)					\
asmlinkage __visible __trap_section void name(struct pt_regs *regs)		\
{										\
	if (user_mode(regs)) {							\
		irqentry_enter_from_user_mode(regs);				\
		do_trap_error(regs, signo, code, regs->epc, "Oops - " str);	\
		irqentry_exit_to_user_mode(regs);				\
	} else {								\
		irqentry_state_t state = irqentry_nmi_enter(regs);		\
		do_trap_error(regs, signo, code, regs->epc, "Oops - " str);	\
		irqentry_nmi_exit(regs, state);					\
	}									\
}

DO_ERROR_INFO(do_trap_unknown,
	SIGILL, ILL_ILLTRP, "unknown exception");
DO_ERROR_INFO(do_trap_insn_misaligned,
	SIGBUS, BUS_ADRALN, "instruction address misaligned");
DO_ERROR_INFO(do_trap_insn_fault,
	SIGSEGV, SEGV_ACCERR, "instruction access fault");

asmlinkage __visible __trap_section void do_trap_insn_illegal(struct pt_regs *regs)
{
	bool handled;

	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		local_irq_enable();

		handled = riscv_v_first_use_handler(regs);

		local_irq_disable();

		if (!handled)
			do_trap_error(regs, SIGILL, ILL_ILLOPC, regs->epc,
				      "Oops - illegal instruction");

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		do_trap_error(regs, SIGILL, ILL_ILLOPC, regs->epc,
			      "Oops - illegal instruction");

		irqentry_nmi_exit(regs, state);
	}
}

DO_ERROR_INFO(do_trap_load_fault,
	SIGSEGV, SEGV_ACCERR, "load access fault");

asmlinkage __visible __trap_section void do_trap_load_misaligned(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		if (handle_misaligned_load(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
			      "Oops - load address misaligned");

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		if (handle_misaligned_load(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
			      "Oops - load address misaligned");

		irqentry_nmi_exit(regs, state);
	}
}

asmlinkage __visible __trap_section void do_trap_store_misaligned(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		if (handle_misaligned_store(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
				"Oops - store (or AMO) address misaligned");

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		if (handle_misaligned_store(regs))
			do_trap_error(regs, SIGBUS, BUS_ADRALN, regs->epc,
				"Oops - store (or AMO) address misaligned");

		irqentry_nmi_exit(regs, state);
	}
}
DO_ERROR_INFO(do_trap_store_fault,
	SIGSEGV, SEGV_ACCERR, "store (or AMO) access fault");
DO_ERROR_INFO(do_trap_ecall_s,
	SIGILL, ILL_ILLTRP, "environment call from S-mode");
DO_ERROR_INFO(do_trap_ecall_m,
	SIGILL, ILL_ILLTRP, "environment call from M-mode");

static inline unsigned long get_break_insn_length(unsigned long pc)
{
	bug_insn_t insn;

	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;

	return GET_INSN_LENGTH(insn);
}

static bool probe_single_step_handler(struct pt_regs *regs)
{
	bool user = user_mode(regs);

	return user ? uprobe_single_step_handler(regs) : kprobe_single_step_handler(regs);
}

static bool probe_breakpoint_handler(struct pt_regs *regs)
{
	bool user = user_mode(regs);

	return user ? uprobe_breakpoint_handler(regs) : kprobe_breakpoint_handler(regs);
}

void handle_break(struct pt_regs *regs)
{
	if (probe_single_step_handler(regs))
		return;

	if (probe_breakpoint_handler(regs))
		return;

	current->thread.bad_cause = regs->cause;

	if (user_mode(regs))
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->epc);
#ifdef CONFIG_KGDB
	else if (notify_die(DIE_TRAP, "EBREAK", regs, 0, regs->cause, SIGTRAP)
								== NOTIFY_STOP)
		return;
#endif
	else if (report_bug(regs->epc, regs) == BUG_TRAP_TYPE_WARN ||
		 handle_cfi_failure(regs) == BUG_TRAP_TYPE_WARN)
		regs->epc += get_break_insn_length(regs->epc);
	else
		die(regs, "Kernel BUG");
}

asmlinkage __visible __trap_section void do_trap_break(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		irqentry_enter_from_user_mode(regs);

		handle_break(regs);

		irqentry_exit_to_user_mode(regs);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		handle_break(regs);

		irqentry_nmi_exit(regs, state);
	}
}

#define __SYSCALL_WITH_COMPAT(nr, native, compat) __SYSCALL(nr, native)
#define __SYSCALL(nr, call) [nr] = #call,

static const char * const syscall_names[] = {
	[0 ... __NR_syscalls - 1] = "unknown",
#include <asm/syscall_table.h>
};

#undef __SYSCALL
#undef __SYSCALL_WITH_COMPAT

asmlinkage __visible __trap_section  __no_stack_protector
void do_trap_ecall_u(struct pt_regs *regs)
{
	if (user_mode(regs)) {
		const char *name = "unknown";

		if (current->thread.nacc_flag & NACC_INITED) {
			if (regs->a7 < ARRAY_SIZE(syscall_names))
				name = syscall_names[regs->a7];
			nacc_debug("[Linux]: 'do_trap_ecall_u' pid=%d comm=%s cid=%lx nacc_flag=%lx epc=%lx sp=%lx a0=%lx a1=%lx a2=%lx syscall: %lx (%s)\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid,
				   current->thread.nacc_flag, regs->epc,
				   regs->sp, regs->a0, regs->a1, regs->a2,
				   regs->a7, name);
		}
		long syscall = regs->a7;

		regs->epc += 4;
		regs->orig_a0 = regs->a0;
		regs->a0 = -ENOSYS;

		riscv_v_vstate_discard(regs);

		syscall = syscall_enter_from_user_mode(regs, syscall);

		add_random_kstack_offset();
		
		if (syscall >= 0 && syscall < NR_syscalls)
			syscall_handler(regs, syscall);

		/*
		 * Ultimately, this value will get limited by KSTACK_OFFSET_MAX(),
		 * so the maximum stack offset is 1k bytes (10 bits).
		 *
		 * The actual entropy will be further reduced by the compiler when
		 * applying stack alignment constraints: 16-byte (i.e. 4-bit) aligned
		 * for RV32I or RV64I.
		 *
		 * The resulting 6 bits of entropy is seen in SP[9:4].
		 */
		choose_random_kstack_offset(get_random_u16());

		syscall_exit_to_user_mode(regs);
		if (current->thread.nacc_flag & NACC_INITED)
			nacc_debug("[Linux]: 'do_trap_ecall_u' pid=%d comm=%s cid=%lx syscall_exit_to_user_mode epc: %lx\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid, regs->epc);
	} else {
		irqentry_state_t state = irqentry_nmi_enter(regs);

		do_trap_error(regs, SIGILL, ILL_ILLTRP, regs->epc,
			"Oops - environment call from U-mode");

		irqentry_nmi_exit(regs, state);
	}

	if (current->thread.nacc_flag & NACC_INITED)
		nacc_debug("[Linux]: Back to 'do_trap_ecall_u' pid=%d comm=%s cid=%lx regs=%lx status=%lx epc=%lx\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   (unsigned long)regs, regs->status, regs->epc);
}

#ifdef CONFIG_MMU
asmlinkage __visible noinstr void do_page_fault(struct pt_regs *regs)
{
	if (current->thread.nacc_flag & NACC_INITED) {
	        nacc_debug("[Linux]: 'do_page_fault' pt_regs details:\n");
		nacc_debug("[Linux]: 'do_page_fault' regs: 0x%lx\n", (uintptr_t) regs);
		nacc_debug("[Linux]: 'do_page_fault' epc (pc): 0x%lx\n", regs->epc);
		nacc_debug("[Linux]: 'do_page_fault' ra (x1): 0x%lx\n", regs->ra);
		nacc_debug("[Linux]: 'do_page_fault' sp (x2): 0x%lx\n", regs->sp);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' gp (x3): 0x%lx\n", regs->gp);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' tp (x4): 0x%lx\n", regs->tp);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' t0 (x5): 0x%lx\n", regs->t0);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' t1 (x6): 0x%lx\n", regs->t1);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' t2 (x7): 0x%lx\n", regs->t2);
			nacc_debug("[Linux]: 'do_page_fault' s0 (x8): 0x%lx\n", regs->s0);
			nacc_debug("[Linux]: 'do_page_fault' s1 (x9): 0x%lx\n", regs->s1);
			nacc_debug("[Linux]: 'do_page_fault' a0 (x10): 0x%lx\n", regs->a0);
			nacc_debug("[Linux]: 'do_page_fault' a1 (x11): 0x%lx\n", regs->a1);
			nacc_debug("[Linux]: 'do_page_fault' a2 (x12): 0x%lx\n", regs->a2);
			nacc_debug("[Linux]: 'do_page_fault' a3 (x13): 0x%lx\n", regs->a3);
			nacc_debug("[Linux]: 'do_page_fault' a4 (x14): 0x%lx\n", regs->a4);
			nacc_debug("[Linux]: 'do_page_fault' a5 (x15): 0x%lx\n", regs->a5);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' a6 (x16): 0x%lx\n", regs->a6);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' a7 (x17): 0x%lx\n", regs->a7);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' s2 (x18): 0x%lx\n", regs->s2);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' s3 (x19): 0x%lx\n", regs->s3);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' s4 (x20): 0x%lx\n", regs->s4);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' s5 (x21): 0x%lx\n", regs->s5);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' s6 (x22): 0x%lx\n", regs->s6);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' s7 (x23): 0x%lx\n", regs->s7);
			nacc_debug("[Linux]: 'do_page_fault' s8 (x24): 0x%lx\n", regs->s8);
			nacc_debug("[Linux]: 'do_page_fault' s9 (x25): 0x%lx\n", regs->s9);
			nacc_debug("[Linux]: 'do_page_fault' s10 (x26): 0x%lx\n", regs->s10);
			nacc_debug("[Linux]: 'do_page_fault' s11 (x27): 0x%lx\n", regs->s11);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' t3 (x28): 0x%lx\n", regs->t3);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' t4 (x29): 0x%lx\n", regs->t4);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' t5 (x30): 0x%lx\n", regs->t5);
		// printk(KERN_ERR "[Linux]: 'do_page_fault' t6 (x31): 0x%lx\n", regs->t6);
		nacc_debug("[Linux]: 'do_page_fault' status: 0x%lx\n", regs->status);
		nacc_debug("[Linux]: 'do_page_fault' badaddr: 0x%lx\n", regs->badaddr);
        nacc_debug("[Linux]: 'do_page_fault' badaddr vpn[2]: %ld vpn[1]: %ld vpn[0]: %ld\n", (regs->badaddr >> 30) & 0x1FF, (regs->badaddr >> 21) & 0x1FF, (regs->badaddr >> 12) & 0x1FF);
		nacc_debug("[Linux]: 'do_page_fault' cause: 0x%lx\n", regs->cause);
		nacc_debug("[Linux]: 'do_page_fault' orig_a0: 0x%lx\n", regs->orig_a0);
	}
	irqentry_state_t state = irqentry_enter(regs);

	handle_page_fault(regs);

	local_irq_disable();

	irqentry_exit(regs, state);

	if (current->thread.nacc_flag & NACC_INITED) {
		nacc_debug("[Linux]: Back to 'do_page_fault'. With regs: %lx\n", (unsigned long)regs);
		nacc_debug("[Linux]: regs->sstatus: %lx\n", regs->status);
		nacc_debug("[Linux]: regs->epc: %lx\n", regs->epc);
	}
}
#endif

static void noinstr handle_riscv_irq(struct pt_regs *regs)
{
	struct pt_regs *old_regs;

	irq_enter_rcu();
	old_regs = set_irq_regs(regs);
	handle_arch_irq(regs);
	set_irq_regs(old_regs);
	irq_exit_rcu();
}

asmlinkage void noinstr do_irq(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	if (IS_ENABLED(CONFIG_IRQ_STACKS) && on_thread_stack())
		call_on_irq_stack(regs, handle_riscv_irq);
	else
	    handle_riscv_irq(regs);

	irqentry_exit(regs, state);

	if (current->thread.nacc_flag & NACC_INITED) {
		nacc_debug("[Linux]: Back to 'do_irq' pid=%d comm=%s cid=%lx regs=%lx status=%lx epc=%lx ra=%lx sp=%lx a0=%lx a2=%lx a4=%lx a5=%lx cause=%lx\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   (unsigned long)regs, regs->status, regs->epc, regs->ra,
			   regs->sp, regs->a0, regs->a2, regs->a4, regs->a5,
			   regs->cause);
	}
}

#ifdef CONFIG_GENERIC_BUG
int is_valid_bugaddr(unsigned long pc)
{
	bug_insn_t insn;

	if (pc < VMALLOC_START)
		return 0;
	if (get_kernel_nofault(insn, (bug_insn_t *)pc))
		return 0;
	if ((insn & __INSN_LENGTH_MASK) == __INSN_LENGTH_32)
		return (insn == __BUG_INSN_32);
	else
		return ((insn & __COMPRESSED_INSN_MASK) == __BUG_INSN_16);
}
#endif /* CONFIG_GENERIC_BUG */

#ifdef CONFIG_VMAP_STACK
DEFINE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)],
		overflow_stack)__aligned(16);

asmlinkage void handle_bad_stack(struct pt_regs *regs)
{
	unsigned long tsk_stk = (unsigned long)current->stack;
	unsigned long ovf_stk = (unsigned long)this_cpu_ptr(overflow_stack);

	console_verbose();

	pr_emerg("Insufficient stack space to handle exception!\n");
	pr_emerg("Task stack:     [0x%016lx..0x%016lx]\n",
			tsk_stk, tsk_stk + THREAD_SIZE);
	pr_emerg("Overflow stack: [0x%016lx..0x%016lx]\n",
			ovf_stk, ovf_stk + OVERFLOW_STACK_SIZE);

	__show_regs(regs);
	panic("Kernel stack overflow");

	for (;;)
		wait_for_interrupt();
}
#endif
