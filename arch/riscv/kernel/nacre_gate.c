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
#include <asm/unistd.h>
#include <asm/stat.h>
#include <asm/termbits.h>
#include <linux/utsname.h>
#include <linux/resource.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/eventpoll.h>

#define NACRE_GATE_BUFFER_GROW 0x1000

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
    case NACRE_GATE_BUFFER_GROW:
        regs->cause = EXC_SYSCALL;
        break;
    case __NR_getcwd:
    case __NR_dup:
    case __NR_dup3:
    case __NR_fcntl:
    case __NR_ioctl:
    case __NR_openat:
    case __NR_close:
    case __NR_pipe2:
    case __NR_socket:
    case __NR_bind:
    case __NR_listen:
    case __NR_accept:
    case __NR_getsockname:
    case __NR_sendto:
    case __NR_recvfrom:
    case __NR_setsockopt:
    case __NR_getsockopt:
    case __NR_recvmsg:
    case __NR_socketpair:
    case __NR_sendfile:
    case __NR_pselect6:
    case __NR_setitimer:
    case __NR_clock_gettime:
    case __NR_kill:
    case __NR_ppoll:
    case __NR_newfstatat:
    case __NR_fstat:
    case __NR_execve:
    case __NR_rt_sigprocmask:
    case __NR_clone:
    case __NR_wait4:
    case __NR_rt_sigaction:
    case __NR_uname:
    case __NR_pread64:
    case __NR_pwrite64:
    case __NR_munmap:
    case __NR_mmap:
    case __NR_eventfd2:
    case __NR_epoll_create1:
    case __NR_epoll_ctl:
    case __NR_epoll_pwait:
    case __NR_mkdirat:
    case __NR_fchownat:
    case __NR_lseek:
    case __NR_writev:
    case __NR_rt_sigsuspend:
    case __NR_setgid:
    case __NR_setuid:
    case __NR_setgroups:
    case __NR_prctl:
    case __NR_connect:
    case __NR_accept4:
    case __NR_prlimit64:
    case __NR_getrusage:
    case __NR_getpid:
    case __NR_getppid:
    case __NR_getuid:
    case __NR_geteuid:
    case __NR_getgid:
    case __NR_getegid: {
        unsigned long args[6];
        static_assert(sizeof(struct stat) == 128);
        static_assert(sizeof(struct termios) == 36);
        static_assert(sizeof(struct new_utsname) == 390);
        static_assert(sizeof(struct user_msghdr) == 56);
        static_assert(sizeof(struct iovec) == 16);
        static_assert(sizeof(struct epoll_event) == 16);
        static_assert(sizeof(struct rlimit64) == 16);
        static_assert(sizeof(struct rusage) == 144);
        static_assert(sizeof(struct __kernel_timespec) == 16);
        static_assert(sizeof(struct __kernel_old_itimerval) == 32);
        /* The fixed argument area and pointees are in the sealed public buffer. */
        /* IRQs are still disabled; resident arguments must be readable without faulting in pages. */
        BUG_ON(copy_from_user_nofault(args, (void __user *)value, sizeof(args)));
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
    case __NR_rt_sigreturn:
    case __NR_read:
    case __NR_write:
    case __NR_exit_group:
    case __NR_brk:
    case __NR_mprotect:
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
    /* Handoff and buffer growth carry an AS request to M. */
    bool handoff = kind == __NR_clone || kind == __NR_execve || kind == NACRE_GATE_BUFFER_GROW;
    instrumentation_begin();
    if (handoff) {
        struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 20, 0, 0, 0, 0, 0, 0);
        if (ret.error) {
            pr_err("NACRE service BEGIN rejected kind=%lu error=%ld\n", kind, ret.error);
            syscall_enter_from_user_mode(regs, -1);
            do_group_exit(SIGKILL);
        }
    }
    instrumentation_end();
    switch (regs->cause) {
	case CAUSE_IRQ_FLAG | IRQ_S_TIMER:
		/* do_irq acknowledges/rearms the timer before irqentry_exit. */
		do_irq(regs);
		break;
	case EXC_SYSCALL:
        if (kind == NACRE_GATE_BUFFER_GROW) {
            syscall_enter_from_user_mode(regs, -1);
            regs->a0 = nacre_buffer_grow(value);
            syscall_exit_to_user_mode(regs);
        } else if (kind == __NR_rt_sigreturn) nacre_signal_return(regs);
        else do_trap_ecall_u(regs);
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
    if (handoff) {
        struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 21, regs->a0, 0, 0, 0, 0, 0);
        if (ret.error) {
            pr_err("NACRE service END rejected kind=%lu error=%ld\n", kind, ret.error);
            syscall_enter_from_user_mode(regs, -1);
            do_group_exit(SIGKILL);
        }
    }
    nacre_activate();
    instrumentation_end();
}
