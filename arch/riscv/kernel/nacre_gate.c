// SPDX-License-Identifier: GPL-2.0-only
#include <linux/entry-common.h>
#include <linux/mm.h>
#include <linux/nacre_shmem.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <asm/sbi.h>
#include <asm/asm-prototypes.h>
#include <asm/nacre_registration.h>
#include <asm/nacre_signal_abi.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/stat.h>
#include <asm/termbits.h>
#include <linux/utsname.h>
#include <linux/resource.h>
#include <linux/timex.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/eventpoll.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/loop.h>
#include <linux/nsfs.h>
#include <uapi/linux/mount.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/sysinfo.h>
#include <linux/mqueue.h>
#include <uapi/linux/sched/types.h>

_Static_assert(sizeof(kernel_siginfo_t) == 48 && offsetof(kernel_siginfo_t, si_code) == 8 &&
               offsetof(kernel_siginfo_t, si_pid) == 16 && offsetof(kernel_siginfo_t, si_uid) == 20 &&
               offsetof(kernel_siginfo_t, si_value) == 24, "Queued signal ABI drift");

#define NACRE_GATE_BUFFER_GROW 0x1000
#define NACRE_GATE_USER_ACCESS 0x1001
#define NACRE_GATE_FD_PRECHECK 0x1003
#define NACRE_GATE_XATTR 0x1004

/* Resolve a syscall operand without reading protected data or raising SIGSEGV. */
static long nacre_user_access(unsigned long address, unsigned long permissions)
{
    bool unlocked = false;
    int rc;
    BUG_ON(permissions != 2 && permissions != 4);
    mmap_read_lock(current->mm);
    rc = fixup_user_fault(current->mm, address,
                         permissions == 4 ? FAULT_FLAG_WRITE : 0, &unlocked);
    mmap_read_unlock(current->mm);
    return rc;
}

/* Guaranteed-negative namespace clones do not carry an M creation request. */
static __always_inline bool nacre_clone_needs_handoff(unsigned long flags)
{
    unsigned int signal = (unsigned int)flags & CSIGNAL;
    unsigned int namespace = (unsigned int)flags & ~CSIGNAL;
    return !((signal == 0 || signal == SIGCHLD) &&
        (namespace == CLONE_NEWPID || namespace == CLONE_NEWCGROUP ||
         namespace == CLONE_NEWIPC || namespace == CLONE_NEWNET ||
         namespace == CLONE_NEWNS || namespace == CLONE_NEWUTS));
}

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
    case NACRE_GATE_FD_PRECHECK:
    case NACRE_GATE_SIGNAL:
    case NACRE_GATE_USER_ACCESS:
    case NACRE_GATE_BUFFER_GROW:
        regs->cause = EXC_SYSCALL;
        break;
    case NACRE_GATE_XATTR:
        /* The explicit syscall number cannot be confused with a page fault. */
        BUG_ON(buffer < __NR_setxattr || buffer > __NR_fremovexattr);
        kind = buffer;
        fallthrough;
    case __NR_sigaltstack:
    case __NR_getcwd:
    case __NR_futex:
    case __NR_set_tid_address:
    case __NR_add_key:
    case __NR_request_key:
    case __NR_keyctl:
    case __NR_madvise:
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
    case __NR_getpeername:
    case __NR_shutdown:
    case __NR_sendto:
    case __NR_recvfrom:
    case __NR_setsockopt:
    case __NR_getsockopt:
    case __NR_sendmsg:
    case __NR_recvmsg:
    case __NR_socketpair:
    case __NR_sendfile:
    case __NR_pselect6:
    case __NR_setitimer:
    case __NR_signalfd4:
    case __NR_timerfd_create:
    case __NR_timerfd_settime:
    case __NR_timerfd_gettime:
    case __NR_clock_nanosleep:
    case __NR_clock_gettime:
    case __NR_clock_getres:
    case __NR_sched_setparam:
    case __NR_sched_setscheduler:
    case __NR_sched_getscheduler:
    case __NR_sched_getparam:
    case __NR_sched_setaffinity:
    case __NR_sched_getaffinity:
    case __NR_sched_get_priority_max:
    case __NR_sched_get_priority_min:
    case __NR_sched_rr_get_interval:
    case __NR_sched_getattr:
    case __NR_tkill:
    case __NR_splice:
    case __NR_tee:
    case __NR_copy_file_range:
    case __NR_ioprio_set:
    case __NR_ioprio_get:
    case __NR_personality:
    case __NR_sethostname:
    case __NR_setdomainname:
    case __NR_getrlimit:
    case __NR_gettimeofday:
    case __NR_settimeofday:
    case __NR_adjtimex:
    case __NR_clock_adjtime:
    case __NR_memfd_create:
    case __NR_membarrier:
    case __NR_sysinfo:
    case __NR_mlock:
    case __NR_munlock:
    case __NR_mlockall:
    case __NR_munlockall:
    case __NR_mlock2:
    case __NR_mq_open:
    case __NR_mq_unlink:
    case __NR_mq_timedsend:
    case __NR_mq_timedreceive:
    case __NR_mq_notify:
    case __NR_mq_getsetattr:
    case __NR_msgget:
    case __NR_msgctl:
    case __NR_msgrcv:
    case __NR_msgsnd:
    case __NR_semget:
    case __NR_semctl:
    case __NR_semtimedop:
    case __NR_semop:
    case __NR_getitimer:
    case __NR_timer_create:
    case __NR_timer_gettime:
    case __NR_timer_getoverrun:
    case __NR_timer_settime:
    case __NR_timer_delete:
    case __NR_clock_settime:
    case __NR_rt_sigtimedwait:
    case __NR_waitid:
    case __NR_getcpu:
    case __NR_getpriority:
    case __NR_setpriority:
    case __NR_readahead:
    case __NR_fadvise64:
    case __NR_fallocate:
    case __NR_setpgid:
    case __NR_getpgid:
    case __NR_getsid:
    case __NR_setsid:
    case __NR_name_to_handle_at:
    case __NR_clone3:
    case __NR_get_robust_list:
    case __NR_mincore:
    case __NR_kcmp:
    case __NR_pidfd_getfd:
    case __NR_rt_sigqueueinfo:
    case __NR_rt_tgsigqueueinfo:
    case __NR_pidfd_send_signal:
    case __NR_pidfd_open:
    case __NR_close_range:
    case __NR_unshare:
    case __NR_setns:
    case __NR_kill:
    case __NR_tgkill:
    case __NR_faccessat:
    case __NR_getdents64:
    case __NR_capget:
    case __NR_capset:
    case __NR_ppoll:
    case __NR_cachestat:
    case __NR_statx:
    case __NR_inotify_init1:
    case __NR_inotify_add_watch:
    case __NR_inotify_rm_watch:
    case __NR_newfstatat:
    case __NR_readlinkat:
    case __NR_fstat:
    case __NR_execve:
    case __NR_execveat:
    case __NR_openat2:
    case __NR_rt_sigprocmask:
    case __NR_rt_sigpending:
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
    case __NR_epoll_pwait2:
    case __NR_mkdirat:
    case __NR_statfs:
    case __NR_chdir:
    case __NR_unlinkat:
    case __NR_flock:
    case __NR_umask:
    case __NR_mknodat:
    case __NR_fstatfs:
    case __NR_truncate:
    case __NR_fchdir:
    case __NR_chroot:
    case __NR_fchmod:
    case __NR_fchown:
    case __NR_vhangup:
    case __NR_sync:
    case __NR_fsync:
    case __NR_sync_file_range:
    case __NR_fdatasync:
    case __NR_syncfs:
    case __NR_faccessat2:
    case __NR_fchmodat2:
    case __NR_linkat:
    case __NR_renameat2:
    case __NR_symlinkat:
    case __NR_ftruncate:
    case __NR_fchmodat:
    case __NR_fchownat:
    case __NR_utimensat:
    case __NR_lseek:
    case __NR_writev:
    case __NR_readv:
    case __NR_preadv:
    case __NR_pwritev:
    case __NR_preadv2:
    case __NR_pwritev2:
    case __NR_rt_sigsuspend:
    case __NR_setgid:
    case __NR_setuid:
    case __NR_setgroups:
    case __NR_getgroups:
    case __NR_setreuid:
    case __NR_setregid:
    case __NR_setresuid:
    case __NR_setresgid:
    case __NR_getresuid:
    case __NR_getresgid:
    case __NR_setfsuid:
    case __NR_setfsgid:
    case __NR_mount:
    case __NR_mount_setattr:
    case __NR_umount2:
    case __NR_open_tree:
    case __NR_move_mount:
    case __NR_fsopen:
    case __NR_fsconfig:
    case __NR_fsmount:
    case __NR_fspick:
    case __NR_prctl:
    case __NR_connect:
    case __NR_accept4:
    case __NR_prlimit64:
    case __NR_getrusage:
    case __NR_sched_yield:
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
        static_assert(sizeof(struct flock) == 32);
        static_assert(offsetof(struct flock, l_start) == 8);
        static_assert(offsetof(struct flock, l_pid) == 24);
        static_assert(sizeof(struct f_owner_ex) == 8);
        static_assert(sizeof(struct epoll_event) == 16);
        static_assert(sizeof(sigset_t) == 8);
        static_assert(sizeof(struct pollfd) == 8);
        static_assert(sizeof(struct loop_info) == 160);
        static_assert(offsetof(struct loop_info, lo_offset) == 20);
        static_assert(offsetof(struct loop_info, lo_flags) == 32);
        static_assert(offsetof(struct loop_info, lo_name) == 36);
        static_assert(sizeof(struct loop_info64) == 232);
        static_assert(offsetof(struct loop_info64, lo_offset) == 24);
        static_assert(offsetof(struct loop_info64, lo_encrypt_type) == 44);
        static_assert(offsetof(struct loop_info64, lo_file_name) == 56);
        static_assert(sizeof(struct loop_config) == 304);
        static_assert(offsetof(struct loop_config, info) == 8);
        static_assert(sizeof(struct sysinfo) == 112);
        static_assert(sizeof(struct mq_attr) == 64);
        static_assert(sizeof(struct sembuf) == 6);
        static_assert(sizeof(struct semid64_ds) == 88);
        static_assert(sizeof(struct msqid64_ds) == 120);
        static_assert(sizeof(struct ipc64_perm) == 48);
        static_assert(offsetof(struct ipc64_perm, uid) == 4);
        static_assert(offsetof(struct ipc64_perm, mode) == 20);
        static_assert(offsetof(struct msqid64_ds, msg_qbytes) == 88);
        static_assert(sizeof(struct msginfo) == 32);
        static_assert(sizeof(struct seminfo) == 40);
        static_assert(offsetof(struct pollfd, events) == 4);
        static_assert(offsetof(struct pollfd, revents) == 6);
        static_assert(sizeof(struct rlimit64) == 16);
        static_assert(sizeof(struct rusage) == 144);
        static_assert(sizeof(struct sigevent) == 64);
        static_assert(offsetof(struct sigevent, sigev_notify) == 12);
        static_assert(offsetof(struct sigevent, sigev_notify_thread_id) == 16);
        static_assert(sizeof(siginfo_t) == 128);
        static_assert(offsetof(siginfo_t, si_pid) == 16);
        static_assert(offsetof(siginfo_t, si_status) == 24);
        static_assert(sizeof(struct __kernel_itimerspec) == 32);
        static_assert(sizeof(struct sched_param) == 4);
        static_assert(sizeof(struct sched_attr) == 56);
        static_assert(NR_CPUS <= 64);
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
        if (kind == __NR_sigaltstack) {
            static_assert(sizeof(stack_t) == 24);
            static_assert(offsetof(stack_t, ss_flags) == 8);
            static_assert(offsetof(stack_t, ss_size) == 16);
            /* Native on_sig_stack uses the existing explicitly shared stack control. */
            regs->sp = args[2];
        }
        break;
    }
    case __NR_read:
    case __NR_restart_syscall:
    case __NR_write:
    case __NR_exit:
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
    bool handoff = (kind == __NR_clone && nacre_clone_needs_handoff(regs->a0)) || kind == __NR_execve || kind == __NR_execveat || kind == NACRE_GATE_BUFFER_GROW;
    handoff |= kind == __NR_futex && ((regs->a1 & 127) == 0 || (regs->a1 & 127) == 9 || (regs->a1 & 127) == 4);
    /* AS renews the private-word authorization for a futex restart block. */
    handoff |= kind == __NR_restart_syscall && value;
    instrumentation_begin();
    if (handoff) {
        struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 20, task_pid_vnr(current), 0, 0, 0, 0, 0);
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
        if (kind == NACRE_GATE_FD_PRECHECK) {
            syscall_enter_from_user_mode(regs, -1);
            regs->a0 = nacre_shmem_precheck(value, buffer, count);
            syscall_exit_to_user_mode(regs);
        } else if (kind == NACRE_GATE_SIGNAL) {
            syscall_enter_from_user_mode(regs, -1);
            regs->a0 = nacre_signal_control(value, buffer, count, regs);
            syscall_exit_to_user_mode(regs);
        } else if (kind == NACRE_GATE_USER_ACCESS) {
            syscall_enter_from_user_mode(regs, -1);
            regs->a0 = nacre_user_access(value, buffer);
            syscall_exit_to_user_mode(regs);
        } else if (kind == NACRE_GATE_BUFFER_GROW) {
            syscall_enter_from_user_mode(regs, -1);
            regs->a0 = nacre_buffer_grow(value);
            syscall_exit_to_user_mode(regs);
        }
        else {
            do_trap_ecall_u(regs);
            nacre_signal_restart(regs);
        }
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
        struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 21, regs->a0, task_pid_vnr(current), 0, 0, 0, 0);
        if (ret.error) {
            pr_err("NACRE service END rejected kind=%lu error=%ld\n", kind, ret.error);
            syscall_enter_from_user_mode(regs, -1);
            do_group_exit(SIGKILL);
        }
    }
    nacre_activate();
    instrumentation_end();
}

static_assert(sizeof(struct __kernel_timex) == 208);
static_assert(offsetof(struct __kernel_timex, status) == 40);
static_assert(offsetof(struct __kernel_timex, constant) == 48);
static_assert(offsetof(struct __kernel_timex, time) == 72);
static_assert(offsetof(struct __kernel_timex, tick) == 88);
static_assert(offsetof(struct __kernel_timex, shift) == 112);
static_assert(offsetof(struct __kernel_timex, tai) == 160);

static_assert(sizeof(struct rlimit) == 16);
static_assert(sizeof(struct __kernel_old_timeval) == 16);
static_assert(sizeof(struct timezone) == 8);

static_assert(NS_GET_OWNER_UID == 0xb704);
static_assert(NS_GET_MNTNS_ID == 0x8008b705);
static_assert(NS_GET_PID_FROM_PIDNS == 0x8004b706);
static_assert(NS_GET_TGID_IN_PIDNS == 0x8004b709);

static_assert(sizeof(struct mount_attr) == 32);
