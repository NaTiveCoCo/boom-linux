// SPDX-License-Identifier: GPL-2.0-only
/* A plain SIGCHLD handler needs no public copy of private AU PC/GPRs. */
#include <linux/entry-common.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <asm/nacre_registration.h>
#include <asm/switch_to.h>

struct nacre_signal_state {
    sigset_t mask;
    struct __riscv_d_ext_state fp;
};

bool nacre_signal_deliver(struct ksignal *ksig, struct pt_regs *regs)
{
    if (current->thread.nacre_flag != NACRE_HANDOFF &&
        current->thread.nacre_flag != NACRE_FORK_CHILD) return false;
    if (ksig->sig != SIGCHLD || current->thread.nacre_signal ||
        (ksig->ka.sa.sa_flags & (SA_SIGINFO | SA_ONSTACK | SA_RESETHAND))) {
        signal_setup_done(-EFAULT, ksig, 0);
        return true;
    }
    struct nacre_signal_state *state = kzalloc(sizeof(*state), GFP_KERNEL);
    BUG_ON(!state);
    state->mask = *sigmask_to_save();
    fstate_save(current, regs);
    state->fp = current->thread.fstate;
    current->thread.nacre_signal = state;
    regs->t6 = SIGCHLD;
    signal_setup_done(0, ksig, 0);
    return true;
}

void nacre_signal_return(struct pt_regs *regs)
{
    struct nacre_signal_state *state = current->thread.nacre_signal;
    BUG_ON(!state);
    syscall_enter_from_user_mode(regs, -1);
    set_current_blocked(&state->mask);
    current->thread.fstate = state->fp;
    fstate_restore(current, regs);
    kfree(state);
    current->thread.nacre_signal = NULL;
    regs->a0 = 0;
    syscall_exit_to_user_mode(regs);
}

void nacre_signal_release(void)
{
    kfree(current->thread.nacre_signal);
    current->thread.nacre_signal = NULL;
}
