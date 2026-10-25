// SPDX-License-Identifier: GPL-2.0-only
/* Linux owns signal selection and masks; AU register frames stay private. */
#include <linux/entry-common.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <asm/nacre_registration.h>
#include <asm/nacre_signal_abi.h>

long nacre_signal_frame_export(struct ksignal *, sigset_t *, unsigned long,
                               unsigned long, struct pt_regs *);
long nacre_signal_frame_restore(unsigned long, struct pt_regs *);

/* Exists only between selection and publication, never throughout a handler. */
struct nacre_signal_state {
    struct ksignal signal;
    sigset_t mask;
};

/* Resolve native restart policy after signal selection. AS alone rewinds AU. */
void nacre_signal_restart(struct pt_regs *regs)
{
    struct nacre_signal_state *state = current->thread.nacre_signal;
    switch ((long)regs->a0) {
    case -ERESTARTSYS:
        if (state && !(state->signal.ka.sa.sa_flags & SA_RESTART))
            regs->a0 = -EINTR;
        break;
    case -ERESTARTNOINTR:
        regs->a0 = -ERESTARTSYS;
        break;
    case -ERESTARTNOHAND:
        regs->a0 = state ? -EINTR : -ERESTARTSYS;
        break;
    case -ERESTART_RESTARTBLOCK:
        if (state) regs->a0 = -EINTR;
        break;
    }
}

bool nacre_signal_dispatch(struct pt_regs *regs)
{
    struct ksignal signal;
    if (current->thread.nacre_flag != NACRE_HANDOFF &&
        current->thread.nacre_flag != NACRE_FORK_CHILD) return false;
    /* Internal frame preparation may fault/schedule before delivery commits. */
    if (current->thread.nacre_signal) return true;
    if (get_signal(&signal)) {
        struct nacre_signal_state *state = kzalloc(sizeof(*state), GFP_KERNEL);
        BUG_ON(!state);
        state->signal = signal;
        state->mask = *sigmask_to_save();
        current->thread.nacre_signal = state;
        regs->t6 = signal.sig;
    } else {
        restore_saved_sigmask();
    }
    return true;
}

long nacre_signal_control(unsigned long operation, unsigned long buffer,
                          unsigned long stack, struct pt_regs *regs)
{
    struct nacre_signal_state *state = current->thread.nacre_signal;
    long rc;
    switch (operation) {
    case NACRE_SIGNAL_FETCH:
        BUG_ON(!state);
        return nacre_signal_frame_export(&state->signal, &state->mask, stack, buffer, regs);
    case NACRE_SIGNAL_DONE:
        BUG_ON(!state);
        signal_setup_done(0, &state->signal, 0);
        kfree(state);
        current->thread.nacre_signal = NULL;
        return 0;
    case NACRE_SIGNAL_RETURN:
        BUG_ON(state);
        rc = nacre_signal_frame_restore(buffer, regs);
        if (!rc) return 0;
        fallthrough;
    case NACRE_SIGNAL_BAD:
        nacre_signal_release();
        force_fatal_sig(SIGSEGV);
        return -EFAULT;
    default:
        panic("NACRE invalid signal control operation\n");
    }
}

void nacre_signal_release(void)
{
    kfree(current->thread.nacre_signal);
    current->thread.nacre_signal = NULL;
}
