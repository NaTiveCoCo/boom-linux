// SPDX-License-Identifier: GPL-2.0-only
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/bug.h>
#include <asm/nacre_registration.h>
#include <asm/sbi.h>

/* Only the locked native WAIT check crosses M; the queue key remains unchanged. */
int nacre_futex_compare(u32 __user *address, u32 expected)
{
    struct sbiret ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, NACRE_FUTEX_COMPARE,
                                  task_pid_vnr(current), (unsigned long)address,
                                  expected, 0, 0, 0);
    BUG_ON(ret.error);
    return ret.value;
}
