/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_NACRE_REGISTRATION_H
#define _ASM_RISCV_NACRE_REGISTRATION_H

#define NACRE_SBI_REGISTER_EXT 0x084e4143
/* No input arguments; returns the Agent registration entry in sbiret.value. */
#define NACRE_SBI_PREPARE 0
#define NACRE_CSR_ASSTATUS 0x7c2
#define NACRE_ASSTATUS_SPA 2

#define NACRE_IDLE 0
#define NACRE_REQUESTED 1
#define NACRE_PREPARED 2
#define NACRE_HANDOFF 3

#ifndef __ASSEMBLY__
struct pt_regs;
struct mm_struct;
struct linux_binprm;
int nacre_exec_reserve(struct mm_struct *mm);
void nacre_exec_prepare(struct linux_binprm *bprm);
void __noreturn nacre_exec_handoff(void);
void nacre_exec_cancel(void);
void nacre_user_return_prepare(struct pt_regs *regs);
#endif
#endif
