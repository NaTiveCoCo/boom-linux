/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_NACRE_REGISTRATION_H
#define _ASM_RISCV_NACRE_REGISTRATION_H

/* Explicit private access FIDs in the NACRE extension. */
#define NACRE_UACCESS_SCOPE_BEGIN 0x19
#define NACRE_UACCESS_PRIVATE_GET_USER_READ 0x1a
#define NACRE_UACCESS_SCOPE_END 0x1b
#define NACRE_UACCESS_PRIVATE_COPY_TO_USER 0x1c
#define NACRE_UACCESS_PRIVATE_PUT_USER_WRITE 0x1d
#define NACRE_UACCESS_PRIVATE_COPY_FROM_USER 0x1e
#define NACRE_UACCESS_PRIVATE_CLEAR_USER 0x1f
#define NACRE_UACCESS_PRIVATE_COPY_KERNEL_ALIAS 0x24

#define NACRE_SBI_REGISTER_EXT 0x084e4143
/* No input arguments; returns the fixed Agent ingress in sbiret.value. */
#define NACRE_SBI_PREPARE 0
#define NACRE_CSR_ASSTATUS 0x7c2
#define NACRE_ASSTATUS_SPA 2
#define NACRE_AS_ECALL 24
#define NACRE_ENTER_UNREGISTER 2
#define NACRE_ENTER_FORK 3
#define NACRE_FORK_CHILD 4

#define NACRE_IDLE 0
#define NACRE_REQUESTED 1
#define NACRE_PREPARED 2
#define NACRE_HANDOFF 3

#ifndef __ASSEMBLY__
#include <linux/types.h>
struct pt_regs;
struct vm_area_struct;
bool nacre_buffer_vma(const struct vm_area_struct *vma);
int nacre_buffer_prepare(unsigned long *address, unsigned long *capacity);
int nacre_bind_initial(unsigned long buffer, unsigned long capacity);
struct mm_struct;
struct task_struct;
struct ksignal;
bool nacre_signal_deliver(struct ksignal *ksig, struct pt_regs *regs);
void nacre_signal_return(struct pt_regs *regs);
void nacre_signal_release(void);
int nacre_fork_mm_prepare(struct mm_struct *mm);
void nacre_fork_publish(struct task_struct *child);
void nacre_activate(void);
void nacre_fork_child_return(void);
void nacre_fork_asm(unsigned long cid, unsigned long pid, struct pt_regs *regs);
int nacre_buffer_fork_pin(struct mm_struct *mm, unsigned long *address, unsigned long *capacity);
struct linux_binprm;
int nacre_exec_reserve(struct mm_struct *mm);
int nacre_exec_prepare(struct linux_binprm *bprm);
void __noreturn nacre_exec_handoff(void);
void nacre_exec_cancel(void);
void nacre_exit(void);
void nacre_unregister_asm(unsigned long cid, unsigned long pid, struct pt_regs *regs);
void nacre_user_return_prepare(struct pt_regs *regs);
#endif
#endif
