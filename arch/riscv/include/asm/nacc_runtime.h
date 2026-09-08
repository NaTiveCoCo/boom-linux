/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC Linux runtime continuation 的 RISC-V 内部接口。 */
#ifndef _ASM_RISCV_NACC_RUNTIME_H
#define _ASM_RISCV_NACC_RUNTIME_H

#include <linux/linkage.h>
#include <linux/types.h>

#include <asm/nacc_runtime_lifecycle.h>

#define NACC_AS_LINUX_RUNTIME_RESPONSE_OPCODE 0x8002U

struct pt_regs;

bool nacc_linux_runtime_is_ready(void);
int nacc_linux_runtime_lifecycle_call(
	const struct nacc_runtime_lifecycle_request *request,
	struct nacc_runtime_lifecycle_result *result);
void nacc_linux_runtime_exec_enter(
	const struct nacc_enter_message_request *request) __noreturn;
void nacc_linux_runtime_response(struct pt_regs *regs);
asmlinkage void nacc_linux_runtime_enter(unsigned long runtime_entry,
					 unsigned long control_satp) __noreturn;
asmlinkage void nacc_linux_runtime_response_resume(void);
asmlinkage void nacc_linux_runtime_response_complete(void) __noreturn;

asmlinkage void nacc_linux_runtime_exit_resume(void);
asmlinkage void nacc_linux_runtime_exit_complete(void) __noreturn;

#endif /* _ASM_RISCV_NACC_RUNTIME_H */
