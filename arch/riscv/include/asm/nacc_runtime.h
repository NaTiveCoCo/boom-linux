/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC Linux runtime continuation 的 RISC-V 内部接口。 */
#ifndef _ASM_RISCV_NACC_RUNTIME_H
#define _ASM_RISCV_NACC_RUNTIME_H

#include <linux/linkage.h>

asmlinkage void nacc_linux_runtime_exit_resume(void);
asmlinkage void nacc_linux_runtime_exit_complete(void) __noreturn;

#endif /* _ASM_RISCV_NACC_RUNTIME_H */
