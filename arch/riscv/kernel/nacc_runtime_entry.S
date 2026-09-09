/* SPDX-License-Identifier: GPL-2.0-only */
/* Linux runtime kthread 与 AS completion 的 terminal continuation。 */

#include <linux/linkage.h>

#include <asm/csr.h>

SYM_CODE_START(nacc_linux_runtime_enter)
	/* Agent runtime entry 第一条指令自行切换 AS stack；Linux frame 不返回。 */
	csrw CSR_EPC, a0
	csrw CSR_SCRATCH, tp
	li t0, SR_SIE | SR_SPIE | SR_SUM | SR_FS_VS
	csrc CSR_STATUS, t0
	li t0, SR_SPP
	csrs CSR_STATUS, t0
	li t0, SR_ASSTATUS_SPA
	csrs CSR_ASSTATUS, t0
	csrw CSR_SATP, a1
	sfence.vma
	sret
SYM_CODE_END(nacc_linux_runtime_enter)

SYM_CODE_START(nacc_linux_runtime_response_resume)
	.option push
	.option norelax
	la gp, __global_pointer$
	.option pop
	tail nacc_linux_runtime_response_complete
SYM_CODE_END(nacc_linux_runtime_response_resume)

SYM_CODE_START(nacc_linux_runtime_syscall_resume)
	.option push
	.option norelax
	la gp, __global_pointer$
	.option pop
	tail nacc_linux_runtime_syscall_complete
SYM_CODE_END(nacc_linux_runtime_syscall_resume)

SYM_CODE_START(nacc_linux_runtime_syscall_return)
	/* a0 是返回值，a1 是已验证的 AS gateway continuation。 */
	csrw CSR_EPC, a1
	csrw CSR_SCRATCH, tp
	li t0, SR_SIE | SR_SPIE | SR_SUM | SR_FS_VS
	csrc CSR_STATUS, t0
	li t0, SR_SPP
	csrs CSR_STATUS, t0
	li t0, SR_ASSTATUS_SPA
	csrs CSR_ASSTATUS, t0
	li ra, 0
	li sp, 0
	li gp, 0
	li tp, 0
	li t0, 0
	li t1, 0
	li t2, 0
	li s0, 0
	li s1, 0
	li a1, 0
	li a2, 0
	li a3, 0
	li a4, 0
	li a5, 0
	li a6, 0
	li a7, 0
	li s2, 0
	li s3, 0
	li s4, 0
	li s5, 0
	li s6, 0
	li s7, 0
	li s8, 0
	li s9, 0
	li s10, 0
	li s11, 0
	li t3, 0
	li t4, 0
	li t5, 0
	li t6, 0
	sret
	ebreak
SYM_CODE_END(nacc_linux_runtime_syscall_return)
