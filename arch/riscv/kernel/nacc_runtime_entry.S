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
