/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>
#include <asm/nacre_registration.h>

	.section .noinstr.text, "ax"
/* Exec owns this non-returning continuation; ordinary exception exits bypass it. */
SYM_CODE_START(nacre_exec_handoff_asm)
	/* Discard the exec C stack; preserve the application frame at its top. */
	mv a2, a0
	mv sp, a2
	li t0, TASK_THREAD_NACRE_FLAG
	add t2, tp, t0
	REG_L a0, (TASK_THREAD_NACRE_CID - TASK_THREAD_NACRE_FLAG)(t2)
	REG_L a3, (TASK_THREAD_NACRE_ENTRY - TASK_THREAD_NACRE_FLAG)(t2)
	li t0, TASK_NACRE_PID
	add t0, tp, t0
	lw a1, 0(t0)
	li t0, NACRE_HANDOFF
	REG_S t0, 0(t2)
	/* No C, logging or SBI calls are permitted after syscall exit. */
	.globl nacre_register_enter
nacre_register_enter:
	/* Clear any LR reservation, writing back the unchanged application EPC. */
	REG_L t0, PT_EPC(a2)
	REG_SC x0, t0, PT_EPC(a2)
	csrr t1, CSR_STATUS
	li t0, ~(SR_SIE | SR_SPIE | SR_SUM | SR_MXR | SR_FS_VS)
	and t1, t1, t0
	ori t1, t1, SR_SPP
	csrw CSR_STATUS, t1
	csrw CSR_EPC, a3
	/* Keep the standard stvec: AS services enter the dedicated early gate. */
	csrw CSR_SCRATCH, zero
	li t0, NACRE_ASSTATUS_SPA
	csrs NACRE_CSR_ASSTATUS, t0
	sret
SYM_CODE_END(nacre_exec_handoff_asm)
ASM_NOKPROBE(nacre_exec_handoff_asm)
