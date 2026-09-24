/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/csr.h>
#include <asm/nacre_registration.h>
#include <asm/scs.h>
#include <asm/thread_info.h>

	.section .noinstr.text, "ax"
SYM_CODE_START(nacre_gate_entry)
	/* U is already at task_pt_regs(); R lives immediately below it. */
	csrr tp, CSR_SCRATCH
	REG_S sp, TASK_TI_KERNEL_SP(tp)
#ifdef CONFIG_VMAP_STACK
	addi sp, sp, -PT_SIZE_ON_STACK
	srli sp, sp, THREAD_SHIFT
	andi sp, sp, 1
	bnez sp, .Lnacre_bad_stack
	REG_L sp, TASK_TI_KERNEL_SP(tp)
#endif
	addi sp, sp, -PT_SIZE_ON_STACK
	REG_S x1, PT_RA(sp)
	REG_S x3, PT_GP(sp)
	REG_S x4, PT_TP(sp)
	REG_S x5, PT_T0(sp)
	save_from_x6_to_x31
	addi t0, sp, PT_SIZE_ON_STACK
	REG_S t0, PT_SP(sp)
	li t0, SR_SUM | SR_FS_VS
	csrrc t1, CSR_STATUS, t0
	REG_S t1, PT_STATUS(sp)
	csrr t0, CSR_EPC
	REG_S t0, PT_EPC(sp)
	csrr t0, CSR_CAUSE
	REG_S t0, PT_CAUSE(sp)
	REG_S zero, PT_BADADDR(sp)
	REG_S zero, PT_ORIG_A0(sp)
	csrw CSR_SCRATCH, zero
	/* Scheduling may return directly to an ordinary task without another trap. */
	li t0, NACRE_ASSTATUS_SPA
	csrc NACRE_CSR_ASSTATUS, t0
	load_global_pointer
	scs_load_current
	/* R retains CID/PID/U even when the handler schedules another task. */
	call nacre_gate_dispatch
	j nacre_gate_return
#ifdef CONFIG_VMAP_STACK
.Lnacre_bad_stack:
	/* Switch before storing anything to the exhausted task stack. */
	csrrw x31, CSR_SCRATCH, x31
	asm_per_cpu sp, overflow_stack, x31
	li x31, OVERFLOW_STACK_SIZE
	add sp, sp, x31
	csrrw x31, CSR_SCRATCH, x31
	addi sp, sp, -PT_SIZE_ON_STACK
	REG_S x1, PT_RA(sp)
	REG_S x3, PT_GP(sp)
	REG_S x5, PT_T0(sp)
	save_from_x6_to_x31
	REG_L t0, TASK_TI_KERNEL_SP(tp)
	REG_S t0, PT_SP(sp)
	REG_S tp, PT_TP(sp)
	csrr t0, CSR_EPC
	REG_S t0, PT_EPC(sp)
	csrr t0, CSR_STATUS
	REG_S t0, PT_STATUS(sp)
	csrr t0, CSR_CAUSE
	REG_S t0, PT_CAUSE(sp)
	REG_S zero, PT_BADADDR(sp)
	csrw CSR_SCRATCH, zero
	load_global_pointer
	scs_load_current
	mv a0, sp
	tail handle_bad_stack
#endif
SYM_CODE_END(nacre_gate_entry)
ASM_NOKPROBE(nacre_gate_entry)

SYM_CODE_START(nacre_gate_return)
	csrci CSR_STATUS, SR_SIE
#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
	call stackleak_erase_on_task_stack
#endif
	addi t0, sp, 2 * PT_SIZE_ON_STACK
	REG_S t0, TASK_TI_KERNEL_SP(tp)
	scs_save_current
	csrw CSR_SCRATCH, zero
	/* Nested ordinary S traps overwrite SPA; reconstruct it at this exit. */
	li t0, NACRE_ASSTATUS_SPA
	csrs NACRE_CSR_ASSTATUS, t0
	REG_L t0, PT_STATUS(sp)
	li t1, ~(SR_SIE | SR_SPIE | SR_SUM | SR_FS_VS)
	and t0, t0, t1
	ori t0, t0, SR_SPP
	csrw CSR_STATUS, t0
	REG_L t0, PT_EPC(sp)
	addi t0, t0, 4
	REG_S t0, PT_EPC(sp)
	REG_SC zero, t0, PT_EPC(sp)
	csrw CSR_EPC, t0
	REG_L x1, PT_RA(sp)
	REG_L x3, PT_GP(sp)
	REG_L x4, PT_TP(sp)
	REG_L x5, PT_T0(sp)
	restore_from_x6_to_x31
	REG_L sp, PT_SP(sp)
	sret
SYM_CODE_END(nacre_gate_return)
ASM_NOKPROBE(nacre_gate_return)
