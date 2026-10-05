/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/csr.h>
#include <asm/nacre_registration.h>

	.section .noinstr.text, "ax"
SYM_FUNC_START(nacre_fork_asm)
    li a7, NACRE_ENTER_FORK
    j .Lnacre_object_entry
SYM_FUNC_END(nacre_fork_asm)

SYM_FUNC_START(nacre_unregister_asm)
    li a7, NACRE_ENTER_UNREGISTER
.Lnacre_object_entry:
	/* Private to Linux: the Agent receives only the return PC/SP/TP/GP. */
	addi sp, sp, -176
	sd ra, 0(sp)
	sd gp, 8(sp)
	sd tp, 16(sp)
	sd s0, 24(sp)
	sd s1, 32(sp)
	sd s2, 40(sp)
	sd s3, 48(sp)
	sd s4, 56(sp)
	sd s5, 64(sp)
	sd s6, 72(sp)
	sd s7, 80(sp)
	sd s8, 88(sp)
	sd s9, 96(sp)
	sd s10, 104(sp)
	sd s11, 112(sp)
	csrr t0, CSR_STATUS
	sd t0, 120(sp)
	csrr t0, CSR_EPC
	sd t0, 128(sp)
	csrr t0, CSR_CAUSE
	sd t0, 136(sp)
	csrr t0, CSR_TVAL
	sd t0, 144(sp)
	csrr t0, CSR_SCRATCH
	sd t0, 152(sp)
	csrr t0, NACRE_CSR_ASSTATUS
	sd t0, 160(sp)
	la a3, nacre_unregister_return
	mv a4, sp
	mv a5, tp
	mv a6, gp
	li t0, SR_SPP
	csrs CSR_STATUS, t0
	li t0, NACRE_ASSTATUS_SPA
	csrs NACRE_CSR_ASSTATUS, t0
	.globl nacre_unregister_enter
nacre_unregister_enter:
	sret
	.globl nacre_unregister_return
nacre_unregister_return:
	/* Interrupts remain disabled until task fields have been cleared in C. */
	ld t0, 128(sp)
	csrw CSR_EPC, t0
	ld t0, 136(sp)
	csrw CSR_CAUSE, t0
	ld t0, 144(sp)
	csrw CSR_TVAL, t0
	ld t0, 152(sp)
	csrw CSR_SCRATCH, t0
	ld t0, 160(sp)
	csrw NACRE_CSR_ASSTATUS, t0
	ld ra, 0(sp)
	ld gp, 8(sp)
	ld tp, 16(sp)
	ld s0, 24(sp)
	ld s1, 32(sp)
	ld s2, 40(sp)
	ld s3, 48(sp)
	ld s4, 56(sp)
	ld s5, 64(sp)
	ld s6, 72(sp)
	ld s7, 80(sp)
	ld s8, 88(sp)
	ld s9, 96(sp)
	ld s10, 104(sp)
	ld s11, 112(sp)
	ld t0, 120(sp)
	csrw CSR_STATUS, t0
	addi sp, sp, 176
	.globl nacre_unregister_restored
nacre_unregister_restored:
	ret
SYM_FUNC_END(nacre_unregister_asm)
ASM_NOKPROBE(nacre_unregister_asm)
