# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -Wextra -Werror -O2 $(KHDR_INCLUDES)
top_srcdir = $(realpath ../../../..)
CFLAGS += -I$(top_srcdir)/arch/riscv/include
TEST_GEN_PROGS := nacc_uapi nacc_bootstrap

include ../lib.mk

$(OUTPUT)/nacc_bootstrap: nacc_bootstrap.c \
	$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap.c \
	$(top_srcdir)/arch/riscv/include/asm/nacc_bootstrap.h
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) nacc_bootstrap.c \
		$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap.c
