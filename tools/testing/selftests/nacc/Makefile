# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -Wextra -Werror -O2 $(KHDR_INCLUDES)
top_srcdir = $(realpath ../../../..)
CFLAGS += -I$(top_srcdir)/arch/riscv/include
TEST_GEN_PROGS := nacc_uapi nacc_bootstrap nacc_agent_image nacc_root

include ../lib.mk

$(OUTPUT)/nacc_bootstrap: nacc_bootstrap.c \
	$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap.c \
	$(top_srcdir)/arch/riscv/include/asm/nacc_bootstrap.h
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) nacc_bootstrap.c \
		$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap.c

$(OUTPUT)/nacc_agent_image: nacc_agent_image.c \
	$(top_srcdir)/arch/riscv/kernel/nacc_agent_image.c \
	$(top_srcdir)/arch/riscv/include/asm/nacc_agent_image.h
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) nacc_agent_image.c \
		$(top_srcdir)/arch/riscv/kernel/nacc_agent_image.c

$(OUTPUT)/nacc_root: nacc_root.c \
	$(top_srcdir)/arch/riscv/mm/nacc_root_core.c \
	$(top_srcdir)/arch/riscv/kernel/nacc_agent_image.c \
	$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap.c \
	$(top_srcdir)/arch/riscv/include/asm/nacc_root.h \
	$(top_srcdir)/arch/riscv/include/asm/nacc_agent_image.h \
	$(top_srcdir)/arch/riscv/include/asm/nacc_bootstrap.h
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) nacc_root.c \
		$(top_srcdir)/arch/riscv/mm/nacc_root_core.c \
		$(top_srcdir)/arch/riscv/kernel/nacc_agent_image.c \
		$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap.c
