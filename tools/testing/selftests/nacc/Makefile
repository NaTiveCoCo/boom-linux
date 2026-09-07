# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -Wextra -Werror -O2 $(KHDR_INCLUDES)
top_srcdir = $(realpath ../../../..)
CFLAGS += -I$(top_srcdir)/arch/riscv/include
TEST_GEN_PROGS := nacc_uapi nacc_bootstrap nacc_agent_image nacc_root \
	nacc_bootstrap_session nacc_lifecycle

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

$(OUTPUT)/nacc_bootstrap_session: nacc_bootstrap_session.c \
	$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap_session_core.c \
	$(top_srcdir)/arch/riscv/include/asm/nacc_bootstrap_session.h \
	$(top_srcdir)/arch/riscv/include/asm/nacc_bootstrap.h
	$(CC) -o$@ $(CFLAGS) $(LDFLAGS) nacc_bootstrap_session.c \
		$(top_srcdir)/arch/riscv/kernel/nacc_bootstrap_session_core.c

$(OUTPUT)/nacc_lifecycle: nacc_lifecycle.c \
	$(top_srcdir)/drivers/misc/nacc/nacc_lifecycle_core.c \
	$(top_srcdir)/include/linux/nacc_lifecycle.h
	$(CC) -o$@ $(CFLAGS) -I$(top_srcdir)/include $(LDFLAGS) nacc_lifecycle.c \
		$(top_srcdir)/drivers/misc/nacc/nacc_lifecycle_core.c
