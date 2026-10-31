// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2014 Darius Rad <darius@bluespec.com>
 * Copyright (C) 2017 SiFive
 */

#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched/signal.h>
#include <asm/cacheflush.h>

#include <asm/sbi.h>

#include <linux/slab.h>
#include <linux/gfp.h>
#include <asm/nacre.h>
#include <asm/nacre_registration.h>
#include <asm/page.h>
#include <asm/processor.h>

#include <asm/io.h>

static long riscv_sys_mmap(unsigned long addr, unsigned long len,
			   unsigned long prot, unsigned long flags,
			   unsigned long fd, off_t offset,
			   unsigned long page_shift_offset)
{
	long ret;

	if (nacre_private_data_uaccess_active() &&
	    (flags & (MAP_SHARED | MAP_HUGETLB)))
		return -EOPNOTSUPP;

	if (unlikely(offset & (~PAGE_MASK >> page_shift_offset)))
		return -EINVAL;

	ret = ksys_mmap_pgoff(addr, len, prot, flags, fd,
			     offset >> (PAGE_SHIFT - page_shift_offset));
	return ret;
}

#ifdef CONFIG_64BIT
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
{
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 0);
}
#endif

#if defined(CONFIG_32BIT) || defined(CONFIG_COMPAT)
SYSCALL_DEFINE6(mmap2, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
{
	/*
	 * Note that the shift for mmap2 is constant (12),
	 * regardless of PAGE_SIZE
	 */
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 12);
}
#endif

/*
 * Allows the instruction cache to be flushed from userspace.  Despite RISC-V
 * having a direct 'fence.i' instruction available to userspace (which we
 * can't trap!), that's not actually viable when running on Linux because the
 * kernel might schedule a process on another hart.  There is no way for
 * userspace to handle this without invoking the kernel (as it doesn't know the
 * thread->hart mappings), so we've defined a RISC-V specific system call to
 * flush the instruction cache.
 *
 * sys_riscv_flush_icache() is defined to flush the instruction cache over an
 * address range, with the flush applying to either all threads or just the
 * caller.  We don't currently do anything with the address range, that's just
 * in there for forwards compatibility.
 */
SYSCALL_DEFINE3(riscv_flush_icache, uintptr_t, start, uintptr_t, end,
	uintptr_t, flags)
{
	/* Check the reserved flags. */
	if (unlikely(flags & ~SYS_RISCV_FLUSH_ICACHE_ALL))
		return -EINVAL;

	flush_icache_mm(current->mm, flags & SYS_RISCV_FLUSH_ICACHE_LOCAL);

	return 0;
}

int nacre_record_vvar_sbi(unsigned long root_pgd_pa, unsigned long addr,
			 unsigned long pfn)
{
	struct sbiret ret;

	ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 14,
			root_pgd_pa, addr, pfn, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacre_record_vvar_sbi failed: root=%lx addr=%lx pfn=%lx err=%ld val=%ld\n",
		       root_pgd_pa, addr, pfn, ret.error, ret.value);
		return ret.error == SBI_ERR_NO_SHMEM ? -ENOMEM : -EIO;
	}

	nacre_debug("[Linux]: nacre_record_vvar_sbi ok: root=%lx addr=%lx pfn=%lx val=%ld\n",
		   root_pgd_pa, addr, pfn, ret.value);
	return 0;
}

int nacre_adopt_vdso_sbi(unsigned long root_pgd_pa, unsigned long addr,
			unsigned long nr_pages, unsigned long source_pfns_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(NACRE_SBI_REGISTER_EXT, 15,
			root_pgd_pa, addr, nr_pages, source_pfns_pa, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: nacre_adopt_vdso_sbi failed: root=%lx addr=%lx nr_pages=%lx pfns_pa=%lx err=%ld val=%ld\n",
		       root_pgd_pa, addr, nr_pages, source_pfns_pa,
		       ret.error, ret.value);
		return ret.error == SBI_ERR_NO_SHMEM ? -ENOMEM : -EIO;
	}

	return 0;
}

/* Not defined using SYSCALL_DEFINE0 to avoid error injection */
asmlinkage long __riscv_sys_ni_syscall(const struct pt_regs *__unused)
{
	return -ENOSYS;
}
