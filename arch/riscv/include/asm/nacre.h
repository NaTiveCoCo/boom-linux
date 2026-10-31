#ifndef _ASM_RISCV_NACRE_H
#define _ASM_RISCV_NACRE_H

#ifndef __ASSEMBLY__
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/sched.h>

struct mm_struct;
struct page;
struct ptdesc;
struct pt_regs;
struct ksignal;
struct vm_area_struct;

#ifdef NACRE_LOG_DEBUG
#define nacre_debug(fmt, ...) printk(KERN_ERR fmt, ##__VA_ARGS__)
#define nacre_debug_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_ERR fmt, ##__VA_ARGS__)
#else
#define nacre_debug(fmt, ...) no_printk(KERN_ERR fmt, ##__VA_ARGS__)
#define nacre_debug_ratelimited(fmt, ...) \
	no_printk(KERN_ERR fmt, ##__VA_ARGS__)
#endif

enum nacre_uaccess_scope_class {
	NACRE_UACCESS_SCOPE_CLASS_UNKNOWN = 0,
	NACRE_UACCESS_SCOPE_STRING_READ = 1,
};

enum nacre_uaccess_scope_direction {
	NACRE_UACCESS_SCOPE_DIR_UNKNOWN = 0,
	NACRE_UACCESS_SCOPE_DIR_FROM_USER = 1,
	NACRE_UACCESS_SCOPE_DIR_TO_USER = 2,
};

#define NACRE_UACCESS_STRING_READ_DESC_VERSION	1UL
#define NACRE_UACCESS_STRING_READ_NO_NUL		(~0UL)

enum nacre_uaccess_string_read_op {
	NACRE_UACCESS_STRING_READ_OP_UNKNOWN = 0,
	NACRE_UACCESS_STRING_READ_OP_COPY_CSTR = 1,
	NACRE_UACCESS_STRING_READ_OP_MEASURE_CSTR = 2,
};

struct nacre_uaccess_string_read_desc {
	unsigned long version;
	unsigned long op;
	unsigned long flags;
	unsigned long buffer_va;
	unsigned long buffer_bytes;
	unsigned long count;
	unsigned long scanned_bytes;
	unsigned long copied_bytes;
	unsigned long nul_index;
	unsigned long private_bytes;
	unsigned long caller_pc;
};

#define NACRE_USER_VPN2_PROTECTED_SLOTS 256UL
#define NACRE_USER_VPN2_SLOT_SIZE       (1UL << 30)
#define NACRE_USER_VPN2_PROTECTED_END \
	(NACRE_USER_VPN2_PROTECTED_SLOTS * NACRE_USER_VPN2_SLOT_SIZE)

#define NACRE_AGENT_VA_BASE		0x3ec0000000UL
#define NACRE_AGENT_VA_SLOT_SIZE		(1UL << 30)
#define NACRE_AGENT_VA_SLOT_END \
	(NACRE_AGENT_VA_BASE + NACRE_AGENT_VA_SLOT_SIZE)
#define NACRE_SEMANTIC_MAX_PFNS	16UL

static inline bool nacre_private_data_uaccess_active(void)
{
	/* Runtime I/O uses the NORMAL buffer through native uaccess only. */
	return current->mm && current->mm->context.nacre_private &&
	       !current->mm->context.nacre_prepared;
}

#ifdef CONFIG_MMU
bool nacre_vma_is_vvar_abi_data(const struct vm_area_struct *vma);
bool nacre_vma_is_vdso_text(const struct vm_area_struct *vma);
int nacre_adopt_vdso_text(struct vm_area_struct *vma);
#else
static inline bool nacre_vma_is_vvar_abi_data(const struct vm_area_struct *vma)
{
	(void)vma;
	return false;
}
static inline bool nacre_vma_is_vdso_text(const struct vm_area_struct *vma)
{
	(void)vma;
	return false;
}
static inline int nacre_adopt_vdso_text(struct vm_area_struct *vma)
{
	(void)vma;
	return 0;
}
#endif

int nacre_record_vvar_sbi(unsigned long root_pgd_pa, unsigned long addr,
			 unsigned long pfn);
int nacre_adopt_vdso_sbi(unsigned long root_pgd_pa, unsigned long addr,
			unsigned long nr_pages, unsigned long source_pfns_pa);
bool nacre_copy_mc_user_highpage_sbi(struct page *to, struct page *from,
				    unsigned long vaddr,
				    struct vm_area_struct *vma);
bool nacre_uaccess_scope_begin(enum nacre_uaccess_scope_class scope_class,
			      enum nacre_uaccess_scope_direction direction,
			      unsigned long user_va,
			      unsigned long bytes,
			      unsigned long caller_pc);
int nacre_uaccess_string_read_begin(unsigned long user_va,
				   unsigned long bytes,
				   struct nacre_uaccess_string_read_desc *desc);
bool nacre_uaccess_scope_end(enum nacre_uaccess_scope_class scope_class,
			    enum nacre_uaccess_scope_direction direction,
			    unsigned long user_va,
			    unsigned long bytes,
			    long result);
int nacre_private_data_get_user_read(unsigned long user_va,
				    unsigned long bytes,
				    unsigned long *value);
int nacre_private_data_put_user_write(unsigned long user_va,
				     const void *value,
				     unsigned long bytes);
int nacre_private_data_copy_to_user(unsigned long user_va,
				   unsigned long kernel_va,
				   unsigned long bytes,
				   unsigned long caller_pc,
				   unsigned long *left);
int nacre_private_data_copy_from_user(unsigned long kernel_va,
				     unsigned long user_va,
				     unsigned long bytes,
				     unsigned long caller_pc,
				     unsigned long *left);
int nacre_private_data_copy_kernel_alias(unsigned long destination_kernel_va,
					unsigned long source_kernel_va,
					unsigned long bytes,
					unsigned long caller_pc,
					unsigned long *left);
int nacre_private_data_clear_user(unsigned long user_va,
				 unsigned long bytes,
				 unsigned long caller_pc,
				 unsigned long *left);
long nacre_signal_frame_export(struct ksignal *ksig, sigset_t *mask,
			       unsigned long stack, unsigned long buffer,
			       struct pt_regs *regs);
long nacre_signal_frame_restore(unsigned long buffer, struct pt_regs *regs);
#endif

#endif /* _ASM_RISCV_NACRE_H */
