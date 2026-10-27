/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_NACRE_SHMEM_H
#define _LINUX_NACRE_SHMEM_H
#include <linux/mm_types.h>
struct inode;
struct file;
struct folio;
struct nacre_shmem;
int shmem_nacre_get_folio(struct vm_fault *vmf, struct folio **folio);
#ifdef CONFIG_RISCV
int nacre_shmem_create(struct inode *inode);
int nacre_shmem_io(struct inode *inode);
int nacre_shmem_resize(struct inode *inode);
int nacre_shmem_mmap(struct file *file, struct vm_area_struct *vma);
bool nacre_shmem_vma(struct vm_area_struct *vma);
bool nacre_shmem_protected(struct inode *inode);
void nacre_shmem_evict(struct inode *inode);
void nacre_shmem_run_cleanup(unsigned long run);
unsigned long nacre_shmem_run(struct mm_struct *mm);
void nacre_shmem_map(struct vm_fault *vmf, unsigned long value);
/* Flags: bit0 checks both FDs; bits1/2 mark splice input/output offsets. */
long nacre_shmem_precheck(unsigned long fd, unsigned long second, unsigned long flags);
#else
static inline int nacre_shmem_create(struct inode *i) { return 0; }
static inline int nacre_shmem_io(struct inode *i) { return 0; }
static inline int nacre_shmem_resize(struct inode *i) { return 0; }
static inline int nacre_shmem_mmap(struct file *f, struct vm_area_struct *v) { return 0; }
static inline bool nacre_shmem_vma(struct vm_area_struct *v) { return false; }
static inline bool nacre_shmem_protected(struct inode *i) { return false; }
static inline void nacre_shmem_evict(struct inode *i) { }
static inline void nacre_shmem_map(struct vm_fault *v, unsigned long pte) { }
#endif
#endif
