/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_NACRE_PTP_H
#define _ASM_RISCV_NACRE_PTP_H

#include <linux/types.h>
struct mm_struct;
struct ptdesc;
struct page;
int nacre_private_prepare(struct mm_struct *mm);
int nacre_protnone_reserve(struct mm_struct *mm, unsigned long start, unsigned long end);
void nacre_protnone_finish(struct mm_struct *mm, unsigned long start,
			   unsigned long end, bool abort);
void nacre_private_claim(struct mm_struct *mm, void *slot, unsigned long value,
                         unsigned long source, unsigned long op);

bool nacre_mm_private(struct mm_struct *mm);
bool nacre_mm_managed(struct mm_struct *mm);
void nacre_mm_init(struct mm_struct *mm);
void nacre_root_retire(struct mm_struct *mm);
unsigned long nacre_root_entry(struct mm_struct *mm, unsigned long addr);
bool nacre_agent_slot(struct mm_struct *mm, unsigned long addr);
bool nacre_ptp_contains(const void *ptr);
struct ptdesc *nacre_ptp_alloc(struct mm_struct *mm, unsigned int level);
void nacre_ptp_dtor(struct ptdesc *ptdesc, unsigned long pfn,
		    unsigned int level, const char *tag);
bool nacre_ptp_release(struct mm_struct *mm, struct ptdesc *ptdesc,
                        unsigned int level, bool installed);
bool nacre_ptp_populate(struct mm_struct *mm, void *slot, unsigned long pfn);
void nacre_ptp_unlink(struct mm_struct *mm, void *slot, unsigned long pfn);
unsigned long nacre_ptp_update(void *slot, unsigned long value, unsigned long op);
#endif
