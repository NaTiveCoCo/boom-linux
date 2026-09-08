/* SPDX-License-Identifier: GPL-2.0-only */
/* NACC control device 与 kernel object backend 的内部接口。 */
#ifndef _NACC_INTERNAL_H
#define _NACC_INTERNAL_H

#include <linux/types.h>

struct file;
struct nacc_uapi_header;

int nacc_validate_header(const struct nacc_uapi_header *header,
			 size_t user_size);
u64 nacc_supported_features(void);
int nacc_control_open(struct file *file);
int nacc_control_release(struct file *file);
long nacc_create_agent(struct file *file, void __user *argument,
		       size_t user_size);
long nacc_prepare_exec(struct file *file, void __user *argument,
		       size_t user_size);
long nacc_query_status(struct file *file, void __user *argument,
		       size_t user_size);
long nacc_destroy_agent(struct file *file, void __user *argument,
			 size_t user_size);

#endif /* _NACC_INTERNAL_H */
