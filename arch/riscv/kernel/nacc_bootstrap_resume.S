/* SPDX-License-Identifier: GPL-2.0-only */
/* 从一次性 AS bootstrap trap frame 进入不返回的 Linux continuation。 */

#include <linux/linkage.h>

SYM_CODE_START(nacc_linux_bootstrap_resume)
	.option push
	.option norelax
	la gp, __global_pointer$
	.option pop
	tail nacc_linux_bootstrap_complete
SYM_CODE_END(nacc_linux_bootstrap_resume)
