/* SPDX-License-Identifier: GPL-2.0-only */
/* 从 terminal AS EXIT trap frame 进入不返回的 Linux task-exit continuation。 */

#include <linux/linkage.h>

SYM_CODE_START(nacc_linux_runtime_exit_resume)
	.option push
	.option norelax
	la gp, __global_pointer$
	.option pop
	tail nacc_linux_runtime_exit_complete
SYM_CODE_END(nacc_linux_runtime_exit_resume)
