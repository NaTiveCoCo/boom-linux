// SPDX-License-Identifier: GPL-2.0-only
/* Linux → AS lifecycle request 与 terminal response continuation。 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>

#include <asm/csr.h>
#include <asm/nacc_bootstrap.h>
#include <asm/nacc_bootstrap_session.h>
#include <asm/nacc_root.h>
#include <asm/nacc_runtime.h>
#include <asm/nacc_runtime_session.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>

struct nacc_linux_runtime_call {
	struct completion completion;
	struct nacc_runtime_lifecycle_request request;
	struct nacc_runtime_lifecycle_result result;
	u64 linux_satp;
	u64 control_satp;
	u64 mailbox_virtual_address;
	u64 runtime_entry_address;
	int error;
};

static DEFINE_MUTEX(nacc_linux_runtime_mutex);
static struct nacc_linux_runtime_session nacc_linux_runtime_session
	__aligned(NACC_ENTER_MAILBOX_SIZE);
static struct task_struct *nacc_linux_runtime_task;
static struct nacc_linux_runtime_call *nacc_linux_runtime_call;

static unsigned long nacc_linux_runtime_stack_top(struct task_struct *task)
{
	return (unsigned long)task_stack_page(task) + THREAD_SIZE;
}

static void nacc_linux_runtime_session_require_idle(void)
{
	const struct nacc_bootstrap_descriptor *descriptor;
	int ret;

	if (nacc_linux_runtime_session.state ==
	    NACC_RUNTIME_SESSION_UNINITIALIZED) {
		descriptor = nacc_root_descriptor_snapshot();
		if (descriptor->bootstrap_sequence == U64_MAX)
			panic("NACC runtime initial sequence overflow");
		ret = nacc_linux_runtime_session_initialize(
			&nacc_linux_runtime_session,
			descriptor->bootstrap_sequence + 1);
		if (ret)
			panic("NACC runtime session initialization failed (%d)",
			      ret);
	}
	if (nacc_linux_runtime_session.state != NACC_RUNTIME_SESSION_IDLE)
		panic("NACC runtime session is not idle");
}

static void __noreturn nacc_linux_runtime_thread_fail(
	struct nacc_linux_runtime_call *call, int error)
{
	if (nacc_linux_runtime_session.state != NACC_RUNTIME_SESSION_IDLE)
		panic("NACC runtime thread failed after request publication");
	call->error = error;
	WRITE_ONCE(nacc_linux_runtime_call, NULL);
	WRITE_ONCE(nacc_linux_runtime_task, NULL);
	kthread_complete_and_exit(&call->completion, 0);
}

static int nacc_linux_runtime_thread(void *opaque)
{
	const struct nacc_bootstrap_descriptor *descriptor;
	const struct nacc_root_build_result *root;
	struct nacc_linux_runtime_call *call = opaque;
	void __iomem *mailbox_alias;
	void *request_page;
	unsigned long stack_top;
	int ret;

	if (!call || current != READ_ONCE(nacc_linux_runtime_task) ||
	    call != READ_ONCE(nacc_linux_runtime_call) ||
	    num_online_cpus() != 1 || raw_smp_processor_id() != 0)
		panic("NACC runtime thread ownership invariant failed");
	descriptor = nacc_root_descriptor_snapshot();
	root = nacc_root_result_snapshot();
	call->runtime_entry_address = nacc_linux_runtime_entry_snapshot();
	call->control_satp = NACC_LINUX_SESSION_SATP_MODE_SV39 |
		(root->root_physical_address >> PAGE_SHIFT);
	call->mailbox_virtual_address = descriptor->mailbox_virtual_base;

	request_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!request_page)
		nacc_linux_runtime_thread_fail(call, -ENOMEM);
	ret = nacc_runtime_lifecycle_message_build(
		request_page, PAGE_SIZE, &call->request);
	if (ret)
		panic("NACC runtime request build failed (%d)", ret);
	/* memremap(WB) 可能为 NOMAP PFN 返回无效的 direct-map alias。 */
	mailbox_alias = ioremap_prot(descriptor->mailbox.base, PAGE_SIZE,
				     _PAGE_KERNEL);
	if (!mailbox_alias) {
		free_page((unsigned long)request_page);
		nacc_linux_runtime_thread_fail(call, -ENOMEM);
	}
	ret = nacc_linux_runtime_session_arm(
		&nacc_linux_runtime_session, &call->request);
	if (ret)
		panic("NACC runtime request arm failed (%d)", ret);
	memcpy_toio(mailbox_alias, request_page, PAGE_SIZE);
	/* Agent 的 acquire fence 只能观察完整的一页 request。 */
	mb();
	iounmap(mailbox_alias);
	free_page((unsigned long)request_page);

	/* 此后直到 AS response continuation 都不得调度或接收中断。 */
	local_irq_disable();
	call->linux_satp = csr_read(CSR_SATP);
	if ((call->linux_satp & NACC_LINUX_SESSION_SATP_MODE_MASK) !=
		    NACC_LINUX_SESSION_SATP_MODE_SV39 ||
	    (call->linux_satp & NACC_LINUX_SESSION_SATP_PPN_MASK) ==
		    (call->control_satp & NACC_LINUX_SESSION_SATP_PPN_MASK) ||
	    (csr_read(CSR_ASSTATUS) & SR_ASSTATUS_SPA))
		panic("NACC runtime entry state invariant failed");
	stack_top = nacc_linux_runtime_stack_top(current);
	current->thread_info.kernel_sp = stack_top;
	nacc_linux_runtime_enter(call->runtime_entry_address,
				 call->control_satp);
}

int nacc_linux_runtime_lifecycle_call(
	const struct nacc_runtime_lifecycle_request *request,
	struct nacc_runtime_lifecycle_result *result)
{
	struct nacc_linux_runtime_call call = {};
	struct task_struct *task;
	int ret;

	if (!request || !result || request->sequence)
		return -EINVAL;
	call.request = *request;
	call.request.sequence = 1;
	if (nacc_runtime_lifecycle_request_validate(&call.request))
		return -EINVAL;

	mutex_lock(&nacc_linux_runtime_mutex);
	nacc_linux_runtime_session_require_idle();
	call.request.sequence = nacc_linux_runtime_session.next_sequence;
	init_completion(&call.completion);
	task = kthread_create(nacc_linux_runtime_thread, &call, "nacc-runtime");
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto out_unlock;
	}
	WRITE_ONCE(nacc_linux_runtime_call, &call);
	WRITE_ONCE(nacc_linux_runtime_task, task);
	wake_up_process(task);
	wait_for_completion(&call.completion);
	if (READ_ONCE(nacc_linux_runtime_call) ||
	    READ_ONCE(nacc_linux_runtime_task))
		panic("NACC runtime completion retained stale ownership");
	ret = call.error;
	if (!ret)
		*result = call.result;

out_unlock:
	mutex_unlock(&nacc_linux_runtime_mutex);
	return ret;
}

void nacc_linux_runtime_response(struct pt_regs *regs)
{
	struct nacc_linux_runtime_call *call =
		READ_ONCE(nacc_linux_runtime_call);
	nacc_enter_u64 reserved_registers[5];
	unsigned long stack_top;
	int ret;

	if (!regs || !call || current != READ_ONCE(nacc_linux_runtime_task) ||
	    csr_read(CSR_SATP) != call->control_satp)
		panic("NACC runtime response ownership invariant failed");
	reserved_registers[0] = regs->a2;
	reserved_registers[1] = regs->a3;
	reserved_registers[2] = regs->a4;
	reserved_registers[3] = regs->a5;
	reserved_registers[4] = regs->a6;
	/* 与 Agent 完整发布 response 后的 release fence 配对。 */
	mb();
	ret = nacc_linux_runtime_session_response_capture(
		&nacc_linux_runtime_session,
		(const void *)(unsigned long)call->mailbox_virtual_address,
		PAGE_SIZE, regs->a0, regs->a1, reserved_registers);
	if (ret)
		panic("NACC runtime response capture failed (%d)", ret);

	stack_top = nacc_linux_runtime_stack_top(current);
	current->thread_info.kernel_sp = stack_top;
	csr_write(CSR_SATP, call->linux_satp);
	local_flush_tlb_all();
	regs->epc = (unsigned long)nacc_linux_runtime_response_resume;
	regs->sp = stack_top;
	regs->tp = (unsigned long)current;
	regs->status &= ~(SR_SIE | SR_SPIE | SR_SUM | SR_FS_VS);
	regs->status |= SR_SPP;
	regs->asstatus &= ~SR_ASSTATUS_SPA;
}

asmlinkage __visible __noreturn void
nacc_linux_runtime_response_complete(void)
{
	struct nacc_linux_runtime_call *call =
		READ_ONCE(nacc_linux_runtime_call);
	int ret;

	if (!call || current != READ_ONCE(nacc_linux_runtime_task) ||
	    csr_read(CSR_SATP) != call->linux_satp ||
	    (csr_read(CSR_ASSTATUS) & SR_ASSTATUS_SPA))
		panic("NACC runtime response continuation invariant failed");
	ret = nacc_linux_runtime_session_complete(
		&nacc_linux_runtime_session, call->request.sequence,
		&call->result);
	if (ret)
		panic("NACC runtime response validation failed (%d)", ret);
	call->error = 0;
	WRITE_ONCE(nacc_linux_runtime_call, NULL);
	WRITE_ONCE(nacc_linux_runtime_task, NULL);
	local_irq_enable();
	kthread_complete_and_exit(&call->completion, 0);
}
