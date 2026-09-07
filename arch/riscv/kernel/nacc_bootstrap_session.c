// SPDX-License-Identifier: GPL-2.0-only
/* NACC single-hart boot→AS→Linux activation adapter。 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/sched/task_stack.h>

#include <asm/csr.h>
#include <asm/nacc_agent_image.h>
#include <asm/nacc_bootstrap.h>
#include <asm/nacc_bootstrap_session.h>
#include <asm/nacc_root.h>
#include <asm/ptrace.h>
#include <asm/sbi.h>
#include <asm/tlbflush.h>

static struct nacc_linux_bootstrap_session nacc_linux_session;
static DECLARE_COMPLETION(nacc_linux_bootstrap_complete_event);
static struct task_struct *nacc_linux_bootstrap_task;

static unsigned long nacc_linux_bootstrap_stack_top(struct task_struct *task)
{
	return (unsigned long)task_stack_page(task) + THREAD_SIZE;
}

void nacc_linux_bootstrap_enter(const struct nacc_bootstrap_descriptor *descriptor,
				const struct nacc_root_build_result *root)
{
	const struct nacc_agent_image_metadata *image;
	struct sbiret result;
	unsigned long flags;
	u64 context_address;
	u64 control_satp;
	u64 old_satp;
	int ret;

	if (!descriptor || !root || current != nacc_linux_bootstrap_task ||
	    num_online_cpus() != 1 || smp_processor_id() != 0)
		panic("NACC bootstrap enter invariant failed");
	if (nacc_bootstrap_validate(descriptor, sizeof(*descriptor)) ||
	    root->root_physical_address != descriptor->control_root_l0.base)
		panic("NACC bootstrap enter root invariant failed");
	image = nacc_agent_image_metadata_snapshot();
	if (image->boot_context_offset >
	    NACC_BOOTSTRAP_SV39_USER_LIMIT - descriptor->agent_virtual_base)
		panic("NACC bootstrap context VA overflow");
	context_address = descriptor->agent_virtual_base +
			  image->boot_context_offset;
	old_satp = csr_read(CSR_SATP);
	control_satp = NACC_LINUX_SESSION_SATP_MODE_SV39 |
		       (root->root_physical_address >> PAGE_SHIFT);
	ret = nacc_linux_bootstrap_session_arm(&nacc_linux_session,
					       context_address,
					       descriptor->bootstrap_sequence,
					       (unsigned long)current, old_satp,
					       control_satp);
	if (ret)
		panic("NACC Linux bootstrap session arm failed (%d)", ret);

	pr_info("NACC boot->AS bootstrap request\n");
	local_irq_save(flags);
	/* AS trap 必须先有可供 handle_exception 使用的 Linux kernel stack。 */
	current->thread_info.kernel_sp = nacc_linux_bootstrap_stack_top(current);
	csr_write(CSR_SATP, control_satp);
	local_flush_tlb_all();
	result = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_BOOTSTRAP,
			   (unsigned long)descriptor, sizeof(*descriptor),
			   0, 0, 0, 0);
	csr_write(CSR_SATP, old_satp);
	local_flush_tlb_all();
	local_irq_restore(flags);
	if (nacc_linux_bootstrap_session_fail(&nacc_linux_session))
		panic("NACC bootstrap SBI returned after session state changed");
	panic("NACC bootstrap SBI failed (%ld, value=%ld)",
	      result.error, result.value);
}

long nacc_linux_bootstrap_ready(struct pt_regs *regs)
{
	struct nacc_linux_bootstrap_ready_request request;
	unsigned long stack_top;
	int ret;

	if (!regs || current != nacc_linux_bootstrap_task ||
	    csr_read(CSR_SATP) != nacc_linux_session.control_satp ||
	    (unsigned long)current != nacc_linux_session.linux_thread_pointer)
		panic("NACC BOOTSTRAP_READY execution invariant failed");
	pr_info("NACC AS->Linux BOOTSTRAP_READY request\n");
	request = (struct nacc_linux_bootstrap_ready_request) {
		.context_address = regs->a0,
		.context_size = regs->a1,
		.bootstrap_sequence = regs->a2,
		.handshake_cookie = regs->a3,
		.current_thread_pointer = (unsigned long)current,
		.reserved = { regs->a4, regs->a5, regs->a6 },
	};
	ret = nacc_linux_bootstrap_session_ready_commit(&nacc_linux_session,
							&request);
	if (ret)
		panic("NACC BOOTSTRAP_READY rejected (%d)", ret);

	stack_top = nacc_linux_bootstrap_stack_top(current);
	current->thread_info.kernel_sp = stack_top;
	csr_write(CSR_SATP, nacc_linux_session.old_satp);
	local_flush_tlb_all();
	regs->epc = (unsigned long)nacc_linux_bootstrap_resume;
	regs->sp = stack_top;
	regs->tp = nacc_linux_session.linux_thread_pointer;
	regs->status &= ~(SR_SIE | SR_SPIE | SR_SUM | SR_FS_VS);
	regs->status |= SR_SPP;
	regs->asstatus &= ~SR_ASSTATUS_SPA;
	return 0;
}

asmlinkage __visible __noreturn void nacc_linux_bootstrap_complete(void)
{
	if (current != nacc_linux_bootstrap_task ||
	    !nacc_linux_bootstrap_session_is_ready(&nacc_linux_session) ||
	    csr_read(CSR_SATP) != nacc_linux_session.old_satp ||
	    (csr_read(CSR_ASSTATUS) & SR_ASSTATUS_SPA))
		panic("NACC Linux bootstrap continuation invariant failed");
	local_irq_enable();
	pr_info("NACC boot->AS->Linux bootstrap ready\n");
	kthread_complete_and_exit(&nacc_linux_bootstrap_complete_event, 0);
}

static int nacc_linux_bootstrap_thread(void *unused)
{
	(void)unused;
	nacc_linux_bootstrap_enter(nacc_root_descriptor_snapshot(),
				   nacc_root_result_snapshot());
	panic("NACC bootstrap enter returned");
}

static int __init nacc_linux_bootstrap_init(void)
{
	unsigned long capabilities = nacc_bootstrap_sbi_capabilities();
	struct task_struct *task;

	if (!nacc_bootstrap_capabilities_allow_bootstrap(capabilities))
		return 0;
	if (!nacc_root_is_ready())
		panic("NACC bootstrap capability lacks a prepared control root");
	task = kthread_create(nacc_linux_bootstrap_thread, NULL, "nacc-bootstrap");
	if (IS_ERR(task))
		panic("NACC bootstrap kthread creation failed (%ld)",
		      PTR_ERR(task));
	nacc_linux_bootstrap_task = task;
	wake_up_process(task);
	wait_for_completion(&nacc_linux_bootstrap_complete_event);
	if (!nacc_linux_bootstrap_session_is_ready(&nacc_linux_session))
		panic("NACC bootstrap completion lacks READY state");
	return 0;
}
late_initcall(nacc_linux_bootstrap_init);
