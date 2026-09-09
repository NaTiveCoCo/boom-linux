// SPDX-License-Identifier: GPL-2.0-only
/* Linux → AS lifecycle request、同步 syscall 与 terminal continuation。 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
#include <linux/userfaultfd_k.h>

#include <asm/csr.h>
#include <asm/nacc_bootstrap.h>
#include <asm/nacc_bootstrap_session.h>
#include <asm/nacc_root.h>
#include <asm/nacc_runtime.h>
#include <asm/nacc_runtime_session.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/unistd.h>

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

struct nacc_linux_runtime_syscall_owner {
	u64 active;
	u64 number;
	u64 arguments[6];
	u64 as_epc;
};

enum nacc_linux_runtime_munmap_state {
	NACC_LINUX_RUNTIME_MUNMAP_IDLE = 0,
	NACC_LINUX_RUNTIME_MUNMAP_PREPARED,
	NACC_LINUX_RUNTIME_MUNMAP_REMOVED,
};

enum nacc_linux_runtime_munmap_stage {
	NACC_LINUX_RUNTIME_MUNMAP_PREPARE = 0,
	NACC_LINUX_RUNTIME_MUNMAP_COMMIT = 1,
	NACC_LINUX_RUNTIME_MUNMAP_ABORT = 2,
	NACC_LINUX_RUNTIME_MUNMAP_FINISH = 3,
};

struct nacc_linux_runtime_munmap_owner {
	u64 state;
	u64 generation;
	struct mm_struct *mm;
	unsigned long address;
	unsigned long length;
};

struct nacc_linux_runtime_enter_owner {
	struct task_struct *task;
	u64 sequence;
	u64 linux_satp;
	u64 control_satp;
	u64 live_satp;
	u64 mailbox_virtual_address;
	u64 mmap_active;
	struct vm_area_struct *mmap_vma;
	vm_flags_t mmap_vm_flags;
	u64 next_munmap_generation;
	struct nacc_linux_runtime_munmap_owner munmap;
	struct nacc_linux_runtime_syscall_owner syscall;
};

static struct nacc_linux_runtime_enter_owner nacc_linux_runtime_enter_owner;

bool nacc_linux_runtime_syscall_is_active(void)
{
	return READ_ONCE(nacc_linux_runtime_enter_owner.syscall.active) != 0;
}

bool nacc_linux_runtime_syscall_live_root_is_current(void)
{
	struct nacc_linux_runtime_enter_owner owner =
		nacc_linux_runtime_enter_owner;

	return owner.syscall.active && owner.live_satp &&
		csr_read(CSR_SATP) == owner.live_satp;
}

bool nacc_linux_runtime_switch_live_root(struct task_struct *task,
					struct mm_struct *mm)
{
	struct nacc_linux_runtime_enter_owner owner =
		nacc_linux_runtime_enter_owner;

	if (!owner.syscall.active || task != owner.task)
		return false;
	if (!task || !mm || task->mm != mm || !owner.live_satp)
		panic("NACC syscall schedule-in invariant failed");
	csr_write(CSR_SATP, owner.live_satp);
	local_flush_tlb_all();
	return true;
}

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
	pr_info("NACC Agent lifecycle opcode %#x begin\n", request->opcode);

	mutex_lock(&nacc_linux_runtime_mutex);
	pr_info("NACC Agent lifecycle opcode %#x locked\n", request->opcode);
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
	pr_info("NACC Agent lifecycle opcode %#x return %d\n",
		request->opcode, ret);
	mutex_unlock(&nacc_linux_runtime_mutex);
	return ret;
}

void __noreturn nacc_linux_runtime_exec_enter(
	const struct nacc_enter_message_request *request)
{
	const struct nacc_bootstrap_descriptor *descriptor;
	const struct nacc_root_build_result *root;
	struct nacc_enter_message_request active_request;
	void __iomem *mailbox_alias;
	void *request_page;
	u64 control_satp;
	unsigned long handoff_sp;
	unsigned long stack_bottom;
	unsigned long stack_top;
	unsigned long trap_frame_size;
	int ret;

	if (!request || request->sequence || current->flags & PF_KTHREAD ||
	    num_online_cpus() != 1 || raw_smp_processor_id() != 0)
		panic("NACC exec ENTER caller invariant failed");
	active_request = *request;
	pr_info("NACC Linux runtime ENTER begin\n");
	mutex_lock(&nacc_linux_runtime_mutex);
	pr_info("NACC Linux runtime ENTER locked\n");
	nacc_linux_runtime_session_require_idle();
	if (READ_ONCE(nacc_linux_runtime_task) ||
	    READ_ONCE(nacc_linux_runtime_call) ||
	    READ_ONCE(nacc_linux_runtime_enter_owner.task))
		panic("NACC exec ENTER found stale runtime ownership");
	active_request.sequence = nacc_linux_runtime_session.next_sequence;
	descriptor = nacc_root_descriptor_snapshot();
	root = nacc_root_result_snapshot();
	control_satp = NACC_LINUX_SESSION_SATP_MODE_SV39 |
		(root->root_physical_address >> PAGE_SHIFT);
	request_page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!request_page)
		panic("NACC exec ENTER request allocation failed");
	ret = nacc_enter_message_build(request_page, PAGE_SIZE,
				       &active_request);
	if (ret)
		panic("NACC exec ENTER message build failed (%d)", ret);
	mailbox_alias = ioremap_prot(descriptor->mailbox.base, PAGE_SIZE,
				     _PAGE_KERNEL);
	if (!mailbox_alias)
		panic("NACC exec ENTER mailbox mapping failed");
	memcpy_toio(mailbox_alias, request_page, PAGE_SIZE);
	/* Agent acquire 只能在完整 ENTER page 发布后运行。 */
	mb();
	pr_info("NACC Linux runtime ENTER published\n");
	iounmap(mailbox_alias);
	free_page((unsigned long)request_page);

	pr_info("NACC Linux runtime ENTER switch\n");
	local_irq_disable();
	if ((csr_read(CSR_SATP) & NACC_LINUX_SESSION_SATP_MODE_MASK) !=
		    NACC_LINUX_SESSION_SATP_MODE_SV39 ||
	    (csr_read(CSR_SATP) & NACC_LINUX_SESSION_SATP_PPN_MASK) ==
		    (control_satp & NACC_LINUX_SESSION_SATP_PPN_MASK) ||
	    (csr_read(CSR_ASSTATUS) & SR_ASSTATUS_SPA))
		panic("NACC exec ENTER handoff state invariant failed");
	nacc_linux_runtime_enter_owner = (struct nacc_linux_runtime_enter_owner) {
		.task = current,
		.sequence = active_request.sequence,
		.linux_satp = csr_read(CSR_SATP),
		.control_satp = control_satp,
		.live_satp = NACC_LINUX_SESSION_SATP_MODE_SV39 |
			(active_request.live_root_physical_address >> PAGE_SHIFT),
		.mailbox_virtual_address = descriptor->mailbox_virtual_base,
		.next_munmap_generation = 1,
	};
	/* IRQ-disabled owner snapshot 必须先于 Agent ENTER 可见。 */
	mb();
	stack_bottom = (unsigned long)task_stack_page(current);
	stack_top = nacc_linux_runtime_stack_top(current);
	handoff_sp = current_stack_pointer;
	trap_frame_size = ALIGN(sizeof(struct pt_regs), STACK_ALIGN);
	if (handoff_sp < stack_bottom || handoff_sp >= stack_top ||
	    handoff_sp & (STACK_ALIGN - 1) ||
	    handoff_sp - stack_bottom < trap_frame_size)
		panic("NACC exec ENTER live stack invariant failed");
	/* 首个 AS trap frame 必须落在已放弃的 exec continuation 下方。 */
	current->thread_info.kernel_sp = handoff_sp;
	nacc_linux_runtime_enter(nacc_linux_runtime_entry_snapshot(),
				 control_satp);
}

void nacc_linux_runtime_syscall_capture(struct pt_regs *regs)
{
	struct nacc_linux_runtime_enter_owner owner =
		nacc_linux_runtime_enter_owner;
	unsigned long stack_top;

	/* trap 区只捕获公开参数；可阻塞的 syscall 必须移到 Linux continuation。 */
	if (!regs || !irqs_disabled() || !owner.task || owner.task != current ||
	    !owner.sequence || !owner.live_satp || owner.syscall.active ||
	    csr_read(CSR_SATP) != owner.live_satp)
		panic("NACC AS syscall invariant failed");
	switch (regs->a0) {
	case __NR_write:
	case __NR_writev:
		if (regs->a1 != 2 ||
		    regs->a2 != owner.mailbox_virtual_address || !regs->a3 ||
		    regs->a3 > PAGE_SIZE || regs->a4 || regs->a5 || regs->a6)
			panic("NACC AS write/writev syscall invariant failed");
		break;
	case __NR_getpid:
		if (regs->a1 || regs->a2 || regs->a3 || regs->a4 || regs->a5 ||
		    regs->a6)
			panic("NACC AS getpid syscall invariant failed");
		break;
	case __NR_mmap:
		break;
	case __NR_munmap:
		if (regs->a3 > NACC_LINUX_RUNTIME_MUNMAP_FINISH ||
		    regs->a5 || regs->a6)
			panic("NACC AS munmap syscall invariant failed");
		break;
	default:
		panic("NACC AS unsupported syscall invariant failed");
	}
	nacc_linux_runtime_enter_owner.syscall =
		(struct nacc_linux_runtime_syscall_owner) {
		.active = 1,
		.number = regs->a0,
		.arguments = { regs->a1, regs->a2, regs->a3, regs->a4,
			       regs->a5, regs->a6 },
		.as_epc = regs->epc,
	};
	mb();
	stack_top = nacc_linux_runtime_stack_top(current) -
		ALIGN(sizeof(struct pt_regs), STACK_ALIGN);
	current->thread_info.kernel_sp = stack_top;
	regs->epc = (unsigned long)nacc_linux_runtime_syscall_resume;
	regs->sp = stack_top;
	regs->tp = (unsigned long)current;
	regs->status &= ~(SR_SIE | SR_SPIE | SR_SUM | SR_FS_VS);
	regs->status |= SR_SPP;
	regs->asstatus &= ~SR_ASSTATUS_SPA;
}

static long nacc_linux_runtime_write_bounce(
	const struct nacc_linux_runtime_enter_owner *owner)
{
	struct fd f = fdget_pos(owner->syscall.arguments[0]);
	loff_t position;
	loff_t *position_pointer = NULL;
	ssize_t ret;

	if (!f.file)
		return -EBADF;
	if (!(f.file->f_mode & FMODE_STREAM)) {
		position = f.file->f_pos;
		position_pointer = &position;
	}
	ret = kernel_write(f.file, (const void *)owner->syscall.arguments[1],
			   owner->syscall.arguments[2],
			   position_pointer);
	if (ret >= 0 && position_pointer)
		f.file->f_pos = position;
	fdput_pos(f);
	return ret;
}

static long nacc_linux_runtime_mmap_one_page(
	const struct nacc_linux_runtime_enter_owner *owner)
{
	struct vm_area_struct *vma;
	unsigned long result;

	if (owner->syscall.arguments[0] ||
	    owner->syscall.arguments[1] != PAGE_SIZE ||
	    owner->syscall.arguments[2] != (PROT_READ | PROT_WRITE) ||
	    owner->syscall.arguments[3] != (MAP_PRIVATE | MAP_ANONYMOUS) ||
	    owner->syscall.arguments[4] != ULONG_MAX ||
	    owner->syscall.arguments[5])
		return -EINVAL;
	result = vm_mmap(NULL, NACC_ENTER_MMAP_VIRTUAL_ADDRESS, PAGE_SIZE,
			 PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0);
	if (IS_ERR_VALUE(result))
		return (long)result;
	if (result != NACC_ENTER_MMAP_VIRTUAL_ADDRESS)
		panic("NACC mmap returned unexpected fixed address");
	if (nacc_linux_runtime_enter_owner.mmap_active ||
	    nacc_linux_runtime_enter_owner.mmap_vma ||
	    nacc_linux_runtime_enter_owner.munmap.state !=
		    NACC_LINUX_RUNTIME_MUNMAP_IDLE)
		panic("NACC mmap publication invariant failed");
	mmap_write_lock(current->mm);
	vma = find_vma(current->mm, NACC_ENTER_MMAP_VIRTUAL_ADDRESS);
	if (!vma || vma->vm_start != NACC_ENTER_MMAP_VIRTUAL_ADDRESS ||
	    vma->vm_end != NACC_ENTER_MMAP_VIRTUAL_ADDRESS + PAGE_SIZE ||
	    vma->vm_file || vma->vm_ops || !vma_is_anonymous(vma) ||
	    userfaultfd_armed(vma) ||
	    vma->vm_flags & (VM_SHARED | VM_EXEC | VM_SPECIAL | VM_HUGETLB |
			     VM_LOCKED) ||
	    (vma->vm_flags & (VM_READ | VM_WRITE)) != (VM_READ | VM_WRITE))
		panic("NACC mmap dedicated VMA invariant failed");
	nacc_linux_runtime_enter_owner.mmap_vma = vma;
	nacc_linux_runtime_enter_owner.mmap_vm_flags = vma->vm_flags;
	nacc_linux_runtime_enter_owner.mmap_active = 1;
	mmap_write_unlock(current->mm);
	return (long)result;
}

static bool nacc_linux_runtime_munmap_vma_is_exact(
	const struct nacc_linux_runtime_enter_owner *owner,
	struct vm_area_struct *vma)
{
	return vma && vma == owner->mmap_vma &&
		vma->vm_start == NACC_ENTER_MMAP_VIRTUAL_ADDRESS &&
		vma->vm_end == NACC_ENTER_MMAP_VIRTUAL_ADDRESS + PAGE_SIZE &&
		vma->vm_flags == owner->mmap_vm_flags && !vma->vm_file &&
		!vma->vm_ops && vma_is_anonymous(vma) &&
		!userfaultfd_armed(vma);
}

static void nacc_linux_runtime_munmap_require_owner(
	const struct nacc_linux_runtime_enter_owner *owner)
{
	if (!owner->task || owner->task != current || !current->mm ||
	    num_online_cpus() != 1 || raw_smp_processor_id() != 0 ||
	    owner->munmap.mm != current->mm ||
	    owner->munmap.address != NACC_ENTER_MMAP_VIRTUAL_ADDRESS ||
	    owner->munmap.length != PAGE_SIZE || !owner->munmap.generation ||
	    !owner->mmap_vma || !owner->mmap_vm_flags)
		panic("NACC munmap owner invariant failed");
	mmap_assert_write_locked(owner->munmap.mm);
}

static long nacc_linux_runtime_munmap_prepare(
	const struct nacc_linux_runtime_enter_owner *owner)
{
	struct vm_area_struct *vma;
	u64 generation;

	if (owner->syscall.arguments[0] != NACC_ENTER_MMAP_VIRTUAL_ADDRESS ||
	    owner->syscall.arguments[1] != PAGE_SIZE ||
	    owner->syscall.arguments[2] != NACC_LINUX_RUNTIME_MUNMAP_PREPARE ||
	    owner->syscall.arguments[3] || owner->syscall.arguments[4] ||
	    owner->syscall.arguments[5])
		return -EINVAL;
	if (!owner->mmap_active ||
	    owner->munmap.state != NACC_LINUX_RUNTIME_MUNMAP_IDLE ||
	    owner->munmap.mm || !owner->next_munmap_generation ||
	    !owner->mmap_vma || !owner->mmap_vm_flags)
		panic("NACC munmap prepare state invariant failed");
	if (signal_pending(current))
		return -EINTR;
	if (mmap_write_lock_killable(current->mm))
		return -EINTR;
	if (signal_pending(current)) {
		mmap_write_unlock(current->mm);
		return -EINTR;
	}
	vma = find_vma(current->mm, NACC_ENTER_MMAP_VIRTUAL_ADDRESS);
	if (!nacc_linux_runtime_munmap_vma_is_exact(owner, vma))
		panic("NACC munmap shadow VMA invariant failed");
	generation = owner->next_munmap_generation;
	if (generation > LONG_MAX)
		panic("NACC munmap generation overflow");
	nacc_linux_runtime_enter_owner.next_munmap_generation = generation + 1;
	nacc_linux_runtime_enter_owner.munmap =
		(struct nacc_linux_runtime_munmap_owner) {
			.state = NACC_LINUX_RUNTIME_MUNMAP_PREPARED,
			.generation = generation,
			.mm = current->mm,
			.address = NACC_ENTER_MMAP_VIRTUAL_ADDRESS,
			.length = PAGE_SIZE,
		};
	return (long)generation;
}

static long nacc_linux_runtime_munmap_continue(
	const struct nacc_linux_runtime_enter_owner *owner)
{
	u64 stage = owner->syscall.arguments[2];
	u64 generation = owner->syscall.arguments[3];
	int ret;

	if (owner->syscall.arguments[0] != owner->munmap.address ||
	    owner->syscall.arguments[1] != owner->munmap.length ||
	    owner->syscall.arguments[4] || owner->syscall.arguments[5] ||
	    generation != owner->munmap.generation)
		panic("NACC munmap continuation identity invariant failed");
	nacc_linux_runtime_munmap_require_owner(owner);
	if (stage == NACC_LINUX_RUNTIME_MUNMAP_COMMIT) {
		if (owner->munmap.state != NACC_LINUX_RUNTIME_MUNMAP_PREPARED)
			panic("NACC munmap commit state invariant failed");
		ret = do_munmap(owner->munmap.mm, owner->munmap.address,
				owner->munmap.length, NULL);
		if (!ret) {
			if (find_vma_intersection(owner->munmap.mm,
					  owner->munmap.address,
					  owner->munmap.address +
						  owner->munmap.length))
				panic("NACC munmap shadow removal invariant failed");
			nacc_linux_runtime_enter_owner.munmap.state =
				NACC_LINUX_RUNTIME_MUNMAP_REMOVED;
		} else if (!nacc_linux_runtime_munmap_vma_is_exact(
				   owner,
				   find_vma(owner->munmap.mm,
					    owner->munmap.address))) {
			panic("NACC munmap rollback VMA invariant failed");
		}
		return ret;
	}
	if (stage == NACC_LINUX_RUNTIME_MUNMAP_ABORT) {
		if (owner->munmap.state != NACC_LINUX_RUNTIME_MUNMAP_PREPARED)
			panic("NACC munmap abort state invariant failed");
		if (!nacc_linux_runtime_munmap_vma_is_exact(
				owner,
				find_vma(owner->munmap.mm, owner->munmap.address)))
			panic("NACC munmap abort VMA invariant failed");
		mmap_write_unlock(owner->munmap.mm);
		nacc_linux_runtime_enter_owner.munmap =
			(struct nacc_linux_runtime_munmap_owner) { 0 };
		return 0;
	}
	if (stage == NACC_LINUX_RUNTIME_MUNMAP_FINISH) {
		if (owner->munmap.state != NACC_LINUX_RUNTIME_MUNMAP_REMOVED ||
		    !owner->mmap_active)
			panic("NACC munmap finish state invariant failed");
		nacc_linux_runtime_enter_owner.mmap_active = 0;
		nacc_linux_runtime_enter_owner.mmap_vma = NULL;
		nacc_linux_runtime_enter_owner.mmap_vm_flags = 0;
		mmap_write_unlock(owner->munmap.mm);
		nacc_linux_runtime_enter_owner.munmap =
			(struct nacc_linux_runtime_munmap_owner) { 0 };
		return 0;
	}
	panic("NACC munmap continuation stage invariant failed");
}

static long nacc_linux_runtime_munmap_one_page(
	const struct nacc_linux_runtime_enter_owner *owner)
{
	if (owner->syscall.arguments[2] ==
	    NACC_LINUX_RUNTIME_MUNMAP_PREPARE)
		return nacc_linux_runtime_munmap_prepare(owner);
	return nacc_linux_runtime_munmap_continue(owner);
}

asmlinkage __visible __noreturn void nacc_linux_runtime_syscall_complete(void)
{
	struct nacc_linux_runtime_enter_owner owner =
		nacc_linux_runtime_enter_owner;
	unsigned long as_epc;
	long result;

	if (!irqs_disabled() || !owner.task || owner.task != current ||
	    !owner.syscall.active || csr_read(CSR_SATP) != owner.live_satp ||
	    (csr_read(CSR_ASSTATUS) & SR_ASSTATUS_SPA))
		panic("NACC syscall continuation invariant failed");
	local_irq_enable();
	/* 当前 slice 不得静默绕过 seccomp/audit/ptrace 等未接通 policy。 */
	if (READ_ONCE(current_thread_info()->syscall_work) &&
	    !(owner.syscall.number == __NR_munmap &&
	      owner.syscall.arguments[2] != NACC_LINUX_RUNTIME_MUNMAP_PREPARE &&
	      owner.munmap.state != NACC_LINUX_RUNTIME_MUNMAP_IDLE))
		result = -ENOSYS;
	/* writev 已由 Agent 严格展平为一个 mailbox buffer。 */
	else if (owner.syscall.number == __NR_write ||
		 owner.syscall.number == __NR_writev)
		result = nacc_linux_runtime_write_bounce(&owner);
	else if (owner.syscall.number == __NR_getpid)
		result = task_tgid_vnr(current);
	else if (owner.syscall.number == __NR_mmap)
		result = nacc_linux_runtime_mmap_one_page(&owner);
	else if (owner.syscall.number == __NR_munmap)
		result = nacc_linux_runtime_munmap_one_page(&owner);
	else
		panic("NACC syscall continuation number invariant failed");
	local_irq_disable();
	if (!irqs_disabled() || current != owner.task ||
	    csr_read(CSR_SATP) != owner.live_satp ||
	    !nacc_linux_runtime_enter_owner.syscall.active)
		panic("NACC syscall completion invariant failed");
	as_epc = owner.syscall.as_epc;
	nacc_linux_runtime_enter_owner.syscall =
		(struct nacc_linux_runtime_syscall_owner) { 0 };
	mb();
	nacc_linux_runtime_syscall_return(result, as_epc);
}

void nacc_linux_runtime_exec_exit_complete(void)
{
	struct nacc_linux_runtime_enter_owner owner =
		nacc_linux_runtime_enter_owner;
	int ret;

	if (!irqs_disabled() || !owner.task || owner.task != current ||
	    !owner.sequence || !owner.linux_satp || !owner.control_satp ||
	    !owner.live_satp || owner.control_satp == owner.live_satp ||
	    csr_read(CSR_SATP) != owner.control_satp ||
	    owner.munmap.state != NACC_LINUX_RUNTIME_MUNMAP_IDLE)
		panic("NACC exec EXIT owner invariant failed");
	csr_write(CSR_SATP, owner.linux_satp);
	local_flush_tlb_all();
	ret = nacc_linux_runtime_session_consume_enter(
		&nacc_linux_runtime_session, owner.sequence);
	if (ret)
		panic("NACC exec EXIT sequence completion failed (%d)", ret);
	nacc_linux_runtime_enter_owner =
		(struct nacc_linux_runtime_enter_owner) { 0 };
	/* safe Linux root 与空 owner 必须先于可抢占的 mutex release。 */
	local_irq_enable();
	mutex_unlock(&nacc_linux_runtime_mutex);
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
