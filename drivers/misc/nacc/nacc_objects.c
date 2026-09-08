// SPDX-License-Identifier: GPL-2.0-only
/* NACC control capability、Agent 与 pidfd-bound exec prepare 对象。 */

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/nacc.h>
#include <linux/nacc_exec.h>
#include <linux/nacc_lifecycle.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <asm/nacc_bootstrap.h>
#include <asm/nacc_enter.h>
#include <asm/nacc_live_root.h>
#include <asm/nacc_root.h>
#include <asm/nacc_runtime.h>

#include "nacc_internal.h"

#define NACC_MINIMAL_PAYLOAD_MAPPINGS 2U

struct nacc_agent_object {
	struct kref reference;
	struct nacc_lifecycle_agent lifecycle;
	struct work_struct runtime_retire_work;
	struct nacc_runtime_object_ref runtime_ref;
	bool runtime_ready;
	bool runtime_retiring;
	bool orphaned;
};

struct nacc_control {
	struct nacc_agent_object *agent;
};

struct nacc_prepare_object {
	struct kref reference;
	struct list_head list;
	struct nacc_agent_object *agent;
	struct task_struct *target;
	struct mm_struct *mm;
	struct nacc_live_root_handle *live_root;
	struct nacc_runtime_object_ref runtime_mm_ref;
	struct nacc_runtime_object_ref runtime_thread_ref;
	u64 elf_entry_offset;
	u8 *elf_code_prefix;
	size_t elf_code_prefix_length;
	bool elf_preflight_claimed;
	bool elf_staging;
	bool elf_payload_valid;
	bool exec_attempt_claimed;
	bool runtime_preparing;
	bool runtime_attaching;
	bool runtime_attached;
	bool runtime_retiring;
	struct nacc_lifecycle_exec lifecycle;
	int elf_preflight_errno;
	int post_ponr_errno;
};

static DEFINE_MUTEX(nacc_object_lock);
static LIST_HEAD(nacc_prepare_objects);
static atomic64_t nacc_agent_generation = ATOMIC64_INIT(0);

static void nacc_agent_free(struct kref *reference);

static bool nacc_runtime_ref_equal(struct nacc_runtime_object_ref left,
				   struct nacc_runtime_object_ref right)
{
	return left.handle == right.handle &&
	       left.generation == right.generation;
}

static bool nacc_runtime_ref_is_zero(struct nacc_runtime_object_ref ref)
{
	return !ref.handle && !ref.generation;
}

static int nacc_agent_runtime_retire(struct nacc_agent_object *agent)
{
	const struct nacc_runtime_lifecycle_request request = {
		.opcode = NACC_RUNTIME_AGENT_RETIRE_OPCODE,
		.agent = agent->runtime_ref,
	};
	struct nacc_runtime_lifecycle_result result;
	int ret;

	if (!agent->runtime_ready || !agent->runtime_retiring ||
	    nacc_runtime_ref_is_zero(agent->runtime_ref))
		panic("NACC Agent runtime retire state is invalid");
	ret = nacc_linux_runtime_lifecycle_call(&request, &result);
	if (ret)
		return ret;
	if (result.status != NACC_RUNTIME_LIFECYCLE_STATUS_OK ||
	    !nacc_runtime_ref_equal(result.agent, agent->runtime_ref) ||
	    !nacc_runtime_ref_is_zero(result.mm) ||
	    !nacc_runtime_ref_is_zero(result.thread))
		panic("NACC Agent runtime retire response is invalid");
	return 0;
}

static void nacc_runtime_retire_exec_objects(
	struct nacc_runtime_object_ref agent,
	struct nacc_runtime_object_ref mm,
	struct nacc_runtime_object_ref thread, bool attached)
{
	struct nacc_runtime_lifecycle_request request = {
		.opcode = NACC_RUNTIME_TASK_RETIRE_OPCODE,
		.agent = agent,
		.mm = attached ? mm : (struct nacc_runtime_object_ref) { 0 },
		.thread = thread,
	};
	struct nacc_runtime_lifecycle_result result;
	int ret;

	ret = nacc_linux_runtime_lifecycle_call(&request, &result);
	if (ret || result.status != NACC_RUNTIME_LIFECYCLE_STATUS_OK)
		panic("NACC runtime TASK_RETIRE failed (%d)", ret);
	request = (struct nacc_runtime_lifecycle_request) {
		.opcode = NACC_RUNTIME_MM_RETIRE_OPCODE,
		.agent = agent,
		.mm = mm,
	};
	ret = nacc_linux_runtime_lifecycle_call(&request, &result);
	if (ret || result.status != NACC_RUNTIME_LIFECYCLE_STATUS_OK)
		panic("NACC runtime MM_RETIRE failed (%d)", ret);
}

static int nacc_runtime_create_exec_objects(
	struct nacc_runtime_object_ref agent,
	struct nacc_runtime_object_ref *mm,
	struct nacc_runtime_object_ref *thread)
{
	struct nacc_runtime_lifecycle_request request = {
		.opcode = NACC_RUNTIME_MM_CREATE_OPCODE,
		.agent = agent,
	};
	struct nacc_runtime_lifecycle_result result;
	int ret;

	if (!mm || !thread || !nacc_runtime_ref_is_zero(*mm) ||
	    !nacc_runtime_ref_is_zero(*thread))
		panic("NACC runtime exec create received dirty output");
	ret = nacc_linux_runtime_lifecycle_call(&request, &result);
	if (ret)
		return ret;
	if (result.status == NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY)
		return -ENOSPC;
	if (result.status != NACC_RUNTIME_LIFECYCLE_STATUS_OK ||
	    !nacc_runtime_ref_equal(result.agent, agent) ||
	    nacc_runtime_ref_is_zero(result.mm) ||
	    !nacc_runtime_ref_is_zero(result.thread))
		panic("NACC runtime MM_CREATE response is invalid");
	*mm = result.mm;

	request.opcode = NACC_RUNTIME_TASK_CREATE_OPCODE;
	ret = nacc_linux_runtime_lifecycle_call(&request, &result);
	if (!ret && result.status == NACC_RUNTIME_LIFECYCLE_STATUS_OK) {
		if (!nacc_runtime_ref_equal(result.agent, agent) ||
		    !nacc_runtime_ref_is_zero(result.mm) ||
		    nacc_runtime_ref_is_zero(result.thread))
			panic("NACC runtime TASK_CREATE response is invalid");
		*thread = result.thread;
		return 0;
	}
	if (!ret && result.status != NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY)
		panic("NACC runtime TASK_CREATE status is invalid");
	request = (struct nacc_runtime_lifecycle_request) {
		.opcode = NACC_RUNTIME_MM_RETIRE_OPCODE,
		.agent = agent,
		.mm = *mm,
	};
	if (nacc_linux_runtime_lifecycle_call(&request, &result) ||
	    result.status != NACC_RUNTIME_LIFECYCLE_STATUS_OK)
		panic("NACC runtime MM_CREATE rollback failed");
	*mm = (struct nacc_runtime_object_ref) { 0 };
	return ret ? ret : -ENOSPC;
}

static void nacc_agent_runtime_retire_worker(struct work_struct *work)
{
	struct nacc_agent_object *agent = container_of(
		work, struct nacc_agent_object, runtime_retire_work);
	int ret;

	ret = nacc_agent_runtime_retire(agent);
	if (ret)
		panic("NACC orphaned Agent runtime retire failed (%d)", ret);
	mutex_lock(&nacc_object_lock);
	if (!agent->orphaned || !agent->runtime_ready ||
	    !agent->runtime_retiring || agent->lifecycle.transaction_count ||
	    agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DESTROYING)
		panic("NACC orphaned Agent runtime retire lost ownership");
	agent->runtime_ref = (struct nacc_runtime_object_ref) { 0 };
	agent->runtime_ready = false;
	agent->runtime_retiring = false;
	ret = nacc_lifecycle_finish_destroy(&agent->lifecycle);
	if (ret)
		panic("NACC orphaned Agent cannot finish destroy (%d)", ret);
	mutex_unlock(&nacc_object_lock);
	kref_put(&agent->reference, nacc_agent_free);
}

static u64 nacc_target_identity(const struct task_struct *target)
{
	return (u64)(uintptr_t)target;
}

static void nacc_finish_destroy_if_drained(struct nacc_agent_object *agent)
{
	int ret;

	if (!agent->orphaned ||
	    agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DESTROYING ||
	    agent->lifecycle.transaction_count)
		return;
	if (agent->runtime_ready) {
		if (agent->runtime_retiring)
			panic("NACC drained Agent runtime retire is duplicated");
		agent->runtime_retiring = true;
		kref_get(&agent->reference);
		if (!schedule_work(&agent->runtime_retire_work))
			panic("NACC drained Agent runtime retire work was pending");
		return;
	}
	ret = nacc_lifecycle_finish_destroy(&agent->lifecycle);
	if (ret)
		panic("NACC drained Agent cannot finish destroy (%d)", ret);
}

static void nacc_agent_free(struct kref *reference)
{
	struct nacc_agent_object *agent =
		container_of(reference, struct nacc_agent_object, reference);

	if (agent->lifecycle.transaction_count ||
	    agent->lifecycle.prepared_count ||
	    agent->lifecycle.committed_count || agent->lifecycle.active_count)
		panic("NACC freeing Agent with live transactions");
	if (agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DEAD)
		panic("NACC freeing non-DEAD Agent");
	if (agent->runtime_ready || agent->runtime_retiring ||
	    !nacc_runtime_ref_is_zero(agent->runtime_ref))
		panic("NACC freeing Agent with a runtime identity");
	kfree(agent);
}

static void nacc_prepare_free(struct kref *reference)
{
	struct nacc_prepare_object *prepare =
		container_of(reference, struct nacc_prepare_object, reference);

	if (!list_empty(&prepare->list) ||
	    prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_EMPTY || prepare->mm ||
	    prepare->live_root ||
	    prepare->elf_preflight_claimed || prepare->elf_staging ||
	    prepare->exec_attempt_claimed ||
	    prepare->runtime_preparing || prepare->runtime_attaching ||
	    prepare->runtime_attached || prepare->runtime_retiring ||
	    !nacc_runtime_ref_is_zero(prepare->runtime_mm_ref) ||
	    !nacc_runtime_ref_is_zero(prepare->runtime_thread_ref) ||
	    prepare->elf_preflight_errno ||
	    prepare->elf_payload_valid != !!prepare->elf_code_prefix ||
	    (prepare->elf_payload_valid && !prepare->elf_code_prefix_length))
		panic("NACC freeing live prepare object");
	put_task_struct(prepare->target);
	kref_put(&prepare->agent->reference, nacc_agent_free);
	kfree(prepare->elf_code_prefix);
	kfree(prepare);
}

static int nacc_prepare_release(struct inode *inode, struct file *file)
{
	struct nacc_prepare_object *prepare = file->private_data;
	u64 target = nacc_target_identity(prepare->target);
	u64 generation = prepare->lifecycle.prepare_generation;
	int ret;

	(void)inode;
	mutex_lock(&nacc_object_lock);
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_PREPARED) {
		/* exec attempt begin 后 transaction 已由 target 接管，FD close 不能撤销。 */
		if (!prepare->exec_attempt_claimed) {
			ret = nacc_lifecycle_abort_prepare(
				&prepare->agent->lifecycle, &prepare->lifecycle,
				target, generation);
			if (ret)
				panic("NACC prepare close abort failed (%d)", ret);
			list_del_init(&prepare->list);
			if (prepare->live_root)
				panic("NACC PREPARED close found a live root");
			nacc_finish_destroy_if_drained(prepare->agent);
			kref_put(&prepare->reference, nacc_prepare_free);
		}
	} else if (prepare->lifecycle.state !=
			   NACC_LIFECYCLE_EXEC_COMMITTED &&
		   prepare->lifecycle.state !=
			   NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED &&
		   prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_ACTIVE &&
		   prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_EXITED &&
		   prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_FAILED &&
		   (prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_EMPTY ||
		    !list_empty(&prepare->list))) {
		panic("NACC prepare close found invalid state");
	}
	mutex_unlock(&nacc_object_lock);
	kref_put(&prepare->reference, nacc_prepare_free);
	return 0;
}

static const struct file_operations nacc_prepare_file_operations = {
	.owner = THIS_MODULE,
	.release = nacc_prepare_release,
	.llseek = no_llseek,
};

static int nacc_copy_request(void *request, size_t request_size,
			     void __user *argument, size_t user_size)
{
	struct nacc_uapi_header *header = request;
	int ret;

	if (user_size < request_size)
		return -EINVAL;
	ret = copy_struct_from_user(request, request_size, argument, user_size);
	if (ret)
		return ret;
	return nacc_validate_header(header, user_size);
}

static int nacc_match_control_agent(const struct nacc_control *control,
				    u64 cookie, u64 generation)
{
	if (!control->agent)
		return -ENOENT;
	if (!control->agent->runtime_ready ||
	    control->agent->runtime_retiring)
		return -EBUSY;
	if (control->agent->lifecycle.agent_cookie != cookie ||
	    control->agent->lifecycle.agent_generation != generation)
		return -ESTALE;
	return 0;
}

static struct nacc_prepare_object *nacc_find_prepare_locked(
	const struct task_struct *target)
{
	struct nacc_prepare_object *prepare;

	list_for_each_entry(prepare, &nacc_prepare_objects, list) {
		if (prepare->target == target)
			return prepare;
	}
	return NULL;
}

static struct nacc_prepare_object *nacc_attempt_prepare_locked(
	const struct nacc_exec_attempt *attempt)
{
	struct nacc_prepare_object *prepare;

	if (!attempt || !attempt->captured)
		panic("NACC exec hook received an uncaptured attempt");
	if (!attempt->prepare) {
		if (attempt->prepare_generation)
			panic("NACC negative exec snapshot has a generation");
		return NULL;
	}
	prepare = attempt->prepare;
	if (!attempt->prepare_generation || prepare->target != current)
		panic("NACC exec attempt identity is invalid");
	if (prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_EMPTY &&
	    (list_empty(&prepare->list) ||
	     prepare->lifecycle.prepare_generation !=
		     attempt->prepare_generation))
		panic("NACC exec attempt generation changed");
	return prepare;
}

void nacc_exec_attempt_begin(struct nacc_exec_attempt *attempt)
{
	struct nacc_prepare_object *prepare;

	if (!attempt || attempt->captured || attempt->prepare ||
	    attempt->prepare_generation)
		panic("NACC exec attempt begin received dirty storage");
	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
	if (prepare) {
		if (!prepare->lifecycle.prepare_generation ||
		    prepare->exec_attempt_claimed)
			panic("NACC exec attempt found an invalid transaction claim");
		kref_get(&prepare->reference);
		prepare->exec_attempt_claimed = true;
		attempt->prepare = prepare;
		attempt->prepare_generation =
			prepare->lifecycle.prepare_generation;
	}
	attempt->captured = true;
	mutex_unlock(&nacc_object_lock);
}

void nacc_exec_attempt_release(struct nacc_exec_attempt *attempt)
{
	struct nacc_prepare_object *prepare;

	if (!attempt || !attempt->captured)
		panic("NACC exec attempt release received invalid state");
	prepare = attempt->prepare;
	mutex_lock(&nacc_object_lock);
	if (prepare) {
		if (!prepare->exec_attempt_claimed)
			panic("NACC exec attempt lost its object claim");
		prepare->exec_attempt_claimed = false;
	}
	memset(attempt, 0, sizeof(*attempt));
	mutex_unlock(&nacc_object_lock);
	if (prepare)
		kref_put(&prepare->reference, nacc_prepare_free);
}

static int nacc_prepare_build_minimal_live_root(
	struct nacc_prepare_object *prepare)
{
	const nacc_bootstrap_u64 payload_page_counts[] = { 1, 1 };
	const struct nacc_live_root_layout_request request = {
		.ptp_page_count = NACC_LIVE_ROOT_FIRST_AU_PTP_PAGES,
		.payload_page_counts = payload_page_counts,
		.payload_mapping_count = NACC_MINIMAL_PAYLOAD_MAPPINGS,
	};
	const struct nacc_live_root_mapping_request mappings[] = {
		{
			.virtual_base = NACC_ENTER_CODE_VIRTUAL_ADDRESS,
			.page_count = 1,
			.permissions = NACC_ROOT_PTE_READ |
				       NACC_ROOT_PTE_EXECUTE |
				       NACC_ROOT_PTE_USER,
		},
		{
			.virtual_base = NACC_ENTER_STACK_VIRTUAL_ADDRESS,
			.page_count = 1,
			.permissions = NACC_ROOT_PTE_READ |
				       NACC_ROOT_PTE_WRITE |
				       NACC_ROOT_PTE_USER,
		},
	};
	int ret;

	if (prepare->live_root)
		panic("NACC minimal live root was already built");
	if (!nacc_bootstrap_physical_layout_available() || !nacc_root_is_ready())
		return -ENODEV;
	ret = nacc_live_root_reserve(
		&prepare->live_root, nacc_bootstrap_physical_layout_snapshot(),
		nacc_root_result_snapshot(), &request);
	if (ret)
		return ret;
	ret = nacc_live_root_build(prepare->live_root,
				   nacc_root_descriptor_snapshot(),
				   nacc_agent_image_metadata_snapshot(), mappings,
				   ARRAY_SIZE(mappings));
	if (ret) {
		nacc_live_root_release_unpublished(prepare->live_root);
		prepare->live_root = NULL;
	}
	return ret;
}

int nacc_exec_prepare_elf(const struct nacc_exec_attempt *attempt,
			  struct file *executable,
				  bool fixed_executable,
				  bool direct_executable,
				  bool has_interpreter, u32 load_segment_count,
				  u32 executable_load_segment_count,
				  u32 executable_flags,
				  u64 executable_file_offset,
				  u64 executable_virtual_address,
				  u64 executable_file_size,
				  u64 executable_memory_size, u64 entry)
{
	const struct nacc_enter_elf_metadata metadata = {
		.fixed_executable = fixed_executable,
		.direct_executable = direct_executable,
		.has_interpreter = has_interpreter,
		.load_segment_count = load_segment_count,
		.executable_load_segment_count = executable_load_segment_count,
		.executable_flags = executable_flags,
		.executable_file_offset = executable_file_offset,
		.executable_virtual_address = executable_virtual_address,
		.executable_file_size = executable_file_size,
		.executable_memory_size = executable_memory_size,
		.entry = entry,
	};
	struct nacc_prepare_object *prepare;
	u8 *code_prefix;
	loff_t read_position;
	ssize_t bytes_read;
	u64 entry_offset;
	size_t code_prefix_length;
	int ret = 0;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_attempt_prepare_locked(attempt);
	if (!prepare)
		goto out_unlock;
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_EMPTY) {
		ret = -ESTALE;
		goto out_unlock;
	}
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	if (prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_PREPARED)
		panic("NACC ELF preflight found invalid transaction state");
	if (prepare->elf_preflight_claimed) {
		if (prepare->elf_preflight_errno) {
			ret = prepare->elf_preflight_errno;
			goto out_unlock;
		}
		if (prepare->elf_staging)
			panic("NACC ELF preflight reentered file staging");
		if (!prepare->elf_payload_valid)
			panic("NACC ELF preflight claim has no result");
	} else {
		/* 任意 preflight error 返回到 generation cleanup 前都禁止 replacement。 */
		prepare->elf_preflight_claimed = true;
	}
	ret = nacc_enter_elf_metadata_validate(
		&metadata, &entry_offset, &code_prefix_length);
	if (ret)
		goto out_claim_error;
	if (!executable) {
		ret = -EINVAL;
		goto out_claim_error;
	}
	if (prepare->elf_payload_valid) {
		/* 新 exec attempt 不得按相同 metadata 复用旧 executable bytes。 */
		ret = -ESTALE;
		goto out_unlock;
	}
	code_prefix = kmalloc(code_prefix_length, GFP_KERNEL);
	if (!code_prefix) {
		ret = -ENOMEM;
		goto out_claim_error;
	}
	/*
	 * validator 将读取限制在单页内。占位禁止 FD close 后为同一 target
	 * 安装 replacement prepare；kref 保护解锁后的 transaction storage。
	 */
	prepare->elf_staging = true;
	kref_get(&prepare->reference);
	mutex_unlock(&nacc_object_lock);
	read_position = executable_file_offset;
	bytes_read = kernel_read(executable, code_prefix, code_prefix_length,
				 &read_position);
	mutex_lock(&nacc_object_lock);
	if (nacc_find_prepare_locked(current) != prepare ||
	    prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_PREPARED ||
	    !prepare->elf_preflight_claimed || !prepare->elf_staging ||
	    prepare->elf_payload_valid || prepare->elf_preflight_errno)
		panic("NACC ELF staging lost transaction ownership");
	if (bytes_read < 0 || (size_t)bytes_read != code_prefix_length) {
		/* -ERESTARTNOINTR 会跳过 exec abort；改为可清理 transaction 的错误。 */
		if (bytes_read < 0)
			ret = bytes_read == -ERESTARTNOINTR ? -EINTR :
				(int)bytes_read;
		else
			ret = -EIO;
		prepare->elf_preflight_errno = ret;
		prepare->elf_staging = false;
		kfree(code_prefix);
		goto out_put;
	}
	prepare->elf_staging = false;
	prepare->elf_entry_offset = entry_offset;
	prepare->elf_code_prefix = code_prefix;
	prepare->elf_code_prefix_length = code_prefix_length;
	prepare->elf_payload_valid = true;

out_put:
	mutex_unlock(&nacc_object_lock);
	kref_put(&prepare->reference, nacc_prepare_free);
	return ret;

out_claim_error:
	if (!ret || !prepare->elf_preflight_claimed ||
	    prepare->elf_preflight_errno)
		panic("NACC ELF preflight error state is invalid");
	prepare->elf_preflight_errno = ret;
out_unlock:
	mutex_unlock(&nacc_object_lock);
	return ret;
}

int nacc_exec_commit(const struct nacc_exec_attempt *attempt)
{
	struct nacc_prepare_object *prepare;
	struct nacc_runtime_object_ref agent_ref;
	struct nacc_runtime_object_ref mm_ref = { 0 };
	struct nacc_runtime_object_ref thread_ref = { 0 };
	int ret = 0;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_attempt_prepare_locked(attempt);
	if (prepare && prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_PREPARED) {
		if (!prepare->elf_payload_valid) {
			ret = -ENOEXEC;
			goto out_unlock;
		}
		if (prepare->mm || prepare->live_root)
			panic("NACC first exec commit found existing runtime state");
		ret = nacc_prepare_build_minimal_live_root(prepare);
		if (ret)
			goto out_unlock;
		if (prepare->runtime_preparing || prepare->runtime_attaching ||
		    prepare->runtime_attached || prepare->runtime_retiring ||
		    !nacc_runtime_ref_is_zero(prepare->runtime_mm_ref) ||
		    !nacc_runtime_ref_is_zero(prepare->runtime_thread_ref))
			panic("NACC first exec commit found runtime state");
		prepare->runtime_preparing = true;
		agent_ref = prepare->agent->runtime_ref;
		mutex_unlock(&nacc_object_lock);
		ret = nacc_runtime_create_exec_objects(
			agent_ref, &mm_ref, &thread_ref);
		mutex_lock(&nacc_object_lock);
		if (nacc_attempt_prepare_locked(attempt) != prepare ||
		    prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_PREPARED ||
		    !prepare->runtime_preparing || prepare->runtime_attaching ||
		    prepare->runtime_attached || prepare->runtime_retiring ||
		    !nacc_runtime_ref_is_zero(prepare->runtime_mm_ref) ||
		    !nacc_runtime_ref_is_zero(prepare->runtime_thread_ref) ||
		    !nacc_runtime_ref_equal(prepare->agent->runtime_ref,
					    agent_ref))
			panic("NACC runtime exec create lost ownership");
		prepare->runtime_preparing = false;
		if (ret) {
			if (!nacc_runtime_ref_is_zero(mm_ref) ||
			    !nacc_runtime_ref_is_zero(thread_ref))
				panic("NACC failed runtime exec create retained identity");
			nacc_live_root_release_unpublished(prepare->live_root);
			prepare->live_root = NULL;
			goto out_unlock;
		}
		prepare->runtime_mm_ref = mm_ref;
		prepare->runtime_thread_ref = thread_ref;
		ret = nacc_lifecycle_commit_exec(
			&prepare->agent->lifecycle, &prepare->lifecycle,
			nacc_target_identity(current),
			prepare->lifecycle.prepare_generation);
		if (ret) {
			if (ret != -ESHUTDOWN)
				panic("NACC runtime-backed exec commit failed (%d)",
				      ret);
			/* Agent destroy 可与锁外 AS create 合法竞态。 */
			prepare->runtime_retiring = true;
			mutex_unlock(&nacc_object_lock);
			nacc_runtime_retire_exec_objects(
				agent_ref, mm_ref, thread_ref, false);
			mutex_lock(&nacc_object_lock);
			if (nacc_attempt_prepare_locked(attempt) != prepare ||
			    !prepare->runtime_retiring ||
			    !nacc_runtime_ref_equal(prepare->runtime_mm_ref,
						    mm_ref) ||
			    !nacc_runtime_ref_equal(prepare->runtime_thread_ref,
						    thread_ref))
				panic("NACC failed exec commit rollback lost ownership");
			prepare->runtime_mm_ref =
				(struct nacc_runtime_object_ref) { 0 };
			prepare->runtime_thread_ref =
				(struct nacc_runtime_object_ref) { 0 };
			prepare->runtime_retiring = false;
			nacc_live_root_release_unpublished(prepare->live_root);
			prepare->live_root = NULL;
		}
	} else if (prepare &&
		 prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		if (prepare->mm != current->mm)
			panic("NACC re-exec commit found an invalid mm binding");
		if (!prepare->live_root)
			panic("NACC re-exec commit found no live root");
		/* 最小 single-mm 路径不允许把旧 live root 静默绑定到新 mm。 */
		ret = -EOPNOTSUPP;
	} else if (prepare) {
		panic("NACC exec commit found invalid transaction state");
	}

out_unlock:
	mutex_unlock(&nacc_object_lock);
	return ret;
}

bool nacc_exec_abort(const struct nacc_exec_attempt *attempt)
{
	struct nacc_prepare_object *prepare;
	int ret;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_attempt_prepare_locked(attempt);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return false;
	}
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_EMPTY) {
		mutex_unlock(&nacc_object_lock);
		return false;
	}
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		mutex_unlock(&nacc_object_lock);
		return false;
	}
	prepare->elf_preflight_claimed = false;
	prepare->elf_staging = false;
	prepare->elf_preflight_errno = 0;
	ret = nacc_lifecycle_abort_prepare(
		&prepare->agent->lifecycle, &prepare->lifecycle,
		nacc_target_identity(current),
		prepare->lifecycle.prepare_generation);
	if (ret)
		panic("NACC exec pre-PONR abort failed (%d)", ret);
	list_del_init(&prepare->list);
	if (prepare->live_root)
		panic("NACC pre-PONR abort found a live root");
	nacc_finish_destroy_if_drained(prepare->agent);
	mutex_unlock(&nacc_object_lock);
	kref_put(&prepare->reference, nacc_prepare_free);
	return true;
}

int nacc_exec_bind_mm(const struct nacc_exec_attempt *attempt)
{
	struct nacc_prepare_object *prepare;
	struct mm_struct *old_mm = NULL;
	struct nacc_runtime_lifecycle_request request;
	struct nacc_runtime_lifecycle_result result;
	int ret;

	if (!current->mm)
		panic("NACC exec installed a missing mm");
	mutex_lock(&nacc_object_lock);
	prepare = nacc_attempt_prepare_locked(attempt);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return 0;
	}
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_COMMITTED) {
		if (prepare->mm)
			panic("NACC first exec already has an mm binding");
	} else if (prepare->lifecycle.state ==
		   NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED) {
		if (!prepare->mm || prepare->mm == current->mm)
			panic("NACC re-exec found an invalid mm replacement");
		old_mm = prepare->mm;
	} else {
		panic("NACC exec mm bind found invalid transaction state");
	}
	mmget(current->mm);
	prepare->mm = current->mm;
	if (prepare->runtime_preparing || prepare->runtime_attaching ||
	    prepare->runtime_attached || prepare->runtime_retiring ||
	    nacc_runtime_ref_is_zero(prepare->runtime_mm_ref) ||
	    nacc_runtime_ref_is_zero(prepare->runtime_thread_ref))
		panic("NACC exec mm bind found invalid runtime state");
	prepare->runtime_attaching = true;
	request = (struct nacc_runtime_lifecycle_request) {
		.opcode = NACC_RUNTIME_TASK_ATTACH_OPCODE,
		.agent = prepare->agent->runtime_ref,
		.mm = prepare->runtime_mm_ref,
		.thread = prepare->runtime_thread_ref,
	};
	mutex_unlock(&nacc_object_lock);
	ret = nacc_linux_runtime_lifecycle_call(&request, &result);
	mutex_lock(&nacc_object_lock);
	if (nacc_attempt_prepare_locked(attempt) != prepare ||
	    prepare->mm != current->mm || !prepare->runtime_attaching ||
	    prepare->runtime_attached || prepare->runtime_retiring ||
	    !nacc_runtime_ref_equal(prepare->agent->runtime_ref, request.agent) ||
	    !nacc_runtime_ref_equal(prepare->runtime_mm_ref, request.mm) ||
	    !nacc_runtime_ref_equal(prepare->runtime_thread_ref, request.thread))
		panic("NACC runtime TASK_ATTACH lost ownership");
	prepare->runtime_attaching = false;
	if (!ret) {
		if (result.status != NACC_RUNTIME_LIFECYCLE_STATUS_OK)
			panic("NACC runtime TASK_ATTACH status is invalid");
		prepare->runtime_attached = true;
	}
	mutex_unlock(&nacc_object_lock);
	if (old_mm)
		mmput(old_mm);
	return ret;
}

void nacc_exec_activate(const struct nacc_exec_attempt *attempt)
{
	struct nacc_prepare_object *prepare;
	int ret;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_attempt_prepare_locked(attempt);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return;
	}
	pr_info("NACC Linux exec activation begin\n");
	if (prepare->mm != current->mm)
		panic("NACC exec activation found an invalid mm binding");
	if (!prepare->runtime_attached || prepare->runtime_preparing ||
	    prepare->runtime_attaching || prepare->runtime_retiring)
		panic("NACC exec activation found invalid runtime state");
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_COMMITTED)
		ret = nacc_lifecycle_activate(
			&prepare->agent->lifecycle, &prepare->lifecycle,
			nacc_target_identity(current),
			prepare->lifecycle.prepare_generation);
	else if (prepare->lifecycle.state ==
		 NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED)
		ret = nacc_lifecycle_activate_reexec(
			&prepare->agent->lifecycle, &prepare->lifecycle,
			nacc_target_identity(current),
			prepare->lifecycle.prepare_generation);
	else
		panic("NACC exec activation found invalid transaction state");
	if (ret)
		panic("NACC exec activation failed (%d)", ret);
	mutex_unlock(&nacc_object_lock);
	pr_info("NACC Linux exec activation complete\n");
}

void nacc_exec_enter(const struct nacc_exec_attempt *attempt,
		     unsigned long entry, unsigned long stack_pointer)
{
	const struct nacc_bootstrap_physical_layout *physical_layout;
	const struct nacc_live_root_layout_result *layout;
	const struct nacc_root_build_result *root;
	struct nacc_prepare_object *prepare;
	struct nacc_enter_message_request request;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_attempt_prepare_locked(attempt);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return;
	}
	pr_info("NACC Linux exec ENTER begin\n");
	if (prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_ACTIVE ||
	    prepare->mm != current->mm || !prepare->runtime_attached ||
	    prepare->runtime_preparing || prepare->runtime_attaching ||
	    prepare->runtime_retiring || !prepare->live_root ||
	    !prepare->elf_payload_valid || !prepare->elf_code_prefix ||
	    !prepare->elf_code_prefix_length || !entry || !stack_pointer ||
	    entry != NACC_ENTER_CODE_VIRTUAL_ADDRESS +
			 prepare->elf_entry_offset)
		panic("NACC exec ENTER object invariant failed");
	physical_layout = nacc_bootstrap_physical_layout_snapshot();
	layout = nacc_live_root_layout_snapshot(prepare->live_root);
	root = nacc_live_root_result_snapshot(prepare->live_root);
	if (root->root_physical_address != layout->ptp_base ||
	    root->lower_ptp_count == U64_MAX ||
	    root->lower_ptp_count + 1 > layout->ptp_size / PAGE_SIZE)
		panic("NACC exec ENTER live root invariant failed");
	request = (struct nacc_enter_message_request) {
		.pool_base = physical_layout->nacc_pool.base,
		.pool_size = physical_layout->nacc_pool.size,
		.live_root_physical_address = root->root_physical_address,
		.ptp_page_count = root->lower_ptp_count + 1,
		.code_physical_address = layout->payload_bases[0],
		.stack_physical_address = layout->payload_bases[1],
		.entry_offset = prepare->elf_entry_offset,
		.agent_handle = prepare->agent->runtime_ref.handle,
		.mm_handle = prepare->runtime_mm_ref.handle,
		.thread_handle = prepare->runtime_thread_ref.handle,
		.code_prefix = prepare->elf_code_prefix,
		.code_prefix_length = prepare->elf_code_prefix_length,
	};
	mutex_unlock(&nacc_object_lock);
	pr_info("NACC Linux exec ENTER request ready\n");
	nacc_linux_runtime_exec_enter(&request);
}

bool nacc_exec_is_active_current(void)
{
	struct nacc_prepare_object *prepare;
	bool active = false;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
	if (prepare &&
	    prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		if (prepare->mm != current->mm)
			panic("NACC active query found an invalid mm binding");
		active = true;
	}
	mutex_unlock(&nacc_object_lock);
	return active;
}

void nacc_exec_record_failure(const struct nacc_exec_attempt *attempt,
			      int failure_errno)
{
	struct nacc_prepare_object *prepare;

	if (failure_errno <= 0)
		panic("NACC exec recorded invalid failure errno");
	mutex_lock(&nacc_object_lock);
	prepare = nacc_attempt_prepare_locked(attempt);
	if (prepare) {
		if ((prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_COMMITTED &&
		     prepare->lifecycle.state !=
			     NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED) ||
		    prepare->post_ponr_errno)
			panic("NACC exec failure found invalid transaction state");
		prepare->post_ponr_errno = failure_errno;
	}
	mutex_unlock(&nacc_object_lock);
}

void nacc_exec_exit_current(void)
{
	struct nacc_prepare_object *prepare;
	struct nacc_runtime_object_ref agent_ref;
	struct nacc_runtime_object_ref mm_ref;
	struct nacc_runtime_object_ref thread_ref;
	struct mm_struct *mm;
	bool runtime_attached;
	u64 generation;
	u64 target;
	int ret;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return;
	}
	target = nacc_target_identity(current);
	generation = prepare->lifecycle.prepare_generation;
	prepare->elf_preflight_claimed = false;
	prepare->elf_staging = false;
	prepare->elf_preflight_errno = 0;
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_PREPARED) {
		if (prepare->runtime_preparing || prepare->runtime_attaching ||
		    prepare->runtime_attached || prepare->runtime_retiring ||
		    !nacc_runtime_ref_is_zero(prepare->runtime_mm_ref) ||
		    !nacc_runtime_ref_is_zero(prepare->runtime_thread_ref))
			panic("NACC PREPARED exit retained runtime state");
		ret = nacc_lifecycle_abort_prepare(&prepare->agent->lifecycle,
						   &prepare->lifecycle,
						   target, generation);
	} else if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_COMMITTED ||
		   prepare->lifecycle.state ==
			   NACC_LIFECYCLE_EXEC_REEXEC_COMMITTED) {
		if (!prepare->post_ponr_errno)
			panic("NACC committed exec exited without failure record");
		ret = nacc_lifecycle_target_failed_and_exited(
			&prepare->agent->lifecycle, &prepare->lifecycle, target,
			generation, prepare->post_ponr_errno);
	} else if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		ret = nacc_lifecycle_target_exited(
			&prepare->agent->lifecycle, &prepare->lifecycle, target,
			generation);
	} else {
		panic("NACC task exit found invalid transaction state");
	}
	if (ret)
		panic("NACC task exit transition failed (%d)", ret);
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_FAILED ||
	    prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_EXITED) {
		if (prepare->runtime_preparing || prepare->runtime_attaching ||
		    prepare->runtime_retiring ||
		    nacc_runtime_ref_is_zero(prepare->runtime_mm_ref) ||
		    nacc_runtime_ref_is_zero(prepare->runtime_thread_ref))
			panic("NACC task exit found invalid runtime identity");
		prepare->runtime_retiring = true;
		agent_ref = prepare->agent->runtime_ref;
		mm_ref = prepare->runtime_mm_ref;
		thread_ref = prepare->runtime_thread_ref;
		runtime_attached = prepare->runtime_attached;
		mutex_unlock(&nacc_object_lock);
		nacc_runtime_retire_exec_objects(
			agent_ref, mm_ref, thread_ref, runtime_attached);
		mutex_lock(&nacc_object_lock);
		if (nacc_find_prepare_locked(current) != prepare ||
		    !prepare->runtime_retiring || prepare->runtime_preparing ||
		    prepare->runtime_attaching ||
		    !nacc_runtime_ref_equal(prepare->agent->runtime_ref,
					    agent_ref) ||
		    !nacc_runtime_ref_equal(prepare->runtime_mm_ref, mm_ref) ||
		    !nacc_runtime_ref_equal(prepare->runtime_thread_ref,
					    thread_ref))
			panic("NACC task runtime retire lost ownership");
		prepare->runtime_mm_ref =
			(struct nacc_runtime_object_ref) { 0 };
		prepare->runtime_thread_ref =
			(struct nacc_runtime_object_ref) { 0 };
		prepare->runtime_attached = false;
		prepare->runtime_retiring = false;
		ret = nacc_lifecycle_retire_exec(
			&prepare->agent->lifecycle, &prepare->lifecycle,
			target, generation);
		if (ret)
			panic("NACC task local retire failed (%d)", ret);
	}
	mm = prepare->mm;
	prepare->mm = NULL;
	list_del_init(&prepare->list);
	if (prepare->live_root) {
		nacc_live_root_release_unpublished(prepare->live_root);
		prepare->live_root = NULL;
	}
	nacc_finish_destroy_if_drained(prepare->agent);
	mutex_unlock(&nacc_object_lock);
	if (mm)
		mmput(mm);
	kref_put(&prepare->reference, nacc_prepare_free);
}

int nacc_control_open(struct file *file)
{
	struct nacc_control *control;

	control = kzalloc(sizeof(*control), GFP_KERNEL);
	if (!control)
		return -ENOMEM;
	file->private_data = control;
	return 0;
}

int nacc_control_release(struct file *file)
{
	struct nacc_control *control = file->private_data;
	struct nacc_agent_object *agent;
	int ret;

	mutex_lock(&nacc_object_lock);
	agent = control->agent;
	control->agent = NULL;
	if (agent) {
		if (!agent->runtime_ready || agent->runtime_retiring)
			panic("NACC control close found unpublished runtime state");
		agent->orphaned = true;
	}
	if (agent && agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DEAD &&
	    agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DESTROYING) {
		ret = nacc_lifecycle_begin_destroy(
			&agent->lifecycle, agent->lifecycle.agent_cookie,
			agent->lifecycle.agent_generation);
		if (ret)
			panic("NACC control close cannot begin destroy (%d)", ret);
	}
	if (agent)
		nacc_finish_destroy_if_drained(agent);
	mutex_unlock(&nacc_object_lock);
	if (agent)
		kref_put(&agent->reference, nacc_agent_free);
	kfree(control);
	return 0;
}

long nacc_create_agent(struct file *file, void __user *argument,
		       size_t user_size)
{
	struct nacc_ioc_create_agent request;
	struct nacc_control *control = file->private_data;
	struct nacc_agent_object *agent;
	const struct nacc_runtime_lifecycle_request runtime_request = {
		.opcode = NACC_RUNTIME_AGENT_CREATE_OPCODE,
	};
	struct nacc_runtime_lifecycle_result runtime_result;
	u64 cookie;
	u64 generation;
	int ret;

	ret = nacc_copy_request(&request, sizeof(request), argument, user_size);
	if (ret)
		return ret;
	if (request.flags || request.requested_pool_pages || request.agent_cookie ||
	    request.agent_generation ||
	    memchr_inv(request.reserved, 0, sizeof(request.reserved)))
		return -EINVAL;
	agent = kzalloc(sizeof(*agent), GFP_KERNEL);
	if (!agent)
		return -ENOMEM;
	kref_init(&agent->reference);
	INIT_WORK(&agent->runtime_retire_work, nacc_agent_runtime_retire_worker);
	do {
		cookie = get_random_u64();
	} while (!cookie);
	generation = atomic64_inc_return(&nacc_agent_generation);
	if (!generation)
		panic("NACC Agent generation wrapped");
	ret = nacc_lifecycle_create(&agent->lifecycle, cookie, generation);
	if (ret)
		panic("NACC Agent core create failed (%d)", ret);

	mutex_lock(&nacc_object_lock);
	if (control->agent) {
		mutex_unlock(&nacc_object_lock);
		ret = nacc_lifecycle_begin_destroy(&agent->lifecycle, cookie,
						   generation);
		if (ret || nacc_lifecycle_finish_destroy(&agent->lifecycle))
			panic("NACC unused Agent cleanup failed");
		kref_put(&agent->reference, nacc_agent_free);
		return -EALREADY;
	}
	control->agent = agent;
	mutex_unlock(&nacc_object_lock);

	ret = nacc_linux_runtime_lifecycle_call(&runtime_request,
						&runtime_result);
	if (ret)
		goto out_discard_local;
	if (runtime_result.status == NACC_RUNTIME_LIFECYCLE_STATUS_CAPACITY) {
		ret = -ENOSPC;
		goto out_discard_local;
	}
	if (runtime_result.status != NACC_RUNTIME_LIFECYCLE_STATUS_OK ||
	    nacc_runtime_ref_is_zero(runtime_result.agent) ||
	    !nacc_runtime_ref_is_zero(runtime_result.mm) ||
	    !nacc_runtime_ref_is_zero(runtime_result.thread))
		panic("NACC Agent runtime create response is invalid");
	mutex_lock(&nacc_object_lock);
	if (control->agent != agent || agent->runtime_ready ||
	    agent->runtime_retiring ||
	    !nacc_runtime_ref_is_zero(agent->runtime_ref))
		panic("NACC Agent runtime create lost control ownership");
	agent->runtime_ref = runtime_result.agent;
	agent->runtime_ready = true;
	/* user copy 完成前阻止同一 control FD 观察未发布的 Agent。 */
	agent->runtime_retiring = true;
	mutex_unlock(&nacc_object_lock);

	request.agent_cookie = cookie;
	request.agent_generation = generation;
	request.header.features = nacc_supported_features();
	if (copy_to_user(argument, &request, sizeof(request))) {
		ret = nacc_agent_runtime_retire(agent);
		if (ret)
			panic("NACC Agent create runtime rollback failed (%d)", ret);
		mutex_lock(&nacc_object_lock);
		if (control->agent != agent || !agent->runtime_ready ||
		    !agent->runtime_retiring)
			panic("NACC Agent create rollback lost ownership");
		agent->runtime_ref = (struct nacc_runtime_object_ref) { 0 };
		agent->runtime_ready = false;
		agent->runtime_retiring = false;
		control->agent = NULL;
		ret = nacc_lifecycle_begin_destroy(&agent->lifecycle, cookie,
						   generation);
		if (ret || nacc_lifecycle_finish_destroy(&agent->lifecycle))
			panic("NACC Agent create local rollback failed");
		mutex_unlock(&nacc_object_lock);
		kref_put(&agent->reference, nacc_agent_free);
		return -EFAULT;
	}
	mutex_lock(&nacc_object_lock);
	if (control->agent != agent || !agent->runtime_ready ||
	    !agent->runtime_retiring)
		panic("NACC Agent create publication lost ownership");
	agent->runtime_retiring = false;
	mutex_unlock(&nacc_object_lock);
	return 0;

out_discard_local:
	mutex_lock(&nacc_object_lock);
	if (control->agent != agent || agent->runtime_ready ||
	    agent->runtime_retiring ||
	    !nacc_runtime_ref_is_zero(agent->runtime_ref))
		panic("NACC failed Agent create retained runtime state");
	control->agent = NULL;
	if (nacc_lifecycle_begin_destroy(&agent->lifecycle, cookie, generation) ||
	    nacc_lifecycle_finish_destroy(&agent->lifecycle))
		panic("NACC failed Agent create local cleanup failed");
	mutex_unlock(&nacc_object_lock);
	kref_put(&agent->reference, nacc_agent_free);
	return ret;
}

long nacc_prepare_exec(struct file *file, void __user *argument,
		       size_t user_size)
{
	struct nacc_ioc_prepare_exec request;
	struct nacc_control *control = file->private_data;
	struct nacc_prepare_object *prepare;
	struct task_struct *target;
	struct file *prepare_file;
	unsigned int pidfd_flags;
	u64 prepare_generation;
	int fd;
	int ret;

	ret = nacc_copy_request(&request, sizeof(request), argument, user_size);
	if (ret)
		return ret;
	if (request.flags || request.prepare_fd || request.reserved0 ||
	    memchr_inv(request.reserved, 0, sizeof(request.reserved)))
		return -EINVAL;
	target = pidfd_get_task(request.pidfd, &pidfd_flags);
	if (IS_ERR(target))
		return PTR_ERR(target);
	(void)pidfd_flags;
	if (target->flags & PF_KTHREAD) {
		put_task_struct(target);
		return -EINVAL;
	}
	prepare = kzalloc(sizeof(*prepare), GFP_KERNEL);
	if (!prepare) {
		put_task_struct(target);
		return -ENOMEM;
	}
	kref_init(&prepare->reference);
	INIT_LIST_HEAD(&prepare->list);
	prepare->target = target;

	mutex_lock(&nacc_object_lock);
	/* PF_EXITING 先于 task 的唯一 NACC exit sweep 发布，之后不得新增对象。 */
	if (READ_ONCE(target->flags) & PF_EXITING) {
		ret = -ESRCH;
		goto out_unlock_free;
	}
	ret = nacc_match_control_agent(control, request.agent_cookie,
				       request.agent_generation);
	if (ret)
		goto out_unlock_free;
	{
		struct nacc_prepare_object *existing;

		list_for_each_entry(existing, &nacc_prepare_objects, list) {
			if (existing->target == target) {
				ret = -EBUSY;
				goto out_unlock_free;
			}
		}
	}
	prepare->agent = control->agent;
	kref_get(&prepare->agent->reference);
	ret = nacc_lifecycle_prepare(
		&prepare->agent->lifecycle, &prepare->lifecycle,
		request.agent_cookie, request.agent_generation,
		nacc_target_identity(target), &prepare_generation);
	if (ret) {
		kref_put(&prepare->agent->reference, nacc_agent_free);
		prepare->agent = NULL;
		goto out_unlock_free;
	}
	list_add_tail(&prepare->list, &nacc_prepare_objects);
	mutex_unlock(&nacc_object_lock);

	prepare_file = anon_inode_getfile("nacc-prepare",
					  &nacc_prepare_file_operations, prepare,
					  O_RDONLY | O_CLOEXEC);
	if (IS_ERR(prepare_file)) {
		ret = PTR_ERR(prepare_file);
		goto out_abort_without_file;
	}
	kref_get(&prepare->reference);
	fd = get_unused_fd_flags(O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fput(prepare_file);
		return fd;
	}
	request.prepare_fd = fd;
	request.header.features = nacc_supported_features();
	if (copy_to_user(argument, &request, sizeof(request))) {
		put_unused_fd(fd);
		fput(prepare_file);
		return -EFAULT;
	}
	fd_install(fd, prepare_file);
	return 0;

out_abort_without_file:
	mutex_lock(&nacc_object_lock);
	if (nacc_lifecycle_abort_prepare(
		&prepare->agent->lifecycle, &prepare->lifecycle,
		nacc_target_identity(target), prepare_generation))
		panic("NACC prepare construction rollback failed");
	list_del_init(&prepare->list);
	nacc_finish_destroy_if_drained(prepare->agent);
	mutex_unlock(&nacc_object_lock);
	kref_put(&prepare->reference, nacc_prepare_free);
	return ret;

out_unlock_free:
	mutex_unlock(&nacc_object_lock);
	put_task_struct(target);
	kfree(prepare);
	return ret;
}

long nacc_query_status(struct file *file, void __user *argument,
		       size_t user_size)
{
	struct nacc_ioc_query_status request;
	struct nacc_control *control = file->private_data;
	int ret;

	ret = nacc_copy_request(&request, sizeof(request), argument, user_size);
	if (ret)
		return ret;
	if (request.status || request.failure_errno ||
	    memchr_inv(request.reserved, 0, sizeof(request.reserved)))
		return -EINVAL;
	mutex_lock(&nacc_object_lock);
	ret = nacc_match_control_agent(control, request.agent_cookie,
				       request.agent_generation);
	if (!ret) {
		request.status = nacc_lifecycle_query_status(
			&control->agent->lifecycle);
		request.failure_errno = control->agent->lifecycle.failure_errno;
	}
	mutex_unlock(&nacc_object_lock);
	if (ret)
		return ret;
	request.header.features = nacc_supported_features();
	return copy_to_user(argument, &request, sizeof(request)) ? -EFAULT : 0;
}

long nacc_destroy_agent(struct file *file, void __user *argument,
			 size_t user_size)
{
	struct nacc_ioc_destroy_agent request;
	struct nacc_control *control = file->private_data;
	struct nacc_agent_object *agent;
	int ret;

	ret = nacc_copy_request(&request, sizeof(request), argument, user_size);
	if (ret)
		return ret;
	if (request.flags ||
	    memchr_inv(request.reserved, 0, sizeof(request.reserved)))
		return -EINVAL;
	mutex_lock(&nacc_object_lock);
	ret = nacc_match_control_agent(control, request.agent_cookie,
				       request.agent_generation);
	if (ret)
		goto out_unlock;
	agent = control->agent;
	if (agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DESTROYING) {
		ret = nacc_lifecycle_begin_destroy(&agent->lifecycle,
			request.agent_cookie, request.agent_generation);
		if (ret)
			goto out_unlock;
	}
	if (agent->lifecycle.transaction_count) {
		ret = -EBUSY;
		goto out_unlock;
	}
	if (!agent->runtime_ready || agent->runtime_retiring)
		panic("NACC explicit destroy found invalid runtime state");
	agent->runtime_retiring = true;
	mutex_unlock(&nacc_object_lock);

	ret = nacc_agent_runtime_retire(agent);
	mutex_lock(&nacc_object_lock);
	if (control->agent != agent || !agent->runtime_ready ||
	    !agent->runtime_retiring || agent->lifecycle.transaction_count ||
	    agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DESTROYING)
		panic("NACC explicit destroy lost runtime ownership");
	if (ret) {
		agent->runtime_retiring = false;
		goto out_unlock;
	}
	agent->runtime_ref = (struct nacc_runtime_object_ref) { 0 };
	agent->runtime_ready = false;
	agent->runtime_retiring = false;
	ret = nacc_lifecycle_finish_destroy(&agent->lifecycle);
	if (ret)
		panic("NACC explicit destroy cannot finish local state (%d)", ret);
	control->agent = NULL;
out_unlock:
	mutex_unlock(&nacc_object_lock);
	if (!ret)
		kref_put(&agent->reference, nacc_agent_free);
	return ret;
}
