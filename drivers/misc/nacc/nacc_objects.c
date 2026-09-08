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

#include "nacc_internal.h"

struct nacc_agent_object {
	struct kref reference;
	struct nacc_lifecycle_agent lifecycle;
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
	struct nacc_lifecycle_exec lifecycle;
	int post_ponr_errno;
};

static DEFINE_MUTEX(nacc_object_lock);
static LIST_HEAD(nacc_prepare_objects);
static atomic64_t nacc_agent_generation = ATOMIC64_INIT(0);

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
	kfree(agent);
}

static void nacc_prepare_free(struct kref *reference)
{
	struct nacc_prepare_object *prepare =
		container_of(reference, struct nacc_prepare_object, reference);

	if (!list_empty(&prepare->list) ||
	    prepare->lifecycle.state != NACC_LIFECYCLE_EXEC_EMPTY || prepare->mm)
		panic("NACC freeing live prepare object");
	put_task_struct(prepare->target);
	kref_put(&prepare->agent->reference, nacc_agent_free);
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
		ret = nacc_lifecycle_abort_prepare(&prepare->agent->lifecycle,
						   &prepare->lifecycle,
						   target, generation);
		if (ret)
			panic("NACC prepare close abort failed (%d)", ret);
		list_del_init(&prepare->list);
		nacc_finish_destroy_if_drained(prepare->agent);
		kref_put(&prepare->reference, nacc_prepare_free);
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

int nacc_exec_commit_current(void)
{
	struct nacc_prepare_object *prepare;
	int ret = 0;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
	if (prepare && prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_PREPARED) {
		if (prepare->mm)
			panic("NACC first exec commit found an mm binding");
		ret = nacc_lifecycle_commit_exec(
			&prepare->agent->lifecycle, &prepare->lifecycle,
			nacc_target_identity(current),
			prepare->lifecycle.prepare_generation);
	} else if (prepare &&
		 prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		if (prepare->mm != current->mm)
			panic("NACC re-exec commit found an invalid mm binding");
		ret = nacc_lifecycle_commit_reexec(
			&prepare->agent->lifecycle, &prepare->lifecycle,
			nacc_target_identity(current),
			&prepare->lifecycle.prepare_generation);
		if (!ret)
			prepare->post_ponr_errno = 0;
	} else if (prepare) {
		panic("NACC exec commit found invalid transaction state");
	}
	mutex_unlock(&nacc_object_lock);
	return ret;
}

bool nacc_exec_abort_current(void)
{
	struct nacc_prepare_object *prepare;
	int ret;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return false;
	}
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		mutex_unlock(&nacc_object_lock);
		return false;
	}
	ret = nacc_lifecycle_abort_prepare(
		&prepare->agent->lifecycle, &prepare->lifecycle,
		nacc_target_identity(current),
		prepare->lifecycle.prepare_generation);
	if (ret)
		panic("NACC exec pre-PONR abort failed (%d)", ret);
	list_del_init(&prepare->list);
	nacc_finish_destroy_if_drained(prepare->agent);
	mutex_unlock(&nacc_object_lock);
	kref_put(&prepare->reference, nacc_prepare_free);
	return true;
}

void nacc_exec_bind_mm_current(void)
{
	struct nacc_prepare_object *prepare;
	struct mm_struct *old_mm = NULL;

	if (!current->mm)
		panic("NACC exec installed a missing mm");
	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return;
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
	mutex_unlock(&nacc_object_lock);
	if (old_mm)
		mmput(old_mm);
}

void nacc_exec_activate_current(void)
{
	struct nacc_prepare_object *prepare;
	int ret;

	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
	if (!prepare) {
		mutex_unlock(&nacc_object_lock);
		return;
	}
	if (prepare->mm != current->mm)
		panic("NACC exec activation found an invalid mm binding");
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

void nacc_exec_record_failure_current(int failure_errno)
{
	struct nacc_prepare_object *prepare;

	if (failure_errno <= 0)
		panic("NACC exec recorded invalid failure errno");
	mutex_lock(&nacc_object_lock);
	prepare = nacc_find_prepare_locked(current);
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
	struct mm_struct *mm;
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
	if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_PREPARED) {
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
		if (!ret)
			ret = nacc_lifecycle_retire_exec(
				&prepare->agent->lifecycle, &prepare->lifecycle,
				target, generation);
	} else if (prepare->lifecycle.state == NACC_LIFECYCLE_EXEC_ACTIVE) {
		ret = nacc_lifecycle_target_exited(
			&prepare->agent->lifecycle, &prepare->lifecycle, target,
			generation);
		if (!ret)
			ret = nacc_lifecycle_retire_exec(
				&prepare->agent->lifecycle, &prepare->lifecycle,
				target, generation);
	} else {
		panic("NACC task exit found invalid transaction state");
	}
	if (ret)
		panic("NACC task exit transition failed (%d)", ret);
	mm = prepare->mm;
	prepare->mm = NULL;
	list_del_init(&prepare->list);
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
	if (agent)
		agent->orphaned = true;
	if (agent && agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DEAD &&
	    agent->lifecycle.state != NACC_LIFECYCLE_AGENT_DESTROYING) {
		ret = nacc_lifecycle_begin_destroy(
			&agent->lifecycle, agent->lifecycle.agent_cookie,
			agent->lifecycle.agent_generation);
		if (ret)
			panic("NACC control close cannot begin destroy (%d)", ret);
	}
	if (agent && !agent->lifecycle.transaction_count) {
		ret = nacc_lifecycle_finish_destroy(&agent->lifecycle);
		if (ret && ret != -EALREADY)
			panic("NACC control close cannot finish destroy (%d)", ret);
	}
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
	mutex_unlock(&nacc_object_lock);
	request.agent_cookie = cookie;
	request.agent_generation = generation;
	request.header.features = NACC_UAPI_FEATURE_BASE;
	if (copy_to_user(argument, &request, sizeof(request))) {
		ret = nacc_lifecycle_begin_destroy(&agent->lifecycle, cookie,
						   generation);
		if (ret || nacc_lifecycle_finish_destroy(&agent->lifecycle))
			panic("NACC Agent create rollback failed");
		kref_put(&agent->reference, nacc_agent_free);
		return -EFAULT;
	}
	mutex_lock(&nacc_object_lock);
	if (control->agent) {
		mutex_unlock(&nacc_object_lock);
		ret = nacc_lifecycle_begin_destroy(&agent->lifecycle, cookie,
						   generation);
		if (ret || nacc_lifecycle_finish_destroy(&agent->lifecycle))
			panic("NACC raced Agent cleanup failed");
		kref_put(&agent->reference, nacc_agent_free);
		return -EALREADY;
	}
	control->agent = agent;
	mutex_unlock(&nacc_object_lock);
	return 0;
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
	request.header.features = NACC_UAPI_FEATURE_BASE;
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
	request.header.features = NACC_UAPI_FEATURE_BASE;
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
	ret = nacc_lifecycle_finish_destroy(&agent->lifecycle);
	if (!ret)
		control->agent = NULL;
out_unlock:
	mutex_unlock(&nacc_object_lock);
	if (!ret)
		kref_put(&agent->reference, nacc_agent_free);
	return ret;
}
