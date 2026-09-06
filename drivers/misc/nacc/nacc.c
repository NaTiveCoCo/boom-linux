// SPDX-License-Identifier: GPL-2.0
/*
 * NACC control device。
 *
 * 当前只实现 UAPI discovery。Agent lifecycle backend 接入前不公布对应
 * feature，并对这些命令 fail closed，避免 required workload 静默降级。
 */

#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/nacc.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define NACC_SUPPORTED_FEATURES NACC_UAPI_FEATURE_BASE

static int nacc_validate_header(const struct nacc_uapi_header *header,
				size_t user_size)
{
	if (header->struct_size != user_size)
		return -EINVAL;
	if (header->abi_major != NACC_UAPI_ABI_MAJOR)
		return -EPROTONOSUPPORT;
	if (header->abi_minor > NACC_UAPI_ABI_MINOR)
		return -EPROTONOSUPPORT;
	if (header->features & ~NACC_SUPPORTED_FEATURES)
		return -EOPNOTSUPP;
	if (memchr_inv(header->reserved, 0, sizeof(header->reserved)))
		return -EINVAL;

	return 0;
}

static long nacc_get_abi(void __user *user_argument, size_t user_size)
{
	struct nacc_ioc_get_abi request;
	struct nacc_ioc_get_abi response = {};
	int error;

	if (user_size < sizeof(request))
		return -EINVAL;

	error = copy_struct_from_user(&request, sizeof(request), user_argument,
				      user_size);
	if (error)
		return error;

	error = nacc_validate_header(&request.header, user_size);
	if (error)
		return error;
	if (request.abi_magic || request.max_ioctl_size || request.reserved0)
		return -EINVAL;

	response.header.abi_major = NACC_UAPI_ABI_MAJOR;
	response.header.abi_minor = NACC_UAPI_ABI_MINOR;
	response.header.struct_size = sizeof(response);
	response.header.features = NACC_SUPPORTED_FEATURES;
	response.abi_magic = NACC_UAPI_ABI_MAGIC;
	response.max_ioctl_size = NACC_UAPI_MAX_IOCTL_SIZE_V1;

	if (copy_to_user(user_argument, &response, sizeof(response)))
		return -EFAULT;

	return 0;
}

static long nacc_ioctl(struct file *file, unsigned int command,
		       unsigned long argument)
{
	void __user *user_argument = (void __user *)argument;

	if (_IOC_TYPE(command) != NACC_IOC_MAGIC ||
	    _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
		return -ENOTTY;

	switch (_IOC_NR(command)) {
	case NACC_IOC_NR_GET_ABI:
		return nacc_get_abi(user_argument, _IOC_SIZE(command));
	case NACC_IOC_NR_CREATE_AGENT:
	case NACC_IOC_NR_PREPARE_EXEC:
	case NACC_IOC_NR_QUERY_STATUS:
	case NACC_IOC_NR_DESTROY_AGENT:
		return -EOPNOTSUPP;
	default:
		return -ENOTTY;
	}
}

static int nacc_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return nonseekable_open(inode, file);
}

static const struct file_operations nacc_file_operations = {
	.owner = THIS_MODULE,
	.open = nacc_open,
	.unlocked_ioctl = nacc_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = no_llseek,
};

static struct miscdevice nacc_misc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "nacc",
	.fops = &nacc_file_operations,
	.mode = 0600,
};

static int __init nacc_init(void)
{
	return misc_register(&nacc_misc_device);
}

static void __exit nacc_exit(void)
{
	misc_deregister(&nacc_misc_device);
}

module_init(nacc_init);
module_exit(nacc_exit);

MODULE_DESCRIPTION("NACC confidential container control device");
MODULE_LICENSE("GPL");
