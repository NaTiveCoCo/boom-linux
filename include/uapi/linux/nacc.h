/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_NACC_H
#define _UAPI_LINUX_NACC_H

#include <linux/const.h>
#include <linux/ioctl.h>
#include <linux/types.h>

#define NACC_UAPI_ABI_MAGIC 0x4e41434355415049ULL
#define NACC_UAPI_ABI_MAJOR 1U
#define NACC_UAPI_ABI_MINOR 0U

#define NACC_UAPI_FEATURE_BASE _BITULL(0)
#define NACC_UAPI_FEATURE_AGENT_LIFECYCLE _BITULL(1)
#define NACC_UAPI_FEATURE_PREPARE_EXEC _BITULL(2)
#define NACC_UAPI_FEATURE_STATUS _BITULL(3)

#define NACC_UAPI_RESERVED_WORDS 4U

/*
 * ioctl command 编码中的 `_IOC_SIZE(command)` 是实际 user buffer 长度；
 * `struct_size` 必须与它一致。请求的 `features` 是 required feature 集合，
 * 成功响应中的 `features` 是 kernel 实际提供的集合。
 */
struct nacc_uapi_header {
	__u16 abi_major;
	__u16 abi_minor;
	__u32 struct_size;
	__u64 features;
	__u64 reserved[NACC_UAPI_RESERVED_WORDS];
};

struct nacc_ioc_get_abi {
	struct nacc_uapi_header header;
	__u64 abi_magic;
	__u32 max_ioctl_size;
	__u32 reserved0;
};

/* control FD 持有 Linux capability；agent_cookie 不得暴露给 payload。 */
struct nacc_ioc_create_agent {
	struct nacc_uapi_header header;
	__u64 flags;
	__u64 requested_pool_pages;
	__u64 agent_cookie;
	__u64 agent_generation;
	__u64 reserved[NACC_UAPI_RESERVED_WORDS];
};

/* prepare_fd 是绑定 pidfd target 的一次性 exec prepare capability。 */
struct nacc_ioc_prepare_exec {
	struct nacc_uapi_header header;
	__s32 pidfd;
	__u32 flags;
	__s32 prepare_fd;
	__u32 reserved0;
	__u64 agent_cookie;
	__u64 agent_generation;
	__u64 reserved[NACC_UAPI_RESERVED_WORDS];
};

enum nacc_agent_status {
	NACC_AGENT_STATUS_CREATED = 1,
	NACC_AGENT_STATUS_PREPARED,
	NACC_AGENT_STATUS_ACTIVE,
	NACC_AGENT_STATUS_DESTROYING,
	NACC_AGENT_STATUS_DEAD,
	NACC_AGENT_STATUS_FAILED,
};

struct nacc_ioc_query_status {
	struct nacc_uapi_header header;
	__u64 agent_cookie;
	__u64 agent_generation;
	__u32 status;
	__s32 failure_errno;
	__u64 reserved[NACC_UAPI_RESERVED_WORDS];
};

struct nacc_ioc_destroy_agent {
	struct nacc_uapi_header header;
	__u64 agent_cookie;
	__u64 agent_generation;
	__u64 flags;
	__u64 reserved[NACC_UAPI_RESERVED_WORDS];
};

#define NACC_IOC_MAGIC 'N'

#define NACC_IOC_NR_GET_ABI 0x00
#define NACC_IOC_NR_CREATE_AGENT 0x10
#define NACC_IOC_NR_PREPARE_EXEC 0x11
#define NACC_IOC_NR_QUERY_STATUS 0x12
#define NACC_IOC_NR_DESTROY_AGENT 0x13

#define NACC_IOC_GET_ABI                                                    \
	_IOWR(NACC_IOC_MAGIC, NACC_IOC_NR_GET_ABI, struct nacc_ioc_get_abi)
#define NACC_IOC_CREATE_AGENT                                               \
	_IOWR(NACC_IOC_MAGIC, NACC_IOC_NR_CREATE_AGENT,                       \
	      struct nacc_ioc_create_agent)
#define NACC_IOC_PREPARE_EXEC                                               \
	_IOWR(NACC_IOC_MAGIC, NACC_IOC_NR_PREPARE_EXEC,                       \
	      struct nacc_ioc_prepare_exec)
#define NACC_IOC_QUERY_STATUS                                               \
	_IOWR(NACC_IOC_MAGIC, NACC_IOC_NR_QUERY_STATUS,                       \
	      struct nacc_ioc_query_status)
#define NACC_IOC_DESTROY_AGENT                                              \
	_IOWR(NACC_IOC_MAGIC, NACC_IOC_NR_DESTROY_AGENT,                      \
	      struct nacc_ioc_destroy_agent)

#define NACC_UAPI_MAX_IOCTL_SIZE_V1 ((unsigned int)sizeof(struct nacc_ioc_create_agent))

#endif /* _UAPI_LINUX_NACC_H */
