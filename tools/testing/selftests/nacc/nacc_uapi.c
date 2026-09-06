// SPDX-License-Identifier: GPL-2.0

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/nacc.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../kselftest.h"

#define NACC_LIVE_TEST_COUNT 7

static_assert(sizeof(struct nacc_uapi_header) == 48, "UAPI header size");
static_assert(sizeof(struct nacc_ioc_get_abi) == 64, "GET_ABI size");
static_assert(sizeof(struct nacc_ioc_create_agent) == 112,
	      "CREATE_AGENT size");
static_assert(sizeof(struct nacc_ioc_prepare_exec) == 112,
	      "PREPARE_EXEC size");
static_assert(sizeof(struct nacc_ioc_query_status) == 104,
	      "QUERY_STATUS size");
static_assert(sizeof(struct nacc_ioc_destroy_agent) == 104,
	      "DESTROY_AGENT size");

static int failures;

static void initialize_header(struct nacc_uapi_header *header, uint32_t size)
{
	memset(header, 0, sizeof(*header));
	header->abi_major = NACC_UAPI_ABI_MAJOR;
	header->abi_minor = NACC_UAPI_ABI_MINOR;
	header->struct_size = size;
}

static void report_result(int condition, const char *name)
{
	if (condition) {
		ksft_test_result_pass("%s\n", name);
		return;
	}

	ksft_test_result_fail("%s\n", name);
	failures++;
}

static void skip_live_tests(const char *reason)
{
	int index;

	for (index = 0; index < NACC_LIVE_TEST_COUNT; index++)
		ksft_test_result_skip("/dev/nacc unavailable: %s\n", reason);
}

int main(void)
{
	struct nacc_ioc_create_agent create_agent = {};
	struct nacc_ioc_get_abi get_abi = {};
	unsigned long short_command;
	int device;
	int result;

	ksft_print_header();
	ksft_set_plan(1 + NACC_LIVE_TEST_COUNT);

	report_result(_IOC_TYPE(NACC_IOC_GET_ABI) == NACC_IOC_MAGIC &&
		      _IOC_NR(NACC_IOC_GET_ABI) == NACC_IOC_NR_GET_ABI &&
		      _IOC_SIZE(NACC_IOC_GET_ABI) == sizeof(get_abi) &&
		      sizeof(create_agent) == NACC_UAPI_MAX_IOCTL_SIZE_V1,
		      "UAPI layout and ioctl encoding");

	device = open("/dev/nacc", O_RDWR | O_CLOEXEC);
	if (device < 0) {
		skip_live_tests(strerror(errno));
		return failures ? KSFT_FAIL : KSFT_PASS;
	}

	initialize_header(&get_abi.header, sizeof(get_abi));
	result = ioctl(device, NACC_IOC_GET_ABI, &get_abi);
	report_result(result == 0 &&
		      get_abi.header.abi_major == NACC_UAPI_ABI_MAJOR &&
		      get_abi.header.abi_minor == NACC_UAPI_ABI_MINOR &&
		      get_abi.header.struct_size == sizeof(get_abi) &&
		      get_abi.header.features == NACC_UAPI_FEATURE_BASE &&
		      get_abi.abi_magic == NACC_UAPI_ABI_MAGIC,
		      "GET_ABI returns the supported contract");

	memset(&get_abi, 0, sizeof(get_abi));
	initialize_header(&get_abi.header, sizeof(get_abi));
	get_abi.header.abi_major++;
	errno = 0;
	result = ioctl(device, NACC_IOC_GET_ABI, &get_abi);
	report_result(result == -1 && errno == EPROTONOSUPPORT,
		      "GET_ABI rejects an incompatible major");

	memset(&get_abi, 0, sizeof(get_abi));
	initialize_header(&get_abi.header, sizeof(get_abi));
	get_abi.header.abi_minor++;
	errno = 0;
	result = ioctl(device, NACC_IOC_GET_ABI, &get_abi);
	report_result(result == -1 && errno == EPROTONOSUPPORT,
		      "GET_ABI rejects an unsupported minor");

	memset(&get_abi, 0, sizeof(get_abi));
	initialize_header(&get_abi.header, sizeof(get_abi));
	get_abi.header.features = 1ULL << 63;
	errno = 0;
	result = ioctl(device, NACC_IOC_GET_ABI, &get_abi);
	report_result(result == -1 && errno == EOPNOTSUPP,
		      "GET_ABI rejects an unsupported required feature");

	memset(&get_abi, 0, sizeof(get_abi));
	initialize_header(&get_abi.header, sizeof(get_abi));
	get_abi.header.reserved[0] = 1;
	errno = 0;
	result = ioctl(device, NACC_IOC_GET_ABI, &get_abi);
	report_result(result == -1 && errno == EINVAL,
		      "GET_ABI rejects non-zero reserved fields");

	memset(&get_abi, 0, sizeof(get_abi));
	initialize_header(&get_abi.header, sizeof(get_abi) - 8);
	short_command = _IOC(_IOC_READ | _IOC_WRITE, NACC_IOC_MAGIC,
			     NACC_IOC_NR_GET_ABI, sizeof(get_abi) - 8);
	errno = 0;
	result = ioctl(device, short_command, &get_abi);
	report_result(result == -1 && errno == EINVAL,
		      "GET_ABI rejects a truncated buffer");

	initialize_header(&create_agent.header, sizeof(create_agent));
	errno = 0;
	result = ioctl(device, NACC_IOC_CREATE_AGENT, &create_agent);
	report_result(result == -1 && errno == EOPNOTSUPP,
		      "unadvertised Agent lifecycle fails closed");

	close(device);
	return failures ? KSFT_FAIL : KSFT_PASS;
}
