/* Copyright (C) by OpenResty Inc. All rights reserved. */

#include <stdio.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define ORBPF_IOC_PING_NR  5

#define ORBPF_IOC_TYPE 'O'
#define ORBPF_IOC_PING _IO(ORBPF_IOC_TYPE, ORBPF_IOC_PING_NR)
#define ORBPF_IOC_BAD _IO(ORBPF_IOC_TYPE, 123456)

#define FAIL(...) \
	fprintf(stderr, "line %d: ", __LINE__); \
	fprintf(stderr, __VA_ARGS__); \
	if (errno) { \
		fprintf(stderr, ": %s\n", strerror(errno)); \
	} else { \
		fprintf(stderr, "\n"); \
	} \
	exit(1);

#define PASS() \
	printf("ok %d # line %d\n", ++test_cnt, __LINE__);

#define OK(val, msg) \
	if (val) { \
		PASS(); \
	} else { \
		FAIL(msg); \
	}

int
main(void)
{
	int fd, ret, i;
	int cmd = ORBPF_IOC_PING;
	void *data = NULL;
	int test_cnt = 0;

	fd = open("/dev/orbpf", O_RDONLY);
	OK(fd >= 0, "open dev file failed");

	for (i = 0; i < 3; i++) {
		ret = ioctl(fd, cmd, data);
		if (ret != 0) {
			FAIL("ioctl good cmd failed: %d", ret);
		} else {
			PASS();
		}
	}

	cmd = ORBPF_IOC_BAD;
	ret = ioctl(fd, cmd, data);
	if (ret == 0) {
		FAIL("ioctl bad cmd succeeded unexpectedly");
	} else {
		PASS();
	}

	ret = close(fd);
	OK(ret == 0, "close failed");

	{
		FILE *f;
		int a = 0, b = 0, c = 0;
		int n;
		f = fopen("/sys/module/orbpf/version", "r");
		OK(f, "open module version file");
		n = fscanf(f, "%u.%u.%u\n", &a, &b, &c);
		OK(fclose(f) == 0, "close version file");

		OK(n == 3, "3-segment version number");
		OK(a >= 0 && a <= 999, "first version seg");
		OK(b >= 0 && b <= 999, "second version seg");
		OK(c > 0 && c <= 999, "third version seg");
	}

	printf("All tests successful (%d tests).\n", test_cnt);
	return 0;
}
