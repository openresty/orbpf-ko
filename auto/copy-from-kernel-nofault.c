#include <linux/uaccess.h>

long foo(void *dst, const void *src, size_t size) {
	return copy_from_kernel_nofault(dst, src, size);
}
