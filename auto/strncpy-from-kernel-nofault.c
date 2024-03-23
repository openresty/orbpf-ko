#include <linux/uaccess.h>

long foo(char *dst, const void *unsafe_addr, long count)
{
	return strncpy_from_kernel_nofault(dst, unsafe_addr, count);
}
