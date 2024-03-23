#include <linux/uaccess.h>

long foo(char *dst, const void __user *src, long count) {
	return strncpy_from_user_nofault(dst, src, count);
}
