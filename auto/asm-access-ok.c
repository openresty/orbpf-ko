#include <linux/uaccess.h>

bool foo(const void __user *ptr, size_t size)
{
	return __access_ok(ptr, size);
}
