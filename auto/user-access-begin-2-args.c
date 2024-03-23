#include <linux/uaccess.h>

bool foo(const void __user *ptr, size_t size)
{
	return user_access_begin(ptr, size);
}
