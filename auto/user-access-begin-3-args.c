#include <linux/uaccess.h>

bool foo(int mode, const void __user *ptr, size_t size)
{
	return user_access_begin(mode, ptr, size);
}
