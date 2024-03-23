#include <linux/uaccess.h>

unsigned long foo(void *dst, void __user *src, size_t size)
{
    return raw_copy_from_user(dst, src, size);
}
