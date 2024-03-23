#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/overflow.h>

size_t foo(size_t n, size_t len)
{
	return array_size(n, len);
}
