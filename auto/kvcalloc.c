#include <linux/mm.h>

void *foo(size_t n, size_t size, gfp_t flags)
{
	return kvcalloc(n, size, flags);
}
