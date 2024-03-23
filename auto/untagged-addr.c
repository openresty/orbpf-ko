#include <linux/mm.h>

const char *foo(const char *src)
{
	return untagged_addr(src);
}
