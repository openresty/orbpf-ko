#include <linux/ktime.h>

ktime_t foo(void)
{
	return ktime_get_coarse();
}
