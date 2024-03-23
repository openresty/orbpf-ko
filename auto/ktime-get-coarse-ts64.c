#include <linux/ktime.h>

void foo(struct timespec64 *ts)
{
	ktime_get_coarse_ts64(ts);
}
