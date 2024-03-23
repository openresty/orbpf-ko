#include <linux/atomic.h>

bool foo(atomic64_t *v, s64 *old, s64 new)
{
	return atomic64_try_cmpxchg(v, old, new);
}
