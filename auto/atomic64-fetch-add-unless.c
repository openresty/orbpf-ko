#include <linux/atomic.h>

s64 foo(atomic64_t *v, s64 a, s64 u)
{
	return atomic64_fetch_add_unless(v, a, u);
}
