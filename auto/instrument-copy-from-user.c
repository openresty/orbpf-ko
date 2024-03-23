#include <linux/instrumented.h>

void
foo(const void *to, const void __user *from, unsigned long n)
{
	instrument_copy_from_user_before(to, from, n);
}
