#include <linux/instrumented.h>

void
foo(const void *to, const void __user *from, unsigned long n, unsigned long left)
{
	instrument_copy_from_user_before(to, from, n);
	instrument_copy_from_user_after(to, from, n, left);
}
