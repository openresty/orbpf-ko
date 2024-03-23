#include <linux/random.h>

unsigned long foo(void)
{
	return get_random_long();
}
