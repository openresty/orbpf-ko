#include <linux/random.h>

unsigned int foo(void)
{
	return get_random_u32();
}
