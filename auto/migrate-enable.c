#include <linux/preempt.h>

void foo(void)
{
	migrate_enable();
}
