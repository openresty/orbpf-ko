#include <linux/stddef.h>
#include <linux/sched.h>

size_t foo(void)
{
	return sizeof_field(struct task_struct, mm);
}
