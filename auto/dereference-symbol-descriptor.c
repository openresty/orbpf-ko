#include <linux/kallsyms.h>

void *foo(void *ptr)
{
	return dereference_symbol_descriptor(ptr);
}
