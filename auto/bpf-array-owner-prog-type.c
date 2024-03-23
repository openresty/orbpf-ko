#include <linux/bpf.h>

u32 foo(struct bpf_array *arr)
{
	return arr->owner_prog_type;
}
