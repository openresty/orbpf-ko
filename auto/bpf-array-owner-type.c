#include <linux/bpf.h>

u32 foo(struct bpf_array *m)
{
	return m->owner.type;
}
