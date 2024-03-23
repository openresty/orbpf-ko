#include <linux/bpf.h>

void *foo(const struct bpf_map_ops *ops)
{
	return ops->map_mmap;
}
