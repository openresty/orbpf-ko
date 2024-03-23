#include <linux/bpf.h>

void *foo(u64 size, int numa_node)
{
	return bpf_map_area_mmapable_alloc(size, numa_node);
}
