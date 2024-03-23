#include <linux/bpf.h>

struct bpf_map *foo(struct bpf_map *map, bool b)
{
	return bpf_map_inc(map, b);
}
