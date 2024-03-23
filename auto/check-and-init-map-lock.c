#include <linux/bpf.h>

void foo(struct bpf_map *map, void *dst)
{
	check_and_init_map_lock(map, dst);
}
