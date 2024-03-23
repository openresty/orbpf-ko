#include <linux/bpf.h>

void foo(struct bpf_map *map, struct user_struct *user)
{
	map->user = user;
}
