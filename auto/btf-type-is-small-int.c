#include <linux/bpf.h>
#include <linux/btf.h>

bool foo(const struct btf_type *t)
{
	return btf_type_is_small_int(t);
}
