#include <linux/bpf.h>
#include <linux/btf.h>

int foo(const struct btf_type *t)
{
	return btf_type_vlen(t);
}
