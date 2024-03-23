#include <linux/bpf.h>
#include <linux/btf.h>

const struct btf_member *foo(const struct btf_type *t)
{
	return btf_type_member(t);
}
