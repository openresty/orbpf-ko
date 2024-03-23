#include <linux/filter.h>
#include <linux/bpf.h>

void foo(struct bpf_prog *f, char *sym)
{
	bpf_get_prog_name(f, sym);
}
