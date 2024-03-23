#include <linux/bpf.h>
#include <linux/filter.h>

const char *foo(struct bpf_prog *f)
{
	return f->aux->ksym.name;
}
