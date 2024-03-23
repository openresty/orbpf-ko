#include <linux/bpf.h>

void *foo(struct sk_reuseport_kern *p)
{
	return p;
}
