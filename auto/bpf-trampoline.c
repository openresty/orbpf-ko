#include <linux/bpf.h>

void *foo(struct bpf_trampoline *p) {
	return p;
}
