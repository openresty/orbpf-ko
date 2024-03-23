#include <linux/kprobes.h>

struct kretprobe* foo(struct kretprobe_instance* ri)
{
	return ri->rp;
}
