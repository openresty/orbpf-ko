#include <linux/if_vlan.h>

int foo(enum netns_bpf_attach_type a) {
	return a;
}
