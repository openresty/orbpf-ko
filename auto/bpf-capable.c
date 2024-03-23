#include <linux/capability.h>

bool foo(void) {
	return bpf_capable();
}
