#include <linux/uprobes.h>

int foo(enum uprobe_filter_ctx a) {
	return UPROBE_FILTER_REGISTER + a;
}
