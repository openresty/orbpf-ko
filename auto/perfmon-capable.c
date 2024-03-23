#include <linux/capability.h>

bool foo(void) {
	return perfmon_capable();
}
