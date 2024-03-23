#include <linux/proc_ns.h>

bool foo(const struct ns_common *ns, dev_t dev, ino_t ino)
{
	return ns_match(ns, dev, ino);
}
