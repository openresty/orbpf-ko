#include <linux/fs.h>

int foo(struct dentry *dentry, umode_t mode,
		int (*f)(struct dentry *, umode_t, void *),
		void *arg)
{
	return vfs_mkobj(dentry, ode, f, arg);
}
