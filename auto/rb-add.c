#include <linux/rbtree.h>

void foo(struct rb_node *node, struct rb_root *tree, void *less)
{
	rb_add(node, tree, less);
}
