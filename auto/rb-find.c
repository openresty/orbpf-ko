#include <linux/rbtree.h>

void foo(struct rb_node *node, struct rb_root *tree, void *cmp)
{
	rb_find(node, tree, cmp);
}
