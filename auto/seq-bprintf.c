#include <linux/seq_file.h>

void foo(struct seq_file *m, const char *f, const u32 *binary)
{
	seq_bprintf(m, f, binary);
}
