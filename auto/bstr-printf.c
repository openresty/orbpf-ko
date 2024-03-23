#include <linux/string.h>

void foo(char *buf, size_t size, const char *fmt, const u32 *bin_buf)
{
	bstr_printf(buf, size, fmt, bin_buf);
}
