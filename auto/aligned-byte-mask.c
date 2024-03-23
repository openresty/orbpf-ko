#include <linux/bitops.h>

unsigned long foo(long a)
{
    return aligned_byte_mask(a);
}
