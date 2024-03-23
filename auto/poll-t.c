#include <linux/types.h>

unsigned int foo(__poll_t a)
{
    return a + 1;
}
