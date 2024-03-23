#include <linux/uaccess.h>

int foo(void *addr, size_t size) {
    return check_zeroed_user(addr, size);
}
