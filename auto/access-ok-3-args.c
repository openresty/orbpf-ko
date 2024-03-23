#include <linux/uaccess.h>

int foo(unsigned long addr, size_t len) {
    return access_ok(VERIFY_READ, addr, len);
}
