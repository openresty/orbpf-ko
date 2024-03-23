#include <linux/uaccess.h>
#include <asm/tlbflush.h>

bool foo(void) {
        return nmi_uaccess_okay();
}
