#include <linux/irq_work.h>

bool foo(struct irq_work *work)
{
	return irq_work_is_busy(work);
}
