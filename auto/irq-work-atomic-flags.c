#include <linux/irq_work.h>

bool irq_work_is_busy(struct irq_work *work)
{
 	return atomic_read(&work->flags) & IRQ_WORK_BUSY;
}
