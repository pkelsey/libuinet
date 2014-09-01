#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/systm.h>
#include <sys/kdb.h>

int kdb_active = 0;

void
kdb_backtrace(void)
{

	printf("%s: called\n", __func__);
}

void
kdb_backtrace_thread(struct thread *td)
{

	printf("%s: called; thr=%p\n", __func__, td);
}
