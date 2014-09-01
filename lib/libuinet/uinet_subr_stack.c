#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/systm.h>
#include <sys/stack.h>
#include <sys/_stack.h>

void
stack_save_td(struct stack *st, struct thread *td)
{

}

void
stack_save(struct stack *st)
{
	int i, n;

	uintptr_t pcs[STACK_MAX];

	n = uhi_get_stacktrace(pcs, STACK_MAX);
	for (i = 0; i < n; i++) {
		st->pcs[i] = (vm_offset_t) pcs[i];
	}
	st->depth = n;
}
