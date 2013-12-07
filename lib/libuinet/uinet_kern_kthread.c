/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Derived in part from libplebnet's pn_compat.c.
 *
 */


#include <uinet_sys/param.h>
#include <uinet_sys/types.h>
#include <uinet_sys/kthread.h>
#include <uinet_sys/malloc.h>
#include <uinet_sys/proc.h>
#include <uinet_sys/systm.h>
#include <uinet_sys/lock.h>
#include <uinet_sys/mutex.h>
#include <uinet_sys/condvar.h>
#include <uinet_sys/ucred.h>

/* XXX - should we really be picking up the host stdarg? */ 
#include <uinet_machine/stdarg.h>

#include "uinet_host_interface.h"


void uinet_init_thread0(void);
struct thread *uinet_thread_alloc(struct proc *p);


struct thread *
uinet_thread_alloc(struct proc *p)
{
	struct thread *td = NULL;
	struct mtx *lock = NULL;
	struct cv *cond = NULL;

	if (NULL == p) {
		p = &proc0;
	}

	td = malloc(sizeof(struct thread), M_DEVBUF, M_WAITOK);
	if (NULL == td)
		goto error;

	lock = malloc(sizeof(struct mtx), M_DEVBUF, M_WAITOK);
	if (NULL == lock)
		goto error;

	cond = malloc(sizeof(struct cv), M_DEVBUF, M_WAITOK);
	if (NULL == cond)
		goto error;

	cv_init(cond, "thread_sleepq");
	mtx_init(lock, "thread_lock", NULL, MTX_DEF);
	td->td_lock = lock;
	td->td_sleepqueue = (struct sleepqueue *)cond;
	td->td_ucred = crhold(p->p_ucred);
	td->td_proc = p;

	return (td);

error:
	if (td) free(td, M_DEVBUF);
	if (lock) free(lock, M_DEVBUF);
	if (cond) free(cond, M_DEVBUF);

	return (NULL);
}


static void
thread_end_routine(struct uhi_thread_start_args *start_args)
{
	struct thread *td = start_args->thread_specific_data;

	cv_destroy((struct cv *)&td->td_sleepqueue);
}


/*
 * N.B. The flags are ignored.  Namely RFSTOPPED is not honored and threads
 * are started right away.
 */
int
kthread_add(void (*start_routine)(void *), void *arg, struct proc *p,  
    struct thread **tdp, int flags, int pages,
    const char *str, ...)
{
	int error;
	uhi_thread_t host_thread;
	struct uhi_thread_start_args *tsa;
	struct thread *td;
	va_list ap;

	td = uinet_thread_alloc(p);
	if (NULL == td)
		return (ENOMEM);

	if (tdp)
		*tdp = td;

	tsa = malloc(sizeof(struct uhi_thread_start_args), M_DEVBUF, M_WAITOK);
	tsa->start_routine = start_routine;
	tsa->start_routine_arg = arg;
	tsa->end_routine = thread_end_routine;
	tsa->thread_specific_data = td;

	/* Have uhi_thread_create() store the host thread ID in td_wchan */
	KASSERT(sizeof(td->td_wchan) >= sizeof(uhi_thread_t), ("kthread_add: can't safely store host thread id"));
	tsa->host_thread_id = &td->td_wchan;

	va_start(ap, str);
	vsnprintf(tsa->name, sizeof(tsa->name), str, ap);
	va_end(ap);

	error = uhi_thread_create(&host_thread, tsa, pages * PAGE_SIZE); 

	/*
	 * Ensure tc_wchan is valid before kthread_add returns, in case the
	 * thread has not started yet.
	 */
	td->td_wchan = (void *)host_thread; /* safety of this cast checked by the KASSERT above */
	return (error);
}

void
kthread_exit(void)
{
	uhi_thread_exit();
}

/*
 * N.B. This doesn't actually create the proc if it doesn't exist. It 
 * just uses proc0. 
 */
int
kproc_kthread_add(void (*start_routine)(void *), void *arg,
    struct proc **p,  struct thread **tdp,
    int flags, int pages,
    const char * procname, const char *str, ...)
{
	int error;
	uhi_thread_t host_thread;
	struct uhi_thread_start_args *tsa;
	struct thread *td;
	va_list ap;

	td = uinet_thread_alloc(*p);
	if (NULL == td)
		return (ENOMEM);

	if (tdp)
		*tdp = td;

	tsa = malloc(sizeof(struct uhi_thread_start_args), M_DEVBUF, M_WAITOK);
	tsa->start_routine = start_routine;
	tsa->start_routine_arg = arg;
	tsa->end_routine = thread_end_routine;
	tsa->thread_specific_data = td;

	/* Have uhi_thread_create() store the host thread ID in td_wchan */
	KASSERT(sizeof(td->td_wchan) >= sizeof(uhi_thread_t), ("kproc_kthread_add: can't safely store host thread id"));
	tsa->host_thread_id = &td->td_wchan;

	va_start(ap, str);
	vsnprintf(tsa->name, sizeof(tsa->name), str, ap);
	va_end(ap);

	error = uhi_thread_create(&host_thread, tsa, pages * PAGE_SIZE); 

	/*
	 * Ensure tc_wchan is valid before kthread_add returns, in case the
	 * thread has not started yet.
	 */
	td->td_wchan = (void *)host_thread; /* safety of this cast checked by the KASSERT above */
	return (error);
}


void
uinet_init_thread0(void)
{
	struct thread *td;

	td = &thread0;
	td->td_proc = &proc0;

	KASSERT(sizeof(td->td_wchan) >= sizeof(uhi_thread_t), ("uinet_init_thread0: can't safely store host thread id"));
	td->td_wchan = (void *)uhi_thread_self();

	uhi_thread_set_thread_specific_data(td);
}


