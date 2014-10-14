/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
 * Copyright (c) 2014 Patrick Kelsey. All rights reserved.
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


#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/smp.h>
#include <sys/ucred.h>

/* XXX - should we really be picking up the host stdarg? */ 
#include <machine/stdarg.h>

#include "uinet_host_interface.h"


void uinet_init_thread0(void);


static struct uinet_thread uinet_thread0;
uhi_tls_key_t kthread_tls_key;

struct uinet_thread *
uinet_thread_alloc(struct proc *p)
{
	struct uinet_thread *utd = NULL;
	struct thread *td = NULL;
	struct mtx *lock = NULL;
	struct cv *cond = NULL;

	if (NULL == p) {
		p = &proc0;
	}

	utd = malloc(sizeof(struct uinet_thread), M_DEVBUF, M_ZERO | M_WAITOK);
	if (NULL == utd)
		goto error;

	td = malloc(sizeof(struct thread), M_DEVBUF, M_ZERO | M_WAITOK);
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
	td->td_pflags |= TDP_KTHREAD;
	td->td_oncpu = 0;
	td->td_stop_req = NULL;
	td->td_last_stop_check = ticks;

	utd->td = td;

	return (utd);

error:
	if (utd) free(utd, M_DEVBUF);
	if (td) free(td, M_DEVBUF);
	if (lock) free(lock, M_DEVBUF);
	if (cond) free(cond, M_DEVBUF);

	return (NULL);
}


void
uinet_thread_free(struct uinet_thread *utd)
{
	struct thread *td = utd->td;

	crfree(td->td_proc->p_ucred);
	mtx_destroy(td->td_lock);
	free(td->td_lock, M_DEVBUF);
	cv_destroy((struct cv *)td->td_sleepqueue);
	free(td->td_sleepqueue, M_DEVBUF);
	free(td, M_DEVBUF);
	free(utd, M_DEVBUF);
}


static void
tls_destructor(void *tls_data)
{
	struct uinet_thread *utd = tls_data;

	if (utd != &uinet_thread0)
		uinet_thread_free(utd);
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
	struct uinet_thread *utd;
	struct thread *td;
	va_list ap;

	utd = uinet_thread_alloc(p);
	if (NULL == utd)
		return (ENOMEM);

	td = utd->td;

	if (tdp)
		*tdp = td;

	tsa = malloc(sizeof(struct uhi_thread_start_args), M_DEVBUF, M_WAITOK);
	tsa->start_routine = start_routine;
	tsa->start_routine_arg = arg;
	tsa->end_routine = NULL;
	tsa->tls_key = kthread_tls_key;
	tsa->tls_data = utd;

	/* Have uhi_thread_create() store the host thread ID in td_wchan */
	KASSERT(sizeof(td->td_wchan) >= sizeof(uhi_thread_t), ("kthread_add: can't safely store host thread id"));
	tsa->host_thread_id = (uhi_thread_t *)&td->td_wchan;
	tsa->oncpu = &td->td_oncpu;

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
	struct uinet_thread *utd;
	struct thread *td;
	va_list ap;

	utd = uinet_thread_alloc(*p);
	if (NULL == utd)
		return (ENOMEM);

	td = utd->td;

	if (tdp)
		*tdp = td;

	tsa = malloc(sizeof(struct uhi_thread_start_args), M_DEVBUF, M_WAITOK);
	tsa->start_routine = start_routine;
	tsa->start_routine_arg = arg;
	tsa->end_routine = NULL;
	tsa->tls_key = kthread_tls_key;
	tsa->tls_data = utd;

	/* Have uhi_thread_create() store the host thread ID in td_wchan */
	KASSERT(sizeof(td->td_wchan) >= sizeof(uhi_thread_t), ("kproc_kthread_add: can't safely store host thread id"));
	tsa->host_thread_id = (uhi_thread_t *)&td->td_wchan;
	tsa->oncpu = &td->td_oncpu;

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


/* This must be run from thread0 */
void
uinet_init_thread0(void)
{
	struct thread *td;
	int cpuid;

	if (uhi_tls_key_create(&kthread_tls_key, tls_destructor))
		panic("Could not create kthread subsystem tls key");

	td = &thread0;
	td->td_proc = &proc0;

	KASSERT(sizeof(td->td_wchan) >= sizeof(uhi_thread_t), ("uinet_init_thread0: can't safely store host thread id"));
	td->td_wchan = (void *)uhi_thread_self();

	cpuid = uhi_thread_bound_cpu();
	td->td_oncpu = (cpuid == -1) ? 0 : cpuid % mp_ncpus;
	
	uinet_thread0.td = td;

	uhi_tls_set(kthread_tls_key, &uinet_thread0);
}


void
kthread_stop(struct thread *td, struct thread_stop_req *tsr)
{
	mtx_init(&tsr->tsr_lock, "tsr_lock", NULL, MTX_DEF);
	cv_init(&tsr->tsr_cv, "tsr_cv");
	tsr->tsr_ack = 0;

	mtx_lock(td->td_lock);
	td->td_stop_req = tsr;
	mtx_unlock(td->td_lock);
}


void
kthread_stop_wait(struct thread_stop_req *tsr)
{
	mtx_lock(&tsr->tsr_lock);
	while (!tsr->tsr_ack)
		cv_wait(&tsr->tsr_cv, &tsr->tsr_lock);
	mtx_unlock(&tsr->tsr_lock);

	cv_destroy(&tsr->tsr_cv);
	mtx_destroy(&tsr->tsr_lock);
}


int
kthread_stop_check(void)
{
	int stop = 0;
	struct thread *td = curthread;

	if (ticks - td->td_last_stop_check >= hz) {
		td->td_last_stop_check = ticks;
		mtx_lock(td->td_lock);
		if (td->td_stop_req)
			stop = 1;
		mtx_unlock(td->td_lock);
	}

	return (stop);
}


void
kthread_stop_ack(void)
{
	struct thread *td = curthread;
	struct thread_stop_req *tsr = td->td_stop_req;

	mtx_lock(&tsr->tsr_lock);
	tsr->tsr_ack = 1;
	cv_signal(&tsr->tsr_cv);
	mtx_unlock(&tsr->tsr_lock);
}

