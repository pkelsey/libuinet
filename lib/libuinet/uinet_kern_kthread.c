/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
 * Copyright (c) 2015 Patrick Kelsey. All rights reserved.
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


struct uinet_thread_started_notice {
	struct mtx lock;
	struct cv cond;
	struct uinet_thread *utd;
};


/*
 * The per-thread uinet context is maintained using thread-local storage.
 * If TLS support isn't available in the toolchain or otherwise isn't used,
 * the uhi API is used (pthreads underneath).  Even if toolchain TLS support
 * is used, the uhi API is still used during thread initialization and
 * destruction.
 */

#ifdef HAS_NATIVE_TLS
__thread struct uinet_thread uinet_curthread;
#endif

void uinet_init_thread0(void);
void uinet_thread_init(void);

struct uinet_thread *uinet_thread0;
uhi_tls_key_t kthread_tls_key;

/*
 * This routine runs in the context of a newly created thread after all
 * other initialization has occurred and just before the thread entry point
 * is invoked.
 */
static void
uinet_thread_start_hook(void *arg)
{
	struct uinet_thread *utd;
	struct thread *td;
	int is_thread_zero;
	int cpuid;

	utd = uhi_tls_get(kthread_tls_key);
	is_thread_zero = (utd == uinet_thread0);

#ifdef HAS_NATIVE_TLS
	/*
	 * Dispose of the allocated struct uinet_thread and replace with the
	 * native TLS version.
	 */
	/* td_proc is set in uinet_thread_alloc and thus needs to be copied. */
	uinet_curthread.td.td_proc = utd->td.td_proc;
	uhi_tls_set(kthread_tls_key, &uinet_curthread);
	free(utd, M_DEVBUF);
	utd = &uinet_curthread;
#endif
	td = &utd->td;
	cv_init(&utd->cond, "thread_sleepq");
	mtx_init(&utd->lock, "thread_lock", NULL, MTX_DEF);
	td->td_lock = &utd->lock;
	td->td_sleepqueue = (struct sleepqueue *)(&utd->cond);
 	td->td_last_stop_check = ticks;
	td->td_stop_check_ticks = hz / 2;
	td->td_stop_req = NULL;
	td->td_pflags |= TDP_KTHREAD;

	if (!is_thread_zero) {
		/* for thread0, the ucred is initialized in proc0_init */
		td->td_ucred = crhold(td->td_proc->p_ucred);
	}

	KASSERT(sizeof(curthread->td_wchan) >= sizeof(uhi_thread_t), ("kthread_add: can't safely store host thread id"));
	td->td_wchan = (void *)uhi_thread_self(); /* safety of this cast checked by the KASSERT above */
	cpuid = uhi_thread_bound_cpu();
	td->td_oncpu = (cpuid == -1) ? 0 : cpuid % mp_ncpus;
}


static void
tls_destructor(void *tls_data)
{
	struct uinet_thread *utd = tls_data;

	uinet_thread_free(utd);
}


/*
 * Initialize the uinet kthread shim facility.
 */
void
uinet_thread_init(void)
{
	if (uhi_tls_key_create(&kthread_tls_key, tls_destructor))
		panic("Could not create kthread subsystem tls key");

	uhi_thread_hook_add(UHI_THREAD_HOOK_START, uinet_thread_start_hook, NULL);
}



struct uinet_thread *
uinet_thread_alloc(struct proc *p)
{
	struct uinet_thread *utd;

	if (NULL == p) {
		p = &proc0;
	}

	utd = malloc(sizeof(struct uinet_thread), M_DEVBUF, M_ZERO | M_WAITOK);
	if (NULL == utd)
		return(NULL);
	utd->td.td_proc = p;

	return (utd);
}


void
uinet_thread_free(struct uinet_thread *utd)
{
	struct thread *td = &utd->td;

	crfree(td->td_proc->p_ucred);
	mtx_destroy(&utd->lock);
	cv_destroy(&utd->cond);

#ifndef HAS_NATIVE_TLS
	free(utd, M_DEVBUF);
#endif
}



static void
notify_started(void *arg)
{
	struct uinet_thread_started_notice *n = arg;

	mtx_lock(&n->lock);
	n->utd = uhi_tls_get(kthread_tls_key);
	cv_signal(&n->cond);
	mtx_unlock(&n->lock);
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
	va_list ap;
	struct uinet_thread_started_notice notice;

	utd = uinet_thread_alloc(p);
	if (NULL == utd)
		return (ENOMEM);

	mtx_init(&notice.lock, "notice_lock", NULL, MTX_DEF);
	cv_init(&notice.cond, "notice_cv");
	notice.utd = 0;

	tsa = malloc(sizeof(struct uhi_thread_start_args), M_DEVBUF, M_WAITOK);
	tsa->start_routine = start_routine;
	tsa->start_routine_arg = arg;
	tsa->end_routine = NULL;
 	tsa->start_notify_routine = notify_started;
	tsa->start_notify_routine_arg = &notice;
	tsa->set_tls = 1;
	tsa->tls_key = kthread_tls_key;
	tsa->tls_data = utd;

	va_start(ap, str);
	vsnprintf(tsa->name, sizeof(tsa->name), str, ap);
	va_end(ap);

	error = uhi_thread_create(&host_thread, tsa, pages * PAGE_SIZE); 

 	mtx_lock(&notice.lock);
	while (!notice.utd)
		cv_wait(&notice.cond, &notice.lock);
	mtx_unlock(&notice.lock);

	mtx_destroy(&notice.lock);
	cv_destroy(&notice.cond);

	if (tdp)
		*tdp = &notice.utd->td;

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
	struct uinet_thread_started_notice notice;

	utd = uinet_thread_alloc(*p);
	if (NULL == utd)
		return (ENOMEM);

	td = &utd->td;
	if (*p == NULL) {
		*p = td->td_proc;
	}

	mtx_init(&notice.lock, "notice_lock", NULL, MTX_DEF);
	cv_init(&notice.cond, "notice_cv");
	notice.utd = 0;

	tsa = malloc(sizeof(struct uhi_thread_start_args), M_DEVBUF, M_WAITOK);
	tsa->start_routine = start_routine;
	tsa->start_routine_arg = arg;
	tsa->end_routine = NULL;
 	tsa->start_notify_routine = notify_started;
	tsa->start_notify_routine_arg = &notice;
	tsa->set_tls = 1;
	tsa->tls_key = kthread_tls_key;
	tsa->tls_data = utd;

	va_start(ap, str);
	vsnprintf(tsa->name, sizeof(tsa->name), str, ap);
	va_end(ap);

	error = uhi_thread_create(&host_thread, tsa, pages * PAGE_SIZE); 

 	mtx_lock(&notice.lock);
	while (!notice.utd)
		cv_wait(&notice.cond, &notice.lock);
	mtx_unlock(&notice.lock);

	mtx_destroy(&notice.lock);
	cv_destroy(&notice.cond);

	if (tdp)
		*tdp = &notice.utd->td;

	return (error);
}


/* This must be run from thread0 */
void
uinet_init_thread0(void)
{
	uinet_thread0 = uinet_thread_alloc(&proc0);
	uhi_tls_set(kthread_tls_key, uinet_thread0);
	uhi_thread_run_hooks(UHI_THREAD_HOOK_START);
	/*
	 * The start hook may have replaced the thread state allocated
	 * above, so update uinet_thread0.
	 */
	uinet_thread0 = uhi_tls_get(kthread_tls_key);
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

	if (ticks - td->td_last_stop_check >= td->td_stop_check_ticks) {
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

