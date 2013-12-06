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

#undef _KERNEL
#include <uinet_sys/param.h>
#include <uinet_sys/types.h>
#include <uinet_sys/kthread.h>
#include <uinet_sys/mman.h>
#include <uinet_sys/refcount.h>
#include <uinet_sys/stat.h>
#include <uinet_sys/time.h>
#include <uinet_sys/stdint.h>
#include <uinet_sys/uio.h>

#define _KERNEL
#include <uinet_sys/errno.h>
#include <uinet_sys/proc.h>
#include <uinet_sys/lock.h>
#include <uinet_sys/mutex.h>
#include <uinet_sys/sx.h>
#include <uinet_sys/linker.h>
#include <uinet_sys/ucred.h>
#undef _KERNEL

#include <stdlib.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdarg.h>
#include <stdio.h>


#if defined(UINET_PROFILE)
static struct itimerval prof_itimer;
#endif /* UINET_PROFILE */

__thread struct thread *pcurthread;

struct pthread_start_args 
{
	struct thread *psa_td;
	void (*psa_start_routine)(void *);
	void *psa_arg;
};


int
_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
	       void *(*start_routine)(void *), void *arg);

void uinet_init_thread0(void);
struct thread *uinet_thread_alloc(struct proc *p);


static void *
pthread_start_routine(void *arg)
{
	struct pthread_start_args *psa = arg;

#if defined(UINET_PROFILE)
	setitimer(ITIMER_PROF, &prof_itimer, NULL);
#endif /* UINET_PROFILE */

	pcurthread = psa->psa_td;
	pcurthread->td_proc = &proc0;

	/*
	 * Ensure tc_wchan is valid before thread body executes, in case the
	 * thread starts before this gets set in kthread_add.
	 */
	pcurthread->td_wchan = pthread_self();
	psa->psa_start_routine(psa->psa_arg);
	free(psa->psa_td);
	free(psa);

	return (NULL);
}


struct thread *
uinet_thread_alloc(struct proc *p)
{
	struct thread *td = NULL;
	struct mtx *lock = NULL;
	pthread_cond_t *cond = NULL;

	if (NULL == p) {
		p = &proc0;
	}

	td = malloc(sizeof(struct thread));
	if (NULL == td)
		goto error;

	lock = malloc(sizeof(struct mtx));
	if (NULL == lock)
		goto error;

	cond = malloc(sizeof(pthread_cond_t));
	if (NULL == cond)
		goto error;

	pthread_cond_init(cond, NULL);
	mtx_init(lock, "thread_lock", NULL, MTX_DEF);
	td->td_lock = lock;
	td->td_sleepqueue = (void *)cond;
	td->td_ucred = crhold(p->p_ucred);

	return (td);

error:
	if (td) free(td);
	if (lock) free(lock);
	if (cond) free(cond);

	return (NULL);
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
	pthread_t thread;
	pthread_attr_t attr;
	struct pthread_start_args *psa;
	struct thread *td;
	char name[32];
	va_list ap;

	td = uinet_thread_alloc(p);
	if (NULL == td)
		return (ENOMEM);

	if (tdp)
		*tdp = td;

	psa = malloc(sizeof(struct pthread_start_args));
	psa->psa_start_routine = start_routine;
	psa->psa_arg = arg;
	psa->psa_td = td;
	
	pthread_attr_init(&attr); 
	if (pages) {
		pthread_attr_setstacksize(&attr, pages * PAGE_SIZE);
	}
	error = _pthread_create(&thread, &attr, pthread_start_routine, psa);

	va_start(ap, str);
	vsnprintf(name, sizeof(name), str, ap);
	va_end(ap);
	pthread_set_name_np(thread, name);

	/*
	 * Ensure tc_wchan is valid before kthread_add returns, in case the
	 * thread has not started yet.
	 */
	td->td_wchan = thread;
	return (error);
}

void
kthread_exit(void)
{
	pthread_exit(NULL);
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
	pthread_t thread;
	struct thread *td;
	pthread_attr_t attr;
	struct pthread_start_args *psa;
	char name[32];
	va_list ap;

	td = uinet_thread_alloc(*p);
	if (NULL == td)
		return (ENOMEM);

	if (tdp)
		*tdp = td;

	psa = malloc(sizeof(struct pthread_start_args));
	psa->psa_start_routine = start_routine;
	psa->psa_arg = arg;
	psa->psa_td = td;
	
	pthread_attr_init(&attr); 
	if (pages) {
		pthread_attr_setstacksize(&attr, pages * PAGE_SIZE);
	}
	error = _pthread_create(&thread, &attr, pthread_start_routine, psa);

	va_start(ap, str);
	vsnprintf(name, sizeof(name), str, ap);
	va_end(ap);
	pthread_set_name_np(thread, name);

	/*
	 * Ensure tc_wchan is valid before kthread_add returns, in case the
	 * thread has not started yet.
	 */
	td->td_wchan = thread;
	return (error);
}


void
uinet_init_thread0(void)
{
	pcurthread = &thread0;
	pcurthread->td_proc = &proc0;
	pcurthread->td_wchan = pthread_self();
}


#if defined(UINET_PROFILE)
void gprof_init(void) __attribute__((constructor)); 

void gprof_init(void) {
	printf("getting prof timer\n");
	getitimer(ITIMER_PROF, &prof_itimer);
}
#endif /* UINET_PROFILE */
