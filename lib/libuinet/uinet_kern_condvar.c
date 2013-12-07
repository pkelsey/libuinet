/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/condvar.h>

#include "uinet_host_interface.h"


/*
 * Initialize a condition variable.  Must be called before use.
 */
void
cv_init(struct cv *cvp, const char *desc)
{
	cvp->cv_description = desc;
	if (0 != uhi_cond_init(&cvp->cv_cond))
		panic("Could not initialize condition variable");
}

/*
 * Destroy a condition variable.  The condition variable must be re-initialized
 * in order to be re-used.
 */
void
cv_destroy(struct cv *cvp)
{

	uhi_cond_destroy(&cvp->cv_cond);
}

/*
 * Wait on a condition variable.  The current thread is placed on the condition
 * variable's wait queue and suspended.  A cv_signal or cv_broadcast on the same
 * condition variable will resume the thread.  The mutex is released before
 * sleeping and will be held on return.  It is recommended that the mutex be
 * held when cv_signal or cv_broadcast are called.
 */
void
_cv_wait(struct cv *cvp, struct lock_object *lock)
{
	struct mtx *m = (struct mtx *)lock;

	/*
	 * We only support sleep mutexes since that's what the underlying
	 * pthread_cond_wait works with.
	 */
	KASSERT(LOCK_CLASS(lock) == lock_class_mtx_sleep, ("non-sleep mutex used with condition variable"));

	uhi_cond_wait(&cvp->cv_cond, &m->mtx_lock);
}

/*
 * Wait on a condition variable, allowing interruption by signals.  Return 0 if
 * the thread was resumed with cv_signal or cv_broadcast, EINTR or ERESTART if
 * a signal was caught.  If ERESTART is returned the system call should be
 * restarted if possible.
 */
int
_cv_wait_sig(struct cv *cvp, struct lock_object *lock)
{
	struct mtx *m = (struct mtx *)lock;

	/*
	 * We only support sleep mutexes since that's what the underlying
	 * pthread_cond_wait works with.
	 */
	KASSERT(LOCK_CLASS(lock) == lock_class_mtx_sleep, ("non-sleep mutex used with condition variable"));

	uhi_cond_wait(&cvp->cv_cond, &m->mtx_lock);

	return (0);
}

/*
 * Wait on a condition variable for at most timo/hz seconds.  Returns 0 if the
 * process was resumed by cv_signal or cv_broadcast, EWOULDBLOCK if the timeout
 * expires.
 */
int
_cv_timedwait(struct cv *cvp, struct lock_object *lock, int timo)
{
	uint64_t nsecs = ((uint64_t)timo * (1000UL*1000UL*1000UL)) / hz;
	struct mtx *m = (struct mtx *)lock;

	/*
	 * We only support sleep mutexes since that's what the underlying
	 * pthread_cond_timedwait works with.
	 */
	KASSERT(LOCK_CLASS(lock) == lock_class_mtx_sleep, ("non-sleep mutex used with condition variable"));

	return (uhi_cond_timedwait(&cvp->cv_cond, &m->mtx_lock, nsecs) ? EWOULDBLOCK : 0);
}

/*
 * Wait on a condition variable for at most timo/hz seconds, allowing
 * interruption by signals.  Returns 0 if the thread was resumed by cv_signal
 * or cv_broadcast, EWOULDBLOCK if the timeout expires, and EINTR or ERESTART if
 * a signal was caught.
 */
int
_cv_timedwait_sig(struct cv *cvp, struct lock_object *lock, int timo)
{
	return (_cv_timedwait(cvp, lock, timo));
}

/*
 * Signal a condition variable, wakes up one waiting thread.  Will also wakeup
 * the swapper if the process is not in memory, so that it can bring the
 * sleeping process in.  Note that this may also result in additional threads
 * being made runnable.  Should be called with the same mutex as was passed to
 * cv_wait held.
 */
void
cv_signal(struct cv *cvp)
{
	uhi_cond_signal(&cvp->cv_cond);
}

/*
 * Broadcast a signal to a condition variable.  Wakes up all waiting threads.
 * Should be called with the same mutex as was passed to cv_wait held.
 */
void
cv_broadcastpri(struct cv *cvp, int pri)
{
	uhi_cond_broadcast(&cvp->cv_cond);
}
