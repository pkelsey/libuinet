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
 * Derived in part from libplebnet's pn_kern_synch.c.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>

#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/signalvar.h>
#include <sys/sleepqueue.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#ifdef KTRACE
#include <sys/uio.h>
#include <sys/ktrace.h>
#endif


#include "uinet_host_interface.h"


int	hogticks;
static int pause_wchan;

typedef struct sleep_entry {
	LIST_ENTRY(sleep_entry) list_entry;
	void 		*chan;
	const char 	*wmesg;
	struct cv	cond;
	int		waiters;
} *sleep_entry_t;

static void synch_setup(void *dummy);
SYSINIT(synch_setup, SI_SUB_INTR, SI_ORDER_FIRST, synch_setup,
    NULL);

static struct se_head *se_active;
static u_long se_hashmask;
static struct mtx synch_lock;
#define SE_HASH(chan)	(((uintptr_t)chan) & se_hashmask)
LIST_HEAD(se_head, sleep_entry);

static void
synch_setup(void *arg)
{
	mtx_init(&synch_lock, "synch_lock", NULL, MTX_DEF);

	se_active = hashinit(64, M_TEMP, &se_hashmask);
}

static sleep_entry_t
se_alloc(void *chan, const char *wmesg)
{
	sleep_entry_t se;
	struct se_head *hash_list;

	se = malloc(sizeof(*se), M_DEVBUF, 0);
	se->chan = chan;
	se->wmesg = wmesg;
	se->waiters = 1;
	cv_init(&se->cond, "sleep entry cv");

	/* insert in hash table */
	hash_list = &se_active[SE_HASH(chan)];
	LIST_INSERT_HEAD(hash_list, se, list_entry);
	
	return (se);
}

static sleep_entry_t
se_lookup(void *chan)
{
	struct se_head *hash_list;
	sleep_entry_t se;

	hash_list = &se_active[SE_HASH(chan)];
	LIST_FOREACH(se, hash_list, list_entry) 
		if (se->chan == chan)
			return (se);

	return (NULL);
}

static void
se_free(sleep_entry_t se)
{

	if (--se->waiters == 0) {
		LIST_REMOVE(se, list_entry);
		cv_destroy(&se->cond);
		free(se, M_DEVBUF);
	}
}

/*
 * General sleep call.  Suspends the current thread until a wakeup is
 * performed on the specified identifier.  The thread will then be made
 * runnable with the specified priority.  Sleeps at most timo/hz seconds
 * (0 means no timeout).  If pri includes PCATCH flag, signals are checked
 * before and after sleeping, else signals are not checked.  Returns 0 if
 * awakened, EWOULDBLOCK if the timeout expires.  If PCATCH is set and a
 * signal needs to be delivered, ERESTART is returned if the current system
 * call should be restarted if possible, and EINTR is returned if the system
 * call should be interrupted by the signal (return EINTR).
 *
 * The lock argument is unlocked before the caller is suspended, and
 * re-locked before _sleep() returns.  If priority includes the PDROP
 * flag the lock is not re-locked before returning.
 */
int
_sleep(void *ident, struct lock_object *lock, int priority,
    const char *wmesg, int timo)
{
	sleep_entry_t se = NULL;
	int rv = 0;
	struct mtx *m = (struct mtx *)lock;

	if (lock) {
		mtx_lock(&synch_lock);
		if ((se = se_lookup(ident)) != NULL)
			se->waiters++;
		else
			se = se_alloc(ident, wmesg);
		mtx_unlock(&synch_lock);
	}

	if (timo) {
		if (lock) {
			rv = cv_timedwait(&se->cond, m, timo);
		} else {
			uint64_t nsecs = ((uint64_t)timo * (1000UL*1000UL*1000UL)) / hz;
			uhi_nanosleep(nsecs);
			rv = EWOULDBLOCK;
		}

	} else if (lock) {
		cv_wait(&se->cond, m);
	}

	if (lock) {
		mtx_lock(&synch_lock);
		se_free(se);
		mtx_unlock(&synch_lock);
	}

	return (rv);
}

int
msleep_spin(void *ident, struct mtx *mtx, const char *wmesg, int timo)
{
	sleep_entry_t se;
	int rv = 0;

	mtx_lock(&synch_lock);
	if ((se = se_lookup(ident)) != NULL)
		se->waiters++;
	else
		se = se_alloc(ident, wmesg);
	mtx_unlock(&synch_lock);

	if (timo)
		rv = cv_timedwait(&se->cond, mtx, timo);
	else
		cv_wait(&se->cond, mtx);

	mtx_lock(&synch_lock);
	se_free(se);
	mtx_unlock(&synch_lock);

	return (rv);
}

/*
 * pause() delays the calling thread by the given number of system ticks.
 * The "timo" argument must be greater than or equal to zero. A "timo" value
 * of zero is equivalent to a "timo" value of one.
 */
int
pause(const char *wmesg, int timo)
{
	KASSERT(timo >= 0, ("pause: timo must be >= 0"));

	/* silently convert invalid timeouts */
	if (timo < 1)
		timo = 1;

	return (tsleep(&pause_wchan, 0, wmesg, timo));
}

void
wakeup(void *chan)
{
	sleep_entry_t se;

	mtx_lock(&synch_lock);
	if ((se = se_lookup(chan)) != NULL)
		cv_broadcast(&se->cond);
	mtx_unlock(&synch_lock);
}


void
wakeup_one(void *chan)
{
	sleep_entry_t se;

	mtx_lock(&synch_lock);
	if ((se = se_lookup(chan)) != NULL)
		cv_signal(&se->cond);
	mtx_unlock(&synch_lock);
}

void
kern_yield(int prio)
{
	uhi_thread_yield();
}
