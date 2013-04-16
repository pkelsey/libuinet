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
 * Dervied in part from libplebnet's pn_lock.c.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/rwlock.h>
#include <sys/proc.h>

#include <pthread.h>

static void
assert_rw(struct lock_object *lock, int what)
{

	rw_assert((struct rwlock *)lock, what);
}

struct lock_class lock_class_rw = {
	.lc_name = "rw",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE | LC_UPGRADABLE,
	.lc_assert = assert_rw,
#ifdef DDB
	.lc_ddb_show = db_show_rwlock,
#endif

#ifdef KDTRACE_HOOKS
	.lc_owner = owner_rw,
#endif
};

void
rw_sysinit(void *arg)
{
	struct rw_args *args = arg;

	rw_init(args->ra_rw, args->ra_desc);
}

#ifdef notyet
void
rw_init_flags(struct rwlock *rw, const char *name, int opts)
{
	pthread_rwlockattr_t attr;
	int flags;

	MPASS((opts & ~(RW_DUPOK | RW_NOPROFILE | RW_NOWITNESS | RW_QUIET |
	    RW_RECURSE)) == 0);
	ASSERT_ATOMIC_LOAD_PTR(rw->rw_lock,
	    ("%s: rw_lock not aligned for %s: %p", __func__, name,
	    &rw->rw_lock));

	flags = LO_UPGRADABLE;
	if (opts & RW_DUPOK)
		flags |= LO_DUPOK;
	if (opts & RW_NOPROFILE)
		flags |= LO_NOPROFILE;
	if (!(opts & RW_NOWITNESS))
		flags |= LO_WITNESS;
	if (opts & RW_RECURSE)
		flags |= LO_RECURSABLE;
	if (opts & RW_QUIET)
		flags |= LO_QUIET;

	lock_init(&rw->lock_object, &lock_class_rw, name, NULL, flags);
	pthread_rwlockattr_init(&attr);
	pthread_rwlock_init(&rw->rw_lock, &attr);
}


void
rw_destroy(struct rwlock *rw)
{
	
	pthread_rwlock_destroy(&rw->rw_lock);
}

void
_rw_wlock(struct rwlock *rw, const char *file, int line)
{

	pthread_rwlock_wrlock(&rw->rw_lock);
}

int
_rw_try_wlock(struct rwlock *rw, const char *file, int line)
{

	return (!pthread_rwlock_trywrlock(&rw->rw_lock));
}

void
_rw_wunlock(struct rwlock *rw, const char *file, int line)
{
	
	pthread_rwlock_unlock(&rw->rw_lock);
}

void
_rw_rlock(struct rwlock *rw, const char *file, int line)
{
	
	pthread_rwlock_rdlock(&rw->rw_lock);
}

int
_rw_try_rlock(struct rwlock *rw, const char *file, int line)
{
	
	return (!pthread_rwlock_tryrdlock(&rw->rw_lock));
}

void
_rw_runlock(struct rwlock *rw, const char *file, int line)
{
	
	pthread_rwlock_unlock(&rw->rw_lock);
}

int
_rw_try_upgrade(struct rwlock *rw, const char *file, int line)
{
	
	return (0);
}

void
_rw_downgrade(struct rwlock *rw, const char *file, int line)
{

	pthread_rwlock_unlock(&rw->rw_lock);
	/* XXX */
	pthread_rwlock_rdlock(&rw->rw_lock);
}

#endif

void
rw_init_flags(struct rwlock *rw, const char *name, int opts)
{
	pthread_mutexattr_t attr;
	int flags;

	MPASS((opts & ~(RW_DUPOK | RW_NOPROFILE | RW_NOWITNESS | RW_QUIET |
	    RW_RECURSE)) == 0);
	ASSERT_ATOMIC_LOAD_PTR(rw->rw_lock,
	    ("%s: rw_lock not aligned for %s: %p", __func__, name,
	    &rw->rw_lock));

	flags = LO_UPGRADABLE;
	if (opts & RW_DUPOK)
		flags |= LO_DUPOK;
	if (opts & RW_NOPROFILE)
		flags |= LO_NOPROFILE;
	if (!(opts & RW_NOWITNESS))
		flags |= LO_WITNESS;
	if (opts & RW_RECURSE)
		flags |= LO_RECURSABLE;
	if (opts & RW_QUIET)
		flags |= LO_QUIET;

	lock_init(&rw->lock_object, &lock_class_rw, name, NULL, flags);
	pthread_mutexattr_init(&attr);
	pthread_mutex_init(&rw->rw_lock, &attr);
}


void
rw_destroy(struct rwlock *rw)
{
	
	pthread_mutex_destroy(&rw->rw_lock);
}

void
_rw_wlock(struct rwlock *rw, const char *file, int line)
{

	pthread_mutex_lock(&rw->rw_lock);
}

int
_rw_try_wlock(struct rwlock *rw, const char *file, int line)
{

	return (!pthread_mutex_trylock(&rw->rw_lock));
}

void
_rw_wunlock(struct rwlock *rw, const char *file, int line)
{
	
	pthread_mutex_unlock(&rw->rw_lock);
}

void
_rw_rlock(struct rwlock *rw, const char *file, int line)
{
	
	pthread_mutex_lock(&rw->rw_lock);
}

int
_rw_try_rlock(struct rwlock *rw, const char *file, int line)
{
	
	return (!pthread_mutex_trylock(&rw->rw_lock));
}

void
_rw_runlock(struct rwlock *rw, const char *file, int line)
{
	
	pthread_mutex_unlock(&rw->rw_lock);
}

int
_rw_try_upgrade(struct rwlock *rw, const char *file, int line)
{
	
	return (0);
}

void
_rw_downgrade(struct rwlock *rw, const char *file, int line)
{

}

