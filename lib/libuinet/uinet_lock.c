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
 */

#include <sys/param.h>
#include <sys/systm.h>
//#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/turnstile.h>
#include <sys/vmmeter.h>
#include <sys/lock_profile.h>

#include <pthread.h>

struct mtx Giant;


static void
assert_mtx(struct lock_object *lock, int what)
{

	mtx_assert((struct mtx *)lock, what);
}

static void
lock_mtx(struct lock_object *lock, int how)
{

	mtx_lock((struct mtx *)lock);
}

static int
unlock_mtx(struct lock_object *lock)
{
	struct mtx *m;

	m = (struct mtx *)lock;
	mtx_assert(m, MA_OWNED | MA_NOTRECURSED);
	mtx_unlock(m);
	return (0);
}

/*
 * Lock classes for sleep and spin mutexes.
 */
struct lock_class lock_class_mtx_sleep = {
	.lc_name = "sleep mutex",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE,
	.lc_assert = assert_mtx,
	.lc_lock = lock_mtx,
	.lc_unlock = unlock_mtx,
#ifdef DDB
	.lc_ddb_show = db_show_mtx,
#endif
#ifdef KDTRACE_HOOKS
	.lc_owner = owner_mtx,
#endif
};

void
mtx_init(struct mtx *m, const char *name, const char *type, int opts)
{
	pthread_mutexattr_t attr;

	lock_init(&m->lock_object, &lock_class_mtx_sleep, name, type, opts);
	pthread_mutexattr_init(&attr);
	pthread_mutex_init(&m->mtx_lock, &attr);
}

void
mtx_destroy(struct mtx *m)
{

	pthread_mutex_destroy(&m->mtx_lock);
}

void
mtx_sysinit(void *arg)
{
	struct mtx_args *margs = arg;

	mtx_init(margs->ma_mtx, margs->ma_desc, NULL, margs->ma_opts);
}

void
_mtx_lock_flags(struct mtx *m, int opts, const char *file, int line)
{

	pthread_mutex_lock(&m->mtx_lock);
}

void
_mtx_unlock_flags(struct mtx *m, int opts, const char *file, int line)
{

	pthread_mutex_unlock(&m->mtx_lock);
}

int
_mtx_trylock(struct mtx *m, int opts, const char *file, int line)
{

	return (pthread_mutex_trylock(&m->mtx_lock));
}

void
_mtx_lock_spin_flags(struct mtx *m, int opts, const char *file, int line)
{

	pthread_mutex_lock(&m->mtx_lock);
}

void
_mtx_unlock_spin_flags(struct mtx *m, int opts, const char *file, int line)
{

	pthread_mutex_unlock(&m->mtx_lock);
}

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
_thread_lock_flags(struct thread *td, int opts, const char *file, int line)
{

	mtx_lock(td->td_lock);
}


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


static void
assert_rm(struct lock_object *lock, int what)
{

	panic("assert_rm called");
}

struct lock_class lock_class_rm = {
	.lc_name = "rm",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE,
	.lc_assert = assert_rm,
#if 0
#ifdef DDB
	.lc_ddb_show = db_show_rwlock,
#endif
#endif
#ifdef KDTRACE_HOOKS
	.lc_owner = owner_rm,
#endif
};

void
rm_init(struct rmlock *rm, const char *name)
{

	rw_init((struct rwlock *)rm, name);
}

void
rm_init_flags(struct rmlock *rm, const char *name, int opts)
{

	rw_init_flags((struct rwlock *)rm, name, opts);
}

void
rm_destroy(struct rmlock *rm)
{

	rw_destroy((struct rwlock *)rm);
}

void
_rm_wlock(struct rmlock *rm)
{

	_rw_wlock((struct rwlock *)rm, __FILE__, __LINE__);
}

void
_rm_wunlock(struct rmlock *rm)
{

	_rw_wunlock((struct rwlock *)rm, __FILE__, __LINE__);
}

int
_rm_rlock(struct rmlock *rm, struct rm_priotracker *tracker, int trylock)
{
	if (trylock)
		return _rw_try_rlock((struct rwlock *)rm, __FILE__, __LINE__);

	_rw_rlock((struct rwlock *)rm, __FILE__, __LINE__);
	return (1);
}

void
_rm_runlock(struct rmlock *rm,  struct rm_priotracker *tracker)
{

	_rw_runlock((struct rwlock *)rm, __FILE__, __LINE__);
}


struct lock_class lock_class_sx = {
	.lc_name = "sx",
	.lc_flags = LC_SLEEPLOCK | LC_SLEEPABLE | LC_RECURSABLE | LC_UPGRADABLE,
#ifdef DDB
	.lc_ddb_show = db_show_sx,
#endif
#ifdef KDTRACE_HOOKS
	.lc_owner = owner_sx,
#endif
};

void
sx_init_flags(struct sx *sx, const char *description, int opts)
{

	rw_init_flags((struct rwlock *)sx, description, opts);
}

void
sx_destroy(struct sx *sx)
{

	rw_destroy((struct rwlock *)sx);
}

int
_sx_xlock(struct sx *sx, int opts,
    const char *file, int line)
{
	
	_rw_wlock((struct rwlock *)sx, file, line);
	return (0);
}

int
_sx_slock(struct sx *sx, int opts, const char *file, int line)
{
	
	_rw_rlock((struct rwlock *)sx, file, line);
	return (0);
}

void
_sx_xunlock(struct sx *sx, const char *file, int line)
{
	
	_rw_wunlock((struct rwlock *)sx, file, line);
}

void
_sx_sunlock(struct sx *sx, const char *file, int line)
{
	
	_rw_runlock((struct rwlock *)sx, file, line);
}

int
_sx_try_xlock(struct sx *sx, const char *file, int line)
{

	return (_rw_try_wlock((struct rwlock *)sx, file, line));
}

void
sx_sysinit(void *arg)
{
	struct sx_args *args = arg;

	sx_init(args->sa_sx, args->sa_desc);
}

/*
 * XXX should never be used;
 */
struct lock_class lock_class_lockmgr;
struct lock_class lock_class_mtx_spin;
