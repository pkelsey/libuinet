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

#include <uinet_sys/param.h>
#include <uinet_sys/systm.h>
#include <uinet_sys/conf.h>
#include <uinet_sys/rwlock.h>
#include <uinet_sys/proc.h>

#include "uinet_host_interface.h"

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


void
rw_init_flags(struct rwlock *rw, const char *name, int opts)
{
	int flags;

	MPASS((opts & ~(RW_DUPOK | RW_NOPROFILE | RW_NOWITNESS | RW_QUIET |
	    RW_RECURSE)) == 0);

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
	if (0 != uhi_rwlock_init(&rw->rw_lock, opts & RW_RECURSE ? UHI_RW_WRECURSE : 0))
		panic("Could not initialize rwlock");
}


void
rw_destroy(struct rwlock *rw)
{
	
	uhi_rwlock_destroy(&rw->rw_lock);
}

void
_rw_wlock(struct rwlock *rw, const char *file, int line)
{

	uhi_rwlock_wlock(&rw->rw_lock);
}

int
_rw_try_wlock(struct rwlock *rw, const char *file, int line)
{

	return (uhi_rwlock_trywlock(&rw->rw_lock));
}

void
_rw_wunlock(struct rwlock *rw, const char *file, int line)
{
	
	uhi_rwlock_wunlock(&rw->rw_lock);
}

void
_rw_rlock(struct rwlock *rw, const char *file, int line)
{
	
	uhi_rwlock_rlock(&rw->rw_lock);
}

int
_rw_try_rlock(struct rwlock *rw, const char *file, int line)
{
	
	return (uhi_rwlock_tryrlock(&rw->rw_lock));
}

void
_rw_runlock(struct rwlock *rw, const char *file, int line)
{
	
	uhi_rwlock_runlock(&rw->rw_lock);
}

int
_rw_try_upgrade(struct rwlock *rw, const char *file, int line)
{
	return (uhi_rwlock_tryupgrade(&rw->rw_lock));
}

void
_rw_downgrade(struct rwlock *rw, const char *file, int line)
{
	uhi_rwlock_downgrade(&rw->rw_lock);
}

