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
 * Derived in part from libplebnet's pn_lock.c.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/rmlock.h>
#include <sys/proc.h>

#include "uinet_host_interface.h"

static void
assert_rm(struct lock_object *lock, int what)
{

	panic("assert_rm called");
}

struct lock_class lock_class_rm = {
	.lc_name = "rm",
	.lc_flags = LC_SLEEPLOCK | LC_RECURSABLE,
	.lc_assert = assert_rm,
#ifndef UINET
#ifdef DDB
	.lc_ddb_show = db_show_rmlock,
#endif
#endif
#ifdef KDTRACE_HOOKS
	.lc_owner = owner_rm,
#endif
};

void
rm_init(struct rmlock *rm, const char *name)
{
	rm_init_flags(rm, name, 0);
}

void
rm_init_flags(struct rmlock *rm, const char *name, int opts)
{
	int liflags;

	liflags = 0;
	if (!(opts & RM_NOWITNESS))
		liflags |= LO_WITNESS;
	if (opts & RM_RECURSE)
		liflags |= LO_RECURSABLE;
	/* XXX validate - do we need more? */
#if 0
        if (opts & RM_SLEEPABLE) {
                liflags |= RM_SLEEPABLE;
                sx_init_flags(&rm->rm_lock_sx, "rmlock_sx", SX_RECURSE);
        } else
                mtx_init(&rm->rm_lock_mtx, name, "rmlock_mtx", MTX_NOWITNESS);
#endif

	lock_init(&rm->lock_object, &lock_class_rm, name, NULL, liflags);
	if (0 != uhi_rwlock_init(&rm->rm_lock, opts & RM_RECURSE ? UHI_RW_WRECURSE : 0))
		panic("Could not initialize rmlock");
}

void
rm_destroy(struct rmlock *rm)
{

	uhi_rwlock_destroy(&rm->rm_lock);
}

void
_rm_wlock(struct rmlock *rm)
{
	_uhi_rwlock_wlock(&rm->rm_lock, rm, NULL, 0);
}

void
_rm_wunlock(struct rmlock *rm)
{

	_uhi_rwlock_wunlock(&rm->rm_lock, rm, NULL, 0);
}

int
_rm_rlock(struct rmlock *rm, struct rm_priotracker *tracker, int trylock)
{

	if (trylock)
		return _uhi_rwlock_tryrlock(&rm->rm_lock, rm, NULL, 0);

	_uhi_rwlock_rlock(&rm->rm_lock, rm, NULL, 0);
	return (1);
}


void
_rm_runlock(struct rmlock *rm,  struct rm_priotracker *tracker)
{

	_uhi_rwlock_runlock(&rm->rm_lock, rm, NULL, 0);
}

#if LOCK_DEBUG > 0
void
_rm_wlock_debug(struct rmlock *rm, const char *file, int line)
{

	WITNESS_CHECKORDER(&rm->lock_object, LOP_NEWORDER | LOP_EXCLUSIVE, file,
	    line, NULL);
	_rm_wlock(rm);
#if 0
	if (rm->lock_object.lo_flags & RM_SLEEPABLE)
		WITNESS_LOCK(&rm->rm_lock_sx.lock_object, LOP_EXCLUSIVE,
		    file, line);
	else
#endif
		WITNESS_LOCK(&rm->lock_object, LOP_EXCLUSIVE, file, line);
}

void
_rm_wunlock_debug(struct rmlock *rm, const char *file, int line)
{

#if 0
	if (rm->lock_object.lo_flags & RM_SLEEPABLE)
		WITNESS_UNLOCK(&rm->rm_lock_sx.lock_object, LOP_EXCLUSIVE,
		    file, line);
	else
#endif
		WITNESS_UNLOCK(&rm->lock_object, LOP_EXCLUSIVE, file, line);

	_rm_wunlock(rm);
}

int
_rm_rlock_debug(struct rmlock *rm, struct rm_priotracker *tracker,
    int trylock, const char *file, int line)
{
	int ret;

#if 0
	if (!trylock && (rm->lock_object.lo_flags & RM_SLEEPABLE))
		WITNESS_CHECKORDER(&rm->rm_lock_sx.lock_object, LOP_NEWORDER,
		    file, line, NULL);
#endif
	WITNESS_CHECKORDER(&rm->lock_object, LOP_NEWORDER, file, line, NULL);

	ret = (_rm_rlock(rm, tracker, trylock));
	if (ret)
		WITNESS_LOCK(&rm->lock_object, 0, file, line);

	return (ret);
}

void
_rm_runlock_debug(struct rmlock *rm,  struct rm_priotracker *tracker,
    const char *file, int line)
{

	WITNESS_UNLOCK(&rm->lock_object, 0, file, line);
	_rm_runlock(rm, tracker);
}
#endif
