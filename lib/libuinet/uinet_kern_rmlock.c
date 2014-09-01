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
	uhi_rwlock_wlock(&rm->rm_lock);
}

void
_rm_wunlock(struct rmlock *rm)
{
	uhi_rwlock_wunlock(&rm->rm_lock);
}

int
_rm_rlock(struct rmlock *rm, struct rm_priotracker *tracker, int trylock)
{
	if (trylock)
		return uhi_rwlock_tryrlock(&rm->rm_lock);

	uhi_rwlock_rlock(&rm->rm_lock);
	return (1);
}


void
_rm_runlock(struct rmlock *rm,  struct rm_priotracker *tracker)
{
	uhi_rwlock_runlock(&rm->rm_lock);
}
