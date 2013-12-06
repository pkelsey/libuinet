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
#include <uinet_sys/rmlock.h>
#include <uinet_sys/rwlock.h>
#include <uinet_sys/proc.h>


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
	int rwopts = 0;

	if (opts & RM_RECURSE) rwopts |= RW_RECURSE;

	rw_init_flags((struct rwlock *)rm, name, rwopts);
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
