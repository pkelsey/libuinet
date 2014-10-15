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
#include <sys/sx.h>
#include <sys/proc.h>

#include "uinet_host_interface.h"

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
	int flags;

	MPASS((opts & ~(SX_QUIET | SX_RECURSE | SX_NOWITNESS | SX_DUPOK |
	    SX_NOPROFILE | SX_NOADAPTIVE)) == 0);

	flags = LO_SLEEPABLE | LO_UPGRADABLE;
	if (opts & SX_DUPOK)
		flags |= LO_DUPOK;
	if (opts & SX_NOPROFILE)
		flags |= LO_NOPROFILE;
	if (!(opts & SX_NOWITNESS))
		flags |= LO_WITNESS;
	if (opts & SX_RECURSE)
		flags |= LO_RECURSABLE;
	if (opts & SX_QUIET)
		flags |= LO_QUIET;

	flags |= opts & SX_NOADAPTIVE;
	lock_init(&sx->lock_object, &lock_class_sx, description, NULL, flags);
	if (0 != uhi_rwlock_init(&sx->sx_lock, opts & SX_RECURSE ? UHI_RW_WRECURSE : 0))
		panic("Could not initialize sxlock");
}

void
sx_destroy(struct sx *sx)
{
	uhi_rwlock_destroy(&sx->sx_lock);
}

int
_sx_xlock(struct sx *sx, int opts,
    const char *file, int line)
{

	WITNESS_CHECKORDER(&sx->lock_object, LOP_NEWORDER | LOP_EXCLUSIVE, file,
	    line, NULL);
	_uhi_rwlock_wlock(&sx->sx_lock, sx, file, line);
	WITNESS_LOCK(&sx->lock_object, LOP_EXCLUSIVE, file, line);
	return (0);
}

int
_sx_slock(struct sx *sx, int opts, const char *file, int line)
{

	WITNESS_CHECKORDER(&sx->lock_object, LOP_NEWORDER, file, line, NULL);
	_uhi_rwlock_rlock(&sx->sx_lock, sx, file, line);
	/* XXX always succeeds, so */
	WITNESS_LOCK(&sx->lock_object, 0, file, line);
	return (0);
}

void
_sx_xunlock(struct sx *sx, const char *file, int line)
{

	WITNESS_UNLOCK(&sx->lock_object, LOP_EXCLUSIVE, file, line);
	_uhi_rwlock_wunlock(&sx->sx_lock, sx, file, line);
}

void
_sx_sunlock(struct sx *sx, const char *file, int line)
{

	WITNESS_UNLOCK(&sx->lock_object, 0, file, line);
	_uhi_rwlock_runlock(&sx->sx_lock, sx, file, line);
}

int
_sx_try_slock(struct sx *sx, const char *file, int line)
{
	int ret;

	ret = (_uhi_rwlock_trywlock(&sx->sx_lock, sx, file, line));

	if (ret) {
		WITNESS_LOCK(&sx->lock_object, LOP_TRYLOCK,
		    file, line);
	}

	return (ret);
}

int
_sx_try_xlock(struct sx *sx, const char *file, int line)
{
	int ret;

	ret = (_uhi_rwlock_trywlock(&sx->sx_lock, sx, file, line));

	if (ret) {
		WITNESS_LOCK(&sx->lock_object, LOP_EXCLUSIVE | LOP_TRYLOCK,
		    file, line);
	}

	return (ret);
}

void
sx_sysinit(void *arg)
{
	struct sx_args *args = arg;

	sx_init(args->sa_sx, args->sa_desc);
}
