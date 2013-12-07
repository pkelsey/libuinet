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
#include <sys/conf.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/proc.h>


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
	int rwopts = 0;
	
	if (opts & SX_RECURSE) rwopts |= RW_RECURSE;

	rw_init_flags((struct rwlock *)sx, description, rwopts);
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
