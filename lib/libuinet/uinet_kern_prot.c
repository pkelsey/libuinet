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
 * Derived in part from libplebnet's pn_glue.c and pn_compat.c.
 *
 */


#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/refcount.h>
#include <sys/proc.h>
#include <sys/ucred.h>


static MALLOC_DEFINE(M_CRED, "cred", "credentials");

int
p_cansee(struct thread *td, struct proc *p)
{

	return (0);
}

int
p_candebug(struct thread *td, struct proc *p)
{
	
	return (0);
}

/*
 * Allocate a zeroed cred structure.
 */
struct ucred *
crget(void)
{
	register struct ucred *cr;

	cr = malloc(sizeof(*cr), M_CRED, M_WAITOK | M_ZERO);
	refcount_init(&cr->cr_ref, 1);

	return (cr);
}

/*
 * Claim another reference to a ucred structure.
 */
struct ucred *
crhold(struct ucred *cr)
{

	refcount_acquire(&cr->cr_ref);
	return (cr);
}

/*
 * Free a cred structure.  Throws away space when ref count gets to 0.
 */
void
crfree(struct ucred *cr)
{

	KASSERT(cr->cr_ref > 0, ("bad ucred refcount: %d", cr->cr_ref));
	KASSERT(cr->cr_ref != 0xdeadc0de, ("dangling reference to ucred"));
	if (refcount_release(&cr->cr_ref)) {

		free(cr, M_CRED);
	}
}

/*
 * Fill in a struct xucred based on a struct ucred.
 */

void
cru2x(struct ucred *cr, struct xucred *xcr)
{
#if 0
	int ngroups;

	bzero(xcr, sizeof(*xcr));
	xcr->cr_version = XUCRED_VERSION;
	xcr->cr_uid = cr->cr_uid;

	ngroups = MIN(cr->cr_ngroups, XU_NGROUPS);
	xcr->cr_ngroups = ngroups;
	bcopy(cr->cr_groups, xcr->cr_groups,
	    ngroups * sizeof(*cr->cr_groups));
#endif
}


int
cr_cansee(struct ucred *u1, struct ucred *u2)
{

	return (0);
}

int
cr_canseesocket(struct ucred *cred, struct socket *so)
{

	return (0);
}

int
cr_canseeinpcb(struct ucred *cred, struct inpcb *inp)
{

	return (0);
}

int
securelevel_gt(struct ucred *cr, int level)
{

	return (0);
}

