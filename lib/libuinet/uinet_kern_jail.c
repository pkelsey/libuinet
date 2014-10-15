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
 * Derived in part from libplebnet's pn_glue.c.
 *
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/lock.h>
#include <sys/sx.h>


/* Dummy that should never be used, provided for linkage to
 * uinet_init_main.c.
 */
struct	prison prison0;

/* allprison, allprison_racct and lastprid are protected by allprison_lock. */
struct	sx allprison_lock;
SX_SYSINIT(allprison_lock, &allprison_lock, "allprison");
struct	prisonlist allprison = TAILQ_HEAD_INITIALIZER(allprison);

/*
 * Find a prison that is a descendant of mypr.  Returns a locked prison or NULL.
 */
struct prison *
prison_find_child(struct prison *mypr, int prid)
{

	return (NULL);
}

void
prison_free(struct prison *pr)
{
}

void
prison_hold_locked(struct prison *pr)
{
}

int
prison_if(struct ucred *cred, struct sockaddr *sa)
{

	return (0);
}

int
prison_check_af(struct ucred *cred, int af)
{

	return (0);
}

#ifdef INET
int
prison_get_ip4(struct ucred *cred, struct in_addr *ia)
{

	return (0);
}

int 
prison_saddrsel_ip4(struct ucred *cred, struct in_addr *ia)
{

	/* not jailed */
	return (1);
}

int
prison_equal_ip4(struct prison *pr1, struct prison *pr2)
{

	return (1);
}

int
prison_local_ip4(struct ucred *cred, struct in_addr *ia)
{

	return (0);
}

int
prison_remote_ip4(struct ucred *cred, struct in_addr *ia)
{

	return (0);
}

int
prison_check_ip4(struct ucred *cred, struct in_addr *ia)
{

	return (0);
}
#endif

#ifdef INET6
int
prison_get_ip6(struct ucred *cred, struct in6_addr *ia)
{

	return (0);
}

int 
prison_saddrsel_ip6(struct ucred *cred, struct in6_addr *ia)
{

	/* not jailed */
	return (1);

}

int
prison_equal_ip6(struct prison *pr1, struct prison *pr2)
{

	return (1);
}

int
prison_local_ip6(struct ucred *cred, struct in6_addr *ia, int other)
{

	return (0);
}

int
prison_remote_ip6(struct ucred *cred, struct in6_addr *ia)
{

	return (0);
}

int
prison_check_ip6(struct ucred *cred, struct in6_addr *ia)
{

	return (0);
}
#endif

/*
 * See if a prison has the specific flag set.
 */
int
prison_flag(struct ucred *cred, unsigned flag)
{

	/* This is an atomic read, so no locking is necessary. */
	return (flag & PR_HOST);
}

int
jailed(struct ucred *cred)
{

	return (0);
}

/*
 * Return 1 if the passed credential is in a jail and that jail does not
 * have its own virtual network stack, otherwise 0.
 */
int
jailed_without_vnet(struct ucred *cred)
{

	return (0);
}

#ifdef VIMAGE
/*
 * Determine whether the prison represented by cred owns
 * its vnet rather than having it inherited.
 *
 * Returns 1 in case the prison owns the vnet, 0 otherwise.
 */
int
prison_owns_vnet(struct ucred *cred)
{
	return (0);
}
#endif
