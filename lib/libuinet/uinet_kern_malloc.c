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
 *
 * Derived in part from libplebnet's pn_glue.c.
 *
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/types.h>

/*
 * This include will catch the libuinet sys/malloc.h, which redefines the
 * names malloc, free, realloc, and reallocf to be the uinet_ variants, then
 * includes the kernel sys/malloc.h.  This then provides us with the
 * prototypes for the uinet_ variants below, as well as the other
 * sys/malloc.h #defines and declarations to use.
 */
#include <sys/malloc.h>


#include "uinet_host_interface.h"


MALLOC_DEFINE(M_DEVBUF, "devbuf", "device driver memory");
MALLOC_DEFINE(M_TEMP, "temp", "misc temporary data buffers");

MALLOC_DEFINE(M_IP6OPT, "ip6opt", "IPv6 options");
MALLOC_DEFINE(M_IP6NDP, "ip6ndp", "IPv6 Neighbor Discovery");


void
malloc_init(void *data)
{
	/* Nothing to do here */
}


void
malloc_uninit(void *data)
{
	/* Nothing to do here */
}


/*
 * libuinet/include/sys/malloc.h redirects all malloc() and free() calls to
 * these routines for users of sys/malloc.h.
 */
void *
malloc(unsigned long size, struct malloc_type *type, int flags)
{
	void *alloc;

	do {
		alloc = uhi_malloc(size);
		if (alloc || !(flags & M_WAITOK))
			break;

		pause("malloc", hz/100);
	} while (alloc == NULL);

	if ((flags & M_ZERO) && alloc != NULL)
		bzero(alloc, size);
	return (alloc);
}


void
free(void *addr, struct malloc_type *type)
{

	uhi_free(addr);
}


void *
realloc(void *addr, unsigned long size, struct malloc_type *type,
	int flags)
{
	return (uhi_realloc(addr, size));
}


void *
reallocf(void *addr, unsigned long size, struct malloc_type *type,
	 int flags)
{
	void *mem;

	if ((mem = uhi_realloc(addr, size)) == NULL)
		uhi_free(addr);

	return (mem);
}
