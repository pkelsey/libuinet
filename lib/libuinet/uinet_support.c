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


/*
 * These are user-space implementations of copy routines that are typically
 * implemented in the kernel in a machine-specific assembler file (usually
 * support.S).
 *
 */

#include <uinet_sys/types.h>

/*
 * Reproduced from sys/libsystm.h, which is not included directly in order to
 * avoid massive definition conflict between it and std*.h below.
 */
int	copystr(const void * __restrict kfaddr, void * __restrict kdaddr,
	    size_t len, size_t * __restrict lencopied)
	    __nonnull(1) __nonnull(2);
int	copyinstr(const void * __restrict udaddr, void * __restrict kaddr,
	    size_t len, size_t * __restrict lencopied)
	    __nonnull(1) __nonnull(2);
int	copyin(const void * __restrict udaddr, void * __restrict kaddr,
	    size_t len) __nonnull(1) __nonnull(2);
int	copyout(const void * __restrict kaddr, void * __restrict udaddr,
	    size_t len) __nonnull(1) __nonnull(2);

int	subyte(void *base, int byte);
int	fubyte(void *base);


#include <string.h>


int
copystr(const void *kfaddr, void *kdaddr, size_t len, size_t *done)
{
	size_t bytes;
	
	bytes = strlcpy(kdaddr, kfaddr, len);
	if (done != NULL)
		*done = bytes;

	return (0);
}


int
copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done)
{	
	size_t bytes;
	
	bytes = strlcpy(kaddr, uaddr, len);
	if (done != NULL)
		*done = bytes;

	return (0);
}


int
copyin(const void *uaddr, void *kaddr, size_t len)
{

	memcpy(kaddr, uaddr, len);

	return (0);
}


int
copyout(const void *kaddr, void *uaddr, size_t len)
{
	
	memcpy(uaddr, kaddr, len);

	return (0);
}


int
subyte(void *base, int byte)
{

	*(char *)base = (uint8_t)byte;
	return (0);
}


int
fubyte(void *base)
{

	return (*(uint8_t *)base);
}
