/*
 * Copyright (c) 2014 Patrick Kelsey. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <sys/param.h>
#include <vm/uma.h>

#include "uinet_api.h"

uinet_pool_t
uinet_pool_create(char *name, int size, uinet_pool_ctor ctor, uinet_pool_dtor dtor,
		  uinet_pool_init init, uinet_pool_fini fini, int align, uint16_t flags)
{
	/* fixup zero or non-mask alignments */
	if (!align || (align & (align + 1)))
		align = UINET_POOL_ALIGN_PTR;

	return (uinet_pool_t)uma_zcreate(name, size, (uma_ctor)ctor, (uma_dtor)dtor,
					 (uma_init)init, (uma_fini) fini, align, flags);
}


void *
uinet_pool_alloc_arg(uinet_pool_t pool, void *arg, int flags)
{
	return uma_zalloc_arg((uma_zone_t)pool, arg, flags);
}


void
uinet_pool_free_arg(uinet_pool_t pool, void *item, void *arg)
{
	uma_zfree_arg((uma_zone_t)pool, item, arg);
}


void
uinet_pool_destroy(uinet_pool_t pool)
{
	uma_zdestroy((uma_zone_t)pool);
}


int
uinet_pool_set_max(uinet_pool_t pool, int nitems)
{
	return uma_zone_set_max((uma_zone_t)pool, nitems);
}


int
uinet_pool_get_max(uinet_pool_t pool)
{
	return uma_zone_get_max((uma_zone_t)pool);
}


int
uinet_pool_get_cur(uinet_pool_t pool)
{
	return uma_zone_get_cur((uma_zone_t)pool);
}
