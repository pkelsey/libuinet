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


#include <sys/ctype.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>

#include <net/if.h>

#include "uinet_if.h"



static const struct uinet_if_type_info *uinet_if_types[UINET_IFTYPE_COUNT];


int
uinet_if_attach(struct uinet_if *uif, struct ifnet *ifp, void *sc)
{
	uif->ifindex = ifp->if_index;
	uif->ifdata = sc;
	uif->ifp = ifp;

	uinet_iftouif(ifp) = uif;

	return (0);
}


void
uinet_if_register_type(const void *arg)
{
	const struct uinet_if_type_info *ti;

	ti = (const struct uinet_if_type_info *)arg;
	uinet_if_types[ti->type] = ti;
}


const struct uinet_if_type_info *
uinet_if_get_type_info(uinet_iftype_t type)
{
	return ((type < UINET_IFTYPE_COUNT) ? uinet_if_types[type] : NULL);
}
