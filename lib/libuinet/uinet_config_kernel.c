/*
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
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
#include <sys/sysctl.h>

#include "uinet_internal.h"

int
uinet_config_blackhole(uinet_instance_t uinst, uinet_blackhole_t action)
{
	int val;
	char *name;
	int error = 0;

	switch (action) {
	case UINET_BLACKHOLE_TCP_NONE:
		name = "net.inet.tcp.blackhole";
		val = 0;
		break;
	case UINET_BLACKHOLE_TCP_SYN_ONLY:
		name = "net.inet.tcp.blackhole";
		val = 1;
		break;
	case UINET_BLACKHOLE_TCP_ALL:
		name = "net.inet.tcp.blackhole";
		val = 2;
		break;
	case UINET_BLACKHOLE_UDP_NONE:
		name = "net.inet.udp.blackhole";
		val = 0;
		break;
	case UINET_BLACKHOLE_UDP_ALL:
		name = "net.inet.udp.blackhole";
		val = 1;
		break;
	default:
		return (EINVAL);
	}

	CURVNET_SET(uinst->ui_vnet);
	error = kernel_sysctlbyname(curthread, name, NULL, NULL,
				    &val, sizeof(int), NULL, 0);
	CURVNET_RESTORE();
	return (error);
}

