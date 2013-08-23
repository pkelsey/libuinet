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
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>

#include <net/if.h>

#include "uinet_api.h"



int
uinet_interface_up(const char *canonical_name, unsigned int qno)
{
	struct socket *cfg_so;
	struct thread *td = curthread;
	struct ifreq ifr;
	int error;
	char ifname[IF_NAMESIZE];

	error = socreate(PF_INET, &cfg_so, SOCK_DGRAM, 0, td->td_ucred, td);
	if (0 != error) {
		printf("Socket creation failed (%d)\n", error);
		return (1);
	}

	snprintf(ifname, sizeof(ifname), "%s:%u", canonical_name, qno);
	strcpy(ifr.ifr_name, ifname);

	
	/* set interface to UP */

	error = ifioctl(cfg_so, SIOCGIFFLAGS, (caddr_t)&ifr, td);
	if (0 != error) {
		printf("SSIOCGIFFLAGS failed %d\n", error);
		return (1);
	}

	ifr.ifr_flags |= IFF_UP;
	error = ifioctl(cfg_so, SIOCSIFFLAGS, (caddr_t)&ifr, td);
	if (0 != error) {
		printf("SSIOCSIFFLAGS failed %d\n", error);
		return (1);
	}

	soclose(cfg_so);

	return (0);
	
}
