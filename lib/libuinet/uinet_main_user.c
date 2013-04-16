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


/*
 * This file contains support routines for uinet_main.c that are more easily
 * implemented in a pure user-space environment.
 */


#undef _KERNEL

#include <stdio.h>
#include <string.h>
#include <unistd.h>


#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>

int
get_kernel_stack_if_params(const char *ifname,
			   struct sockaddr_in *addr,
			   struct sockaddr_in *baddr,
			   struct sockaddr_in *netmask);


/*
 * Retrieve parameters from the named interface in the OS kernel.
 */
int
get_kernel_stack_if_params(const char *ifname,
			   struct sockaddr_in *addr,
			   struct sockaddr_in *baddr,
			   struct sockaddr_in *netmask)
{

	int s;
	int error;
	struct ifreq ifr;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		return (1);
	}

	strcpy(ifr.ifr_name, ifname);

	error = ioctl(s, SIOCGIFADDR, &ifr);
	if (0 != error) {
		printf("SIOCGIFADDR failed %d\n", error);
		return (1);
	}
	memcpy(addr, &ifr.ifr_addr, sizeof(struct sockaddr_in));


	error = ioctl(s, SIOCGIFBRDADDR, &ifr);
	if (0 != error) {
		printf("SIOCGIFBRDADDR failed %d\n", error);
		return (1);
	}
	memcpy(baddr, &ifr.ifr_addr, sizeof(struct sockaddr_in));


	error = ioctl(s, SIOCGIFNETMASK, &ifr);
	if (0 != error) {
		printf("SIOCGIFNETMASK failed %d\n", error);
		return (1);
	}
	memcpy(netmask, &ifr.ifr_addr, sizeof(struct sockaddr_in));

	close(s);

	return (0);
}
