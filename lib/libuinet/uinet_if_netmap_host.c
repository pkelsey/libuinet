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

#undef _KERNEL
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/netmap.h>

#include <ifaddrs.h>

#include "uinet_if_netmap_host.h"


void
if_netmap_api_check(unsigned int ifnamesiz)
{
	/*
	 * Check that the value of IFNAMSIZ passed in by the caller matches
	 * the value seen in this file.  When the caller is in a file
	 * compiled against the UINET kernel headers, the defition of
	 * IFNAMSIZ in the caller's environment comes from those kernel
	 * headers, whereas the defition of IFNAMSIZ in this file comes from
	 * the host OS headers.  If the values are different, then the
	 * netmap data structure layout, such as struct nmreq, will not
	 * correspond between the two environments.
	 */
	assert(ifnamesiz == IFNAMSIZ);
}


int
if_netmap_get_ifaddr(const char *ifname, uint8_t *ethaddr)
{
	struct ifaddrs *ifa, *ifa_current;
	int error;

	if (-1 == getifaddrs(&ifa)) {
		printf("getifaddrs failed\n");
		return (-1);
	}

	ifa_current = ifa;
	error = -1;
	while (NULL != ifa_current) {
		if ((0 == strcmp(ifa_current->ifa_name, ifname)) &&
		    (AF_LINK == ifa_current->ifa_addr->sa_family) &&
		    (NULL != ifa_current->ifa_data)) {
			    struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa_current->ifa_addr;

			    memcpy(ethaddr, &sdl->sdl_data[sdl->sdl_nlen], ETHER_ADDR_LEN);
			    error = 0;
			    break;
		}
		ifa_current = ifa_current->ifa_next;
	}

	freeifaddrs(ifa);

	return (error);
}


int
if_netmap_register_if(int nmfd, struct nmreq *req, const char *ifname, unsigned int qno)
{
	req->nr_version = NETMAP_API;
	req->nr_ringid = NETMAP_NO_TX_POLL | NETMAP_HW_RING | qno;
	strlcpy(req->nr_name, ifname, sizeof(req->nr_name));

	return (ioctl(nmfd, NIOCREGIF, req));
}


int
if_netmap_rxsync(int nmfd)
{
	return (ioctl(nmfd, NIOCRXSYNC, NULL));
}


int
if_netmap_txsync(int nmfd)
{
	return (ioctl(nmfd, NIOCTXSYNC, NULL));
}


int
if_netmap_set_offload(int nmfd, const char *ifname, int on)
{
	struct ifreq ifr;
	int rv;

	memset(&ifr, 0, sizeof ifr);
	strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);
	rv = ioctl(nmfd, SIOCGIFCAP, &ifr);
	if (rv == -1) {
		printf("get interface capabilities failed");
		return (-1);
	}

	ifr.ifr_reqcap = ifr.ifr_curcap;

	if (on)
		ifr.ifr_reqcap |= IFCAP_HWCSUM | IFCAP_TSO | IFCAP_TOE | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWTSO;
	else
		ifr.ifr_reqcap &= ~(IFCAP_HWCSUM | IFCAP_TSO | IFCAP_TOE | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWTSO);

	rv = ioctl(nmfd, SIOCSIFCAP, &ifr);
	if (rv == -1) {
		printf("set interface capabilities failed");
		return (-1);
	}

	return (0);
}


int
if_netmap_set_promisc(int nmfd, const char *ifname, int on)
{
	struct ifreq ifr;
	uint32_t flags;
	int rv;

	memset(&ifr, 0, sizeof ifr);
	strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);
	rv = ioctl(nmfd, SIOCGIFFLAGS, &ifr);
	if (rv == -1) {
		printf("get interface flags failed");
		return (-1);
	}

	flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);

	if (on)
		flags |= IFF_PPROMISC;
	else
		flags &= ~IFF_PPROMISC;

	ifr.ifr_flags = flags & 0xffff;
	ifr.ifr_flagshigh = (flags >> 16) & 0xffff;

	rv = ioctl(nmfd, SIOCSIFFLAGS, &ifr);
	if (rv == -1) {
		printf("set interface flags failed");
		return (-1);
	}

	return (0);
}

