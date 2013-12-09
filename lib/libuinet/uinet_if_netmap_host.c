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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sockio.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

#include <ifaddrs.h>

#include "uinet_if_netmap_host.h"


struct if_netmap_host_context {
	int fd;
	const char *ifname;
	struct nmreq req;
	void *mem;
	struct netmap_ring *hw_rx_ring;
	struct netmap_ring *hw_tx_ring;
};


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


struct if_netmap_host_context *
if_netmap_register_if(int nmfd, const char *ifname, unsigned int qno)
{
	struct if_netmap_host_context *ctx;

	ctx = calloc(1, sizeof(struct if_netmap_host_context));
	if (NULL == ctx)
		return (NULL);
	
	ctx->fd = nmfd;
	ctx->ifname = ifname;

	/*
	 * Disable TCP and checksum offload, which can impact throughput
	 * and also cause packets to be dropped or modified gratuitously.
	 *
	 * Also disable VLAN offload/filtering - we want to talk straight to
	 * the wire.
	 *
	 */

	if (0 != if_netmap_set_offload(ctx, 0)) {
		goto fail;
	}

	if (0 != if_netmap_set_promisc(ctx, 1)) {
		goto fail;
	}

	ctx->req.nr_version = NETMAP_API;
	ctx->req.nr_ringid = NETMAP_NO_TX_POLL | NETMAP_HW_RING | qno;
	strlcpy(ctx->req.nr_name, ifname, sizeof(ctx->req.nr_name));

	if (-1 == ioctl(ctx->fd, NIOCREGIF, &ctx->req)) {
		goto fail;
	} 

	ctx->mem = mmap(NULL, ctx->req.nr_memsize, PROT_READ | PROT_WRITE, MAP_NOCORE | MAP_SHARED, ctx->fd, 0);
	if (MAP_FAILED == ctx->mem) {
		goto fail;
	}

	ctx->hw_rx_ring = NETMAP_RXRING(NETMAP_IF(ctx->mem, ctx->req.nr_offset), qno);
	ctx->hw_tx_ring = NETMAP_TXRING(NETMAP_IF(ctx->mem, ctx->req.nr_offset), qno);

	/* NIOCREGIF will reset the hardware rings, but the reserved count
	 * might still be non-zero from a previous user's activities
	 */
	ctx->hw_rx_ring->reserved = 0;

	return (ctx);

fail:
	free(ctx);
	return(NULL);
}


void
if_netmap_deregister_if(struct if_netmap_host_context *ctx)
{
	if_netmap_set_promisc(ctx, 0);

	munmap(ctx->mem, ctx->req.nr_memsize);
	
	free(ctx);
}


int
if_netmap_rxsync(struct if_netmap_host_context *ctx, const uint32_t *avail, const uint32_t *cur, const uint32_t *reserved)
{
	struct netmap_ring *rxr = ctx->hw_rx_ring;

	if (avail) rxr->avail = *avail;
	if (cur) rxr->cur = *cur;
	if (reserved) rxr->reserved = *reserved;

	return (ioctl(ctx->fd, NIOCRXSYNC, NULL));
}


uint32_t
if_netmap_rxavail(struct if_netmap_host_context *ctx)
{
	return (ctx->hw_rx_ring->avail);
}


uint32_t
if_netmap_rxcur(struct if_netmap_host_context *ctx)
{
	return (ctx->hw_rx_ring->cur);
}


uint32_t
if_netmap_rxreserved(struct if_netmap_host_context *ctx)
{
	return (ctx->hw_rx_ring->reserved);
}


uint32_t
if_netmap_rxslots(struct if_netmap_host_context *ctx)
{
	return (ctx->req.nr_rx_slots);
}


uint32_t
if_netmap_rxbufsize(struct if_netmap_host_context *ctx)
{
	return (ctx->hw_rx_ring->nr_buf_size);
}


void *
if_netmap_rxslot(struct if_netmap_host_context *ctx, uint32_t *slotno, uint32_t *len, uint32_t *index)
{
	struct netmap_ring *rxr = ctx->hw_rx_ring;
	uint32_t cur = *slotno;

	*slotno = NETMAP_RING_NEXT(rxr, cur); 
	*index = rxr->slot[cur].buf_idx;
	return (NETMAP_BUF(rxr, rxr->slot[cur].buf_idx));
}


void
if_netmap_rxsetslot(struct if_netmap_host_context *ctx, uint32_t *slotno, uint32_t index)
{
	struct netmap_ring *rxr = ctx->hw_rx_ring;
	uint32_t cur = *slotno;

	rxr->slot[cur].buf_idx = index;
	rxr->slot[cur].flags |= NS_BUF_CHANGED;
	*slotno = NETMAP_RING_NEXT(rxr, cur);
}


int
if_netmap_txsync(struct if_netmap_host_context *ctx, const uint32_t *avail, const uint32_t *cur)
{
	struct netmap_ring *txr = ctx->hw_tx_ring;

	if (avail) txr->avail = *avail;
	if (cur) txr->cur = *cur;

	return (ioctl(ctx->fd, NIOCTXSYNC, NULL));
}


uint32_t
if_netmap_txavail(struct if_netmap_host_context *ctx)
{
	return (ctx->hw_tx_ring->avail);
}


uint32_t
if_netmap_txcur(struct if_netmap_host_context *ctx)
{
	return (ctx->hw_tx_ring->cur);
}


uint32_t
if_netmap_txslots(struct if_netmap_host_context *ctx)
{
	return (ctx->req.nr_tx_slots);
}


void *
if_netmap_txslot(struct if_netmap_host_context *ctx, uint32_t *slotno, uint32_t len)
{
	struct netmap_ring *txr = ctx->hw_tx_ring;
	uint32_t cur = *slotno;
		
	assert(len <= txr->nr_buf_size);

	*slotno = NETMAP_RING_NEXT(txr, cur); 
	return (NETMAP_BUF(txr, txr->slot[cur].buf_idx));
}


int
if_netmap_set_offload(struct if_netmap_host_context *ctx, int on)
{
	struct ifreq ifr;
	int rv;

	memset(&ifr, 0, sizeof ifr);
	strlcpy(ifr.ifr_name, ctx->ifname, sizeof ifr.ifr_name);
	rv = ioctl(ctx->fd, SIOCGIFCAP, &ifr);
	if (rv == -1) {
		printf("get interface capabilities failed");
		return (-1);
	}

	ifr.ifr_reqcap = ifr.ifr_curcap;

	if (on)
		ifr.ifr_reqcap |= IFCAP_HWCSUM | IFCAP_TSO | IFCAP_TOE | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWTSO;
	else
		ifr.ifr_reqcap &= ~(IFCAP_HWCSUM | IFCAP_TSO | IFCAP_TOE | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWTSO);

	rv = ioctl(ctx->fd, SIOCSIFCAP, &ifr);
	if (rv == -1) {
		printf("set interface capabilities failed");
		return (-1);
	}

	return (0);
}


int
if_netmap_set_promisc(struct if_netmap_host_context *ctx, int on)
{
	struct ifreq ifr;
	uint32_t flags;
	int rv;

	memset(&ifr, 0, sizeof ifr);
	strlcpy(ifr.ifr_name, ctx->ifname, sizeof ifr.ifr_name);
	rv = ioctl(ctx->fd, SIOCGIFFLAGS, &ifr);
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

	rv = ioctl(ctx->fd, SIOCSIFFLAGS, &ifr);
	if (rv == -1) {
		printf("set interface flags failed");
		return (-1);
	}

	return (0);
}

