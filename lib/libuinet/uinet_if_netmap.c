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
#include <errno.h>
#define _KERNEL

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/sched.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_tap.h>
#include <net/if_dl.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

#include <machine/atomic.h>

#include "uinet_config_internal.h"

#undef _KERNEL
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <ctype.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <poll.h>

/*
 *  IF_NETMAP_RXRING_ZCOPY_FRAC_NUM and IF_NETMAP_RXRING_ZCOPY_FRAC_DEN are
 *  the numerator and denominator of the fraction of rxring buffers that
 *  will be available for zero-copy receive at any given time.  During
 *  receive processing, if that many buffers have been handed to the stack
 *  in a zero-copy fashion, all further received buffers will be passed to
 *  the stack using copies until some of the zero-copy buffers are
 *  returned.
 *
 *  One way to look at this is that the complement of this fraction
 *  represents the fraction of buffers that will be available for packet
 *  reception at the end of each pass through the receive processing loop,
 *  and thus represents the capacity to absorb traffic between receive
 *  processing passes.
 *
 *  So, for example, if IF_NETMAP_RXRING_ZCOPY_FRAC_NUM = 1 and
 *  IF_NETMAP_RXRING_ZCOPY_FRAC_DEN = 4, up to 1/4 of the buffers in each
 *  rxring will be oustanding to the stack via zero-copy at any given time,
 *  and there will always be at least 3/4 of the buffers in the ring
 *  available for new packet reception at the end of each receive loop pass.
 *
 *  Setting IF_NETMAP_RXRING_ZCOPY_FRAC_NUM to zero will disable zero copy
 *  receive.
 */
#define IF_NETMAP_RXRING_ZCOPY_FRAC_NUM 1
#define IF_NETMAP_RXRING_ZCOPY_FRAC_DEN 2


/* stdio */
extern void	perror(const char *string);

/* stdlib */
extern int	 atoi(const char *);

/* unistd */
extern int	close(int d);


struct if_netmap_bufinfo {
	u_int refcnt;
	uint32_t nm_index;  /* netmap buffer index */
	uint32_t bi_index;  /* bufinfo index */
};

struct if_netmap_bufinfo_pool {
	struct mtx tail_lock;
	struct if_netmap_bufinfo *pool;
	uint32_t *free_list;
	uint32_t max;
	uint32_t avail;
	volatile u_int returnable;
	uint32_t head;
	uint32_t tail;
	uint32_t trail;
};

struct if_netmap_softc {
	struct ifnet *ifp;
	const struct uinet_config_if *cfg;
	uint8_t addr[ETHER_ADDR_LEN];
	int fd;
	struct nmreq req;
	void *mem;
	uint16_t queue;

	uint32_t hw_rx_rsvd_begin;
	struct netmap_ring *hw_rx_ring;
	struct netmap_ring *hw_tx_ring;

	struct if_netmap_bufinfo_pool rx_bufinfo;

	struct thread *tx_thread;
	struct thread *rx_thread;
	struct mtx tx_lock;
};


static int if_netmap_setup_interface(struct if_netmap_softc *sc);
static int if_netmap_set_offload(struct if_netmap_softc *sc, bool on);
static int if_netmap_set_promisc(struct if_netmap_softc *sc, bool on);



static int
if_netmap_bufinfo_pool_init(struct if_netmap_bufinfo_pool *p, uint32_t max)
{
	uint32_t i;

	p->max = max;

	if (p->max > 0) {
		p->pool = malloc(sizeof(struct if_netmap_bufinfo) * p->max, M_DEVBUF, M_WAITOK);
		if (NULL == p->pool) {
			p->free_list = NULL;
			return (-1);
		}
		p->free_list = malloc(sizeof(uint32_t) * p->max, M_DEVBUF, M_WAITOK);
		if (NULL == p->free_list) {
			return (-1);
		}
	} else {
		p->pool = NULL;
		p->free_list = NULL;
	}
	p->avail = p->max;
	p->returnable = 0;
	p->head = 0;
	p->tail = 0;
	p->trail = 0;

	for (i = 0; i < p->max; i++) {
		p->pool[i].bi_index = i;
		p->free_list[i] = i;
	}

	mtx_init(&p->tail_lock, "bitllk", NULL, MTX_DEF);

	return (0);
}


static int
if_netmap_bufinfo_pool_destroy(struct if_netmap_bufinfo_pool *p)
{
	mtx_destroy(&p->tail_lock);

	if (p->free_list) {
		free(p->free_list, M_DEVBUF);
	}

	if (p->pool) {
		free(p->pool, M_DEVBUF);
	}

	return (0);
}


/* Only called from the receive thread */
static struct if_netmap_bufinfo *
if_netmap_bufinfo_alloc(struct if_netmap_bufinfo_pool *p)
{
	struct if_netmap_bufinfo *bi;

	if (p->avail) {
		p->avail--;
		bi = &p->pool[p->free_list[p->head]];

		p->head++;
		if (p->head == p->max) {
			p->head = 0;
		}

		return (bi);
	}

	return (NULL);
}


/*
 * Undo an allocation of a bufinfo that was just allocated.  Only called
 * from the receive thread.
 */
static void
if_netmap_bufinfo_unalloc(struct if_netmap_bufinfo_pool *p)
{
	p->avail++;
	if (p->head > 0) {
		p->head--;
	} else {
		p->head = p->max - 1;
	}
}

/* This may be called from arbitrary threads */
static void
if_netmap_bufinfo_free(struct if_netmap_bufinfo_pool *p, struct if_netmap_bufinfo *bi)
{
	mtx_lock(&p->tail_lock);
	p->free_list[p->tail] = bi->bi_index;

	/*
	 * p->returnable is the only state shared with
	 * if_netmap_sweep_trail, and using atomic add here saves us from
	 * locking there.
	 */
	atomic_add_int(&p->returnable, 1);

	p->tail++;
	if (p->tail == p->max) {
		p->tail = 0;
	}
	mtx_unlock(&p->tail_lock);
}


static int
if_netmap_attach(struct uinet_config_if *cfg)
{
	struct if_netmap_softc *sc;
	struct ifaddrs *ifa, *ifa_current;
	int fd, error, rv;
	uint32_t pool_size;


	printf("ifname is %s\n", cfg->spec);

	sc = malloc(sizeof(struct if_netmap_softc), M_DEVBUF, M_WAITOK);
	if (NULL == sc) {
		perror("if_netmap_softc allocation failed");
		return (ENOMEM);
	}
	memset(sc, 0, sizeof(struct if_netmap_softc));

	sc->cfg = cfg;

	fd = open("/dev/netmap", O_RDWR);
	if (fd < 0) {
		perror("/dev/netmap open failed");
		return (ENXIO);
	}

	sc->fd = fd;


	/*
	 * Disable TCP and checksum offload, which can impact throughput
	 * and also cause packets to be dropped or modified gratuitously.
	 *
	 * Also disable VLAN offload/filtering - we want to talk straight to
	 * the wire.
	 *
	 */

	error = if_netmap_set_offload(sc, false);
	if (error != 0) {
		printf("set offload failed\n");
		goto fail;
	}

	error = if_netmap_set_promisc(sc, true);
	if (error != 0) {
		printf("set promisc failed\n");
		goto fail;
	}

	sc->req.nr_version = NETMAP_API;
	sc->req.nr_ringid = NETMAP_NO_TX_POLL | NETMAP_HW_RING | sc->cfg->queue;
	strlcpy(sc->req.nr_name, sc->cfg->name, sizeof(sc->req.nr_name));
	rv = ioctl(sc->fd, NIOCREGIF, &sc->req);
	if (rv == -1) {
		printf("NIOCREGIF failed\n");
		if_netmap_set_promisc(sc, false);
		goto fail;
	}

	sc->mem = mmap(NULL, sc->req.nr_memsize, PROT_READ | PROT_WRITE, MAP_NOCORE | MAP_SHARED, sc->fd, 0);
	if (sc->mem == MAP_FAILED) {
		printf("mmap failed\n");
		if_netmap_set_promisc(sc, false);
		goto fail;
	}

	/*
	 * Limiting the size of the rxring zero-copy context pool to the
	 * given fraction of the rxring size limits the amount of rxring
	 * buffers that can be outstanding to the stack via zero-copy at any
	 * given time as a failure to allocate a zero-copy context in the
	 * receive loop causes the buffer to be copied to the stack.
	 */
	pool_size = (sc->req.nr_rx_slots * IF_NETMAP_RXRING_ZCOPY_FRAC_NUM) / IF_NETMAP_RXRING_ZCOPY_FRAC_DEN;
	error = if_netmap_bufinfo_pool_init(&sc->rx_bufinfo, pool_size);
	if (error != 0) {
		printf("bufinfo pool init failed\n");
		if_netmap_set_promisc(sc, false);
		goto fail;
	}

        sc->hw_rx_ring = NETMAP_RXRING(NETMAP_IF(sc->mem, sc->req.nr_offset), sc->cfg->queue);
	sc->hw_tx_ring = NETMAP_TXRING(NETMAP_IF(sc->mem, sc->req.nr_offset), sc->cfg->queue);

	/* NIOCREGIF will reset the hardware rings, but the reserved count
	 * might still be non-zero from a previous user's activities
	 */
	sc->hw_rx_ring->reserved = 0;

	if (-1 == getifaddrs(&ifa)) {
		printf("getifaddrs failed\n");
		if_netmap_set_promisc(sc, false);
		goto fail;
	}

	ifa_current = ifa;
	error = -1;
	while (NULL != ifa_current) {
		if ((0 == strcmp(ifa_current->ifa_name, sc->cfg->name)) &&
		    (AF_LINK == ifa_current->ifa_addr->sa_family) &&
		    (NULL != ifa_current->ifa_data)) {
			    struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa_current->ifa_addr;

			    memcpy(sc->addr, &sdl->sdl_data[sdl->sdl_nlen], ETHER_ADDR_LEN);
			    error = 0;
			    break;
		}
		ifa_current = ifa_current->ifa_next;
	}

	freeifaddrs(ifa);

	if (0 != error) {
		printf("failed to find interface address\n");
		if_netmap_set_promisc(sc, false);
		goto fail;
	}

	if (0 == if_netmap_setup_interface(sc)) {
		return (0);
	}

	if_netmap_set_promisc(sc, false);

fail:
	if_netmap_bufinfo_pool_destroy(&sc->rx_bufinfo);

	close(sc->fd);
	free(sc, M_DEVBUF);
	return (ENXIO);
}


static void
if_netmap_init(void *arg)
{
	struct if_netmap_softc *sc = arg;
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}


static void
if_netmap_start(struct ifnet *ifp)
{
	struct if_netmap_softc *sc = ifp->if_softc;

	mtx_lock(&sc->tx_lock);
	ifp->if_drv_flags |= IFF_DRV_OACTIVE;
	wakeup(&ifp->if_drv_flags);
	mtx_unlock(&sc->tx_lock);
}


static void
if_netmap_send(void *arg)
{
	struct mbuf *m;
	struct if_netmap_softc *sc = (struct if_netmap_softc *)arg;
	struct ifnet *ifp = sc->ifp;
	struct netmap_ring *txr;
	struct pollfd pfd;
	uint32_t avail;
	uint32_t cur;
	u_int pktlen;
	int rv;


	while (1) {
		mtx_lock(&sc->tx_lock);
		while (IFQ_DRV_IS_EMPTY(&ifp->if_snd)) {
			ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
			mtx_sleep(&ifp->if_drv_flags, &sc->tx_lock, 0, "wtxlk", 0);
		}
		mtx_unlock(&sc->tx_lock);

		txr = sc->hw_tx_ring;
	
		rv = ioctl(sc->fd, NIOCTXSYNC);
		if (rv == -1) {
			perror("could not sync tx descriptors before transmit");
		}
	
		while (!IFQ_DRV_IS_EMPTY(&ifp->if_snd)) {
			avail = txr->avail;

			while (0 == avail) {
				memset(&pfd, 0, sizeof(pfd));

				pfd.fd = sc->fd;
				pfd.events = POLLOUT;
				
				rv = poll(&pfd, 1, -1);
				if (rv == -1 && errno != EINTR)
					perror("error from poll for transmit");
					
				avail = txr->avail;
			}

			cur = txr->cur;

			while (avail) {
				IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
				avail--;

				pktlen = m_length(m, NULL);
				KASSERT(pktlen <= txr->nr_buf_size, ("if_netmap_send: packet too large"));

				txr->slot[cur].len = pktlen;
				m_copydata(m, 0, pktlen, NETMAP_BUF(txr, txr->slot[cur].buf_idx));
				m_freem(m);

				cur = NETMAP_RING_NEXT(txr, cur);

				if (IFQ_DRV_IS_EMPTY(&ifp->if_snd)) {
					break;
				}
			}

			txr->avail = avail;
			txr->cur = cur;
			rv = ioctl(sc->fd, NIOCTXSYNC);
			if (rv == -1) {
				perror("could not sync tx descriptors after transmit");
			}
		}
	}
	
}


static void
if_netmap_stop(struct if_netmap_softc *sc)
{
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING|IFF_DRV_OACTIVE);
}


static int
if_netmap_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int error = 0;
	struct if_netmap_softc *sc = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			if_netmap_init(sc);
		else if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			if_netmap_stop(sc);
		break;
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}


static void
if_netmap_free(void *arg1, void *arg2)
{
	struct if_netmap_softc *sc;
	struct if_netmap_bufinfo *bi;

	sc = (struct if_netmap_softc *)arg1;
	bi = (struct if_netmap_bufinfo *)arg2;

	if_netmap_bufinfo_free(&sc->rx_bufinfo, bi);
}

/* Only called from the receive thread */
static uint32_t
if_netmap_sweep_trail(struct if_netmap_softc *sc)
{
	struct netmap_ring *rxr;
	struct if_netmap_bufinfo_pool *p;
	uint32_t i;
	uint32_t returned;
	unsigned int n;

	rxr = sc->hw_rx_ring;
	i = sc->hw_rx_rsvd_begin;
	
	p = &sc->rx_bufinfo;

	returned = p->returnable;
	for (n = 0; n < returned; n++) {
		rxr->slot[i].buf_idx = p->pool[p->free_list[p->trail]].nm_index;
		rxr->slot[i].flags |= NS_BUF_CHANGED;

		i = NETMAP_RING_NEXT(rxr, i);

		p->trail++;
		if (p->trail == p->max) {
			p->trail = 0;
		}
	}
	sc->hw_rx_rsvd_begin = i;

	atomic_subtract_int(&p->returnable, returned);
	p->avail += returned;

	return (returned);
}


static void
if_netmap_receive(void *arg)
{
	struct if_netmap_softc *sc;
	struct netmap_ring *rxr;
	struct pollfd pfd;
	struct mbuf *m;
	struct if_netmap_bufinfo *bi;
	uint32_t cur;
	uint32_t avail;
	uint32_t returned;
	uint32_t new_reserved;
	unsigned int n;
	int rv;


	/* Zero-copy receive
	 *
	 * A packet header mbuf is allocated for each received netmap
	 * buffer, and the netmap buffer is attached to this mbuf as
	 * external storage, along with a free routine and piece of context
	 * that enables the free routine to move the netmap buffer on its
	 * way back to the receive ring.  The per-buffer context objects
	 * (struct if_netmap_bufinfo) are managed by this driver.
	 *
	 * When the mbuf layer calls the free routine for an mbuf-attached
	 * netmap buffer, its associated context object is added to a list
	 * that is part of the pool of those objects.  On each pass through
	 * the receive loop below, all of the context objects that have been
	 * returned to the list since the last pass are processed, and their
	 * associated netmap buffers are returned to the receive ring.
	 *
	 * With this approach, a given netmap buffer may be available for
	 * netmap's use on the ring, may be newly available for our
	 * consumption on the ring, may have been passed to the stack for
	 * processing and not yet returned, or may have been returned to us
	 * from the stack but not yet returned to the netmap ring.
	 */

	sc = (struct if_netmap_softc *)arg;
	rxr = sc->hw_rx_ring;

	rv = ioctl(sc->fd, NIOCRXSYNC);
	if (rv == -1)
		perror("could not sync rx descriptors before receive loop");

	sc->hw_rx_rsvd_begin = rxr->cur;

	for (;;) {
		while (0 == (avail = rxr->avail)) {
			memset(&pfd, 0, sizeof pfd);

			pfd.fd = sc->fd;
			pfd.events = POLLIN;

			rv = poll(&pfd, 1, -1);
			if (rv == -1 && errno != EINTR)
				perror("error from poll for receive");
		}

		if (avail > sc->req.nr_rx_slots) {
			printf("bogus rxr->avail %u  cur=%u reserved=%u\n", rxr->avail, rxr->cur, rxr->reserved);
			return;
		}

		cur = rxr->cur;
		new_reserved = 0;
		for (n = 0; n < avail; n++) {
			bi = if_netmap_bufinfo_alloc(&sc->rx_bufinfo);
			if (NULL == bi) {
				/* copy receive */

				/* could streamline this a little since we
				 * know the data is going to fit in a
				 * cluster
				 */
				m = m_devget(NETMAP_BUF(rxr, rxr->slot[cur].buf_idx),
					     rxr->slot[cur].len, 0, sc->ifp, NULL);

				if (NULL == m) {
					/* XXX dropped. should count this */
					printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>NO MBUFS (1)\n");
				}

				/* Recover this buffer at the far end of the
				 * reserved trail from prior zero-copy
				 * activity.
				 */
				rxr->slot[sc->hw_rx_rsvd_begin].buf_idx = rxr->slot[cur].buf_idx;
				rxr->slot[sc->hw_rx_rsvd_begin].flags |= NS_BUF_CHANGED;
				sc->hw_rx_rsvd_begin = NETMAP_RING_NEXT(rxr, sc->hw_rx_rsvd_begin);
			} else {
				/* zero-copy receive */

				m = m_gethdr(M_DONTWAIT, MT_DATA);
				if (NULL == m) {
					if_netmap_bufinfo_unalloc(&sc->rx_bufinfo);
					printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>NO MBUFS (2)\n");
					/* XXX dropped. should count this */

					rxr->slot[sc->hw_rx_rsvd_begin].buf_idx = rxr->slot[cur].buf_idx;
					rxr->slot[sc->hw_rx_rsvd_begin].flags |= NS_BUF_CHANGED;
					sc->hw_rx_rsvd_begin = NETMAP_RING_NEXT(rxr, sc->hw_rx_rsvd_begin);
				} else {

					bi->nm_index = rxr->slot[cur].buf_idx;
					
					m->m_pkthdr.len = m->m_len = rxr->slot[cur].len;
					m->m_pkthdr.rcvif = sc->ifp;
					m->m_ext.ref_cnt = &bi->refcnt;
					m_extadd(m, NETMAP_BUF(rxr, rxr->slot[cur].buf_idx),
						 rxr->nr_buf_size, if_netmap_free, sc, bi, 0, EXT_EXTREF);

					new_reserved++;
				}

			}

			cur = NETMAP_RING_NEXT(rxr, cur);

			if (m) {
				sc->ifp->if_input(sc->ifp, m);
			}
		}

		if (n > rxr->avail) {
			printf("n %u > avail %u\n", n, rxr->avail);
			return;
		}
		rxr->avail -= n;
		rxr->cur = cur;
		rxr->reserved += new_reserved;

		if (avail > sc->req.nr_rx_slots) {
			printf("bogus rxr->avail(2) %u\n", avail);
			return;
		}

		/* Return any netmap buffers freed by the stack to the ring */
		returned = if_netmap_sweep_trail(sc);
		if (returned > rxr->reserved) {
			printf("returned %u > reserved %u\n", returned, rxr->reserved);
			return;
		}
		rxr->reserved -= returned;

		rv = ioctl(sc->fd, NIOCRXSYNC);
		if (rv == -1)
			perror("could not sync rx descriptors after receive");

	}
}


static int
if_netmap_setup_interface(struct if_netmap_softc *sc)
{
	struct ifnet *ifp;
	char basename[IF_NAMESIZE];

	ifp = sc->ifp = if_alloc(IFT_ETHER);

	ifp->if_init =  if_netmap_init;
	ifp->if_softc = sc;

	snprintf(basename, IF_NAMESIZE, "%s%u:", sc->cfg->basename, sc->cfg->unit);
	if_initname(ifp, basename, sc->cfg->queue);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = if_netmap_ioctl;
	ifp->if_start = if_netmap_start;

	/* XXX what values? */
	IFQ_SET_MAXLEN(&ifp->if_snd, sc->req.nr_tx_slots);
	ifp->if_snd.ifq_drv_maxlen = sc->req.nr_tx_slots;

	IFQ_SET_READY(&ifp->if_snd);

	ifp->if_fib = sc->cfg->cdom;

	ether_ifattach(ifp, sc->addr);
	ifp->if_capabilities = ifp->if_capenable = 0;


	mtx_init(&sc->tx_lock, "txlk", NULL, MTX_DEF);

	if (kthread_add(if_netmap_send, sc, NULL, &sc->tx_thread, 0, 0, "nm_tx: %s", ifp->if_xname)) {
		printf("Could not start transmit thread for %s\n", sc->cfg->spec);
		ether_ifdetach(ifp);
		if_free(ifp);
		return (1);
	}


	if (kthread_add(if_netmap_receive, sc, NULL, &sc->rx_thread, 0, 0, "nm_rx: %s", ifp->if_xname)) {
		printf("Could not start receive thread for %s\n", sc->cfg->spec);
		ether_ifdetach(ifp);
		if_free(ifp);
		return (1);
	}

	if (sc->cfg->cpu >= 0) {
		sched_bind(sc->tx_thread, sc->cfg->cpu);
		sched_bind(sc->rx_thread, sc->cfg->cpu);
	}

	return (0);
}


static int
if_netmap_detach(struct uinet_config_if *cfg)
{
	return (0);
}


static int
if_netmap_set_offload(struct if_netmap_softc *sc, bool on)
{
	struct ifreq ifr;
	int rv;

	memset(&ifr, 0, sizeof ifr);
	strlcpy(ifr.ifr_name, sc->cfg->name, sizeof ifr.ifr_name);
	rv = ioctl(sc->fd, SIOCGIFCAP, &ifr);
	if (rv == -1) {
		perror("get interface capabilities failed");
		return (-1);
	}

	ifr.ifr_reqcap = ifr.ifr_curcap;

	if (on)
		ifr.ifr_reqcap |= IFCAP_HWCSUM | IFCAP_TSO | IFCAP_TOE | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWTSO;
	else
		ifr.ifr_reqcap &= ~(IFCAP_HWCSUM | IFCAP_TSO | IFCAP_TOE | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWTSO);

	rv = ioctl(sc->fd, SIOCSIFCAP, &ifr);
	if (rv == -1) {
		perror("set interface capabilities failed");
		return (-1);
	}

	return (0);
}


static int
if_netmap_set_promisc(struct if_netmap_softc *sc, bool on)
{
	struct ifreq ifr;
	uint32_t flags;
	int rv;

	memset(&ifr, 0, sizeof ifr);
	strlcpy(ifr.ifr_name, sc->cfg->name, sizeof ifr.ifr_name);
	rv = ioctl(sc->fd, SIOCGIFFLAGS, &ifr);
	if (rv == -1) {
		perror("get interface flags failed");
		return (-1);
	}

	flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);

	if (on)
		flags |= IFF_PPROMISC;
	else
		flags &= ~IFF_PPROMISC;

	ifr.ifr_flags = flags & 0xffff;
	ifr.ifr_flagshigh = (flags >> 16) & 0xffff;

	rv = ioctl(sc->fd, SIOCSIFFLAGS, &ifr);
	if (rv == -1) {
		perror("set interface flags failed");
		return (-1);
	}

	return (0);
}


static int
if_netmap_modevent(module_t mod, int type, void *data)
{
	struct uinet_config_if *cfg = NULL;

	switch (type) {
	case MOD_LOAD:
		while (NULL != (cfg = uinet_config_if_next(cfg))) {
			if_netmap_attach(cfg);
		}
		break;

	case MOD_UNLOAD:
		while (NULL != (cfg = uinet_config_if_next(cfg))) {
			if_netmap_detach(cfg);
		}
		break;

	default:
		return (EOPNOTSUPP);
	}
	return (0);
}


static moduledata_t if_netmap_mod = {
	"if_netmap",
	if_netmap_modevent,
	0
};

DECLARE_MODULE(if_netmap, if_netmap_mod, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY);
