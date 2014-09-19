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
#include <sys/dirent.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/sched.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_tap.h>
#include <net/if_dl.h>

#include <machine/atomic.h>

#include "uinet_internal.h"
#include "uinet_host_interface.h"
#include "uinet_if_pcap.h"
#include "uinet_if_pcap_host.h"


struct if_pcap_softc {
	struct ifnet *ifp;
	const struct uinet_if *uif;
	uint8_t addr[ETHER_ADDR_LEN];
	int isfile;
	char host_ifname[MAXNAMLEN];

	struct if_pcap_host_context *pcap_host_ctx;

	struct thread *tx_thread;
	struct thread *rx_thread;
	struct mtx tx_lock;
};


static int if_pcap_setup_interface(struct if_pcap_softc *sc);
static void if_pcap_receive_handler(void *ctx, const uint8_t *buf, unsigned int size);


static unsigned int interface_count;



static int
if_pcap_process_configstr(struct if_pcap_softc *sc)
{
	char *configstr = sc->uif->configstr;
	int error = 0;
	char *p;


	if (0 == strncmp(configstr, "file://", 7)) {
		sc->isfile = 1;

		p = &configstr[7];
		if ('\0' == *p) {
			error = EINVAL;
			goto out;
		}
	} else {
		sc->isfile = 0;
		p = configstr;
	}

	if (strlen(p) > (sizeof(sc->host_ifname) - 1)) {
		error = ENAMETOOLONG;
		goto out;
	}

	strcpy(sc->host_ifname, p);

out:
	return (error);
}


int
if_pcap_attach(struct uinet_if *uif)
{
	struct if_pcap_softc *sc = NULL;
	int error = 0;
	
	if (NULL == uif->configstr) {
		error = EINVAL;
		goto fail;
	}

	printf("configstr is %s\n", uif->configstr);

	snprintf(uif->name, sizeof(uif->name), "pcap%u", interface_count);
	interface_count++;

	sc = malloc(sizeof(struct if_pcap_softc), M_DEVBUF, M_WAITOK);
	if (NULL == sc) {
		printf("if_pcapap_softc allocation failed\n");
		error = ENOMEM;
		goto fail;
	}
	memset(sc, 0, sizeof(struct if_pcap_softc));

	sc->uif = uif;

	error = if_pcap_process_configstr(sc);
	if (0 != error) {
		goto fail;
	}

	sc->pcap_host_ctx = if_pcap_create_handle(sc->host_ifname, sc->isfile, if_pcap_receive_handler, sc);
	if (NULL == sc->pcap_host_ctx) {
		printf("Failed to create pcap handle for %s\n", sc->host_ifname);
		error = ENXIO;
		goto fail;
	}

	if (!sc->isfile) {
		if (0 != uhi_get_ifaddr(sc->host_ifname, sc->addr)) {
			printf("failed to find interface address\n");
			error = ENXIO;
			goto fail;
		}
	}

	if (0 != if_pcap_setup_interface(sc)) {
		error = ENXIO;
		goto fail;
	}

	uif->ifindex = sc->ifp->if_index;
	uif->ifdata = sc;
	uif->ifp = sc->ifp;

	return (0);

fail:
	if (sc) {
		if (sc->pcap_host_ctx)
			if_pcap_destroy_handle(sc->pcap_host_ctx);

		free(sc, M_DEVBUF);
	}

	return (error);
}


static void
if_pcap_init(void *arg)
{
	struct if_pcap_softc *sc = arg;
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}


static void
if_pcap_start(struct ifnet *ifp)
{
	struct if_pcap_softc *sc = ifp->if_softc;

	mtx_lock(&sc->tx_lock);
	ifp->if_drv_flags |= IFF_DRV_OACTIVE;
	wakeup(&ifp->if_drv_flags);
	mtx_unlock(&sc->tx_lock);
}


static void
if_pcap_send(void *arg)
{
	struct mbuf *m;
	struct if_pcap_softc *sc = (struct if_pcap_softc *)arg;
	struct ifnet *ifp = sc->ifp;
	uint8_t copybuf[2048];
	uint8_t *pkt;
	unsigned int pktlen;

	if (sc->uif->cpu >= 0)
		sched_bind(sc->tx_thread, sc->uif->cpu);

	while (1) {
		mtx_lock(&sc->tx_lock);
		while (IFQ_DRV_IS_EMPTY(&ifp->if_snd)) {
			ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
			mtx_sleep(&ifp->if_drv_flags, &sc->tx_lock, 0, "wtxlk", 0);
		}
		mtx_unlock(&sc->tx_lock);
	
		while (!IFQ_DRV_IS_EMPTY(&ifp->if_snd)) {
			IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
			pktlen = m_length(m, NULL);

			ifp->if_opackets++;

			if (!sc->isfile && (pktlen <= sizeof(copybuf))) {			
				if (NULL == m->m_next) {
					/* all in one piece - avoid copy */
					pkt = mtod(m, uint8_t *);
					ifp->if_ozcopies++;
				} else {
					pkt = copybuf;
					m_copydata(m, 0, pktlen, pkt);
					ifp->if_ocopies++;
				}

				if (0 != if_pcap_sendpacket(sc->pcap_host_ctx, pkt, pktlen))
					ifp->if_oerrors++;
			} else {
				if (sc->isfile)
					printf("if_pcap_send: Packet send attempt in file mode\n");
				ifp->if_oerrors++;
			}

			m_freem(m);
		}
	}
}


static void
if_pcap_stop(struct if_pcap_softc *sc)
{
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING|IFF_DRV_OACTIVE);
}


static int
if_pcap_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int error = 0;
	struct if_pcap_softc *sc = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			if_pcap_init(sc);
		else if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			if_pcap_stop(sc);
		break;
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}


static void
if_pcap_receive_handler(void *ctx, const uint8_t *buf, unsigned int size)
{
	struct if_pcap_softc *sc = (struct if_pcap_softc *)ctx;
	struct ifnet *ifp = sc->ifp;
	struct mbuf *m;

	m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);

	if (m == NULL) {
		ifp->if_iqdrops++;
		return;
	}

	m_adj(m, ETHER_ALIGN);

	memcpy(mtod(m, uint8_t *), buf, size);
	m->m_len = m->m_pkthdr.len = size;
	m->m_pkthdr.rcvif = sc->ifp;

#if 0
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
	if (sc->isfile)
		printf("injecting packet from file: %48D\n", mtod(m, unsigned char *), " ");
#pragma GCC diagnostic error "-Wformat"
#pragma GCC diagnostic error "-Wformat-extra-args"
#endif

	ifp->if_ipackets++;
	ifp->if_icopies++;
	sc->ifp->if_input(sc->ifp, m);
}


static void
if_pcap_receive(void *arg)
{
	struct if_pcap_softc *sc = (struct if_pcap_softc *)arg;
	int result;

	if (sc->uif->cpu >= 0)
		sched_bind(sc->rx_thread, sc->uif->cpu);

	if (sc->isfile)
		pause("pcaprx", hz);

	result = if_pcap_loop(sc->pcap_host_ctx);
	
	printf("%s exiting receive thread (%d)\n", sc->uif->name, result);
}


static int
if_pcap_setup_interface(struct if_pcap_softc *sc)
{
	struct ifnet *ifp;

	ifp = sc->ifp = if_alloc(IFT_ETHER);

	ifp->if_init =  if_pcap_init;
	ifp->if_softc = sc;

	if_initname(ifp, sc->uif->name, IF_DUNIT_NONE);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = if_pcap_ioctl;
	ifp->if_start = if_pcap_start;

	/* XXX what values? */
	IFQ_SET_MAXLEN(&ifp->if_snd, 128);
	ifp->if_snd.ifq_drv_maxlen = 128;

	IFQ_SET_READY(&ifp->if_snd);

	ifp->if_fib = sc->uif->cdom;

	ether_ifattach(ifp, sc->addr);
	ifp->if_capabilities = ifp->if_capenable = IFCAP_HWSTATS;


	mtx_init(&sc->tx_lock, "txlk", NULL, MTX_DEF);

	if (kthread_add(if_pcap_send, sc, NULL, &sc->tx_thread, 0, 0, "pcap_tx: %s", ifp->if_xname)) {
		printf("Could not start transmit thread for %s (%s)\n", ifp->if_xname, sc->host_ifname);
		ether_ifdetach(ifp);
		if_free(ifp);
		return (1);
	}


	if (kthread_add(if_pcap_receive, sc, NULL, &sc->rx_thread, 0, 0, "pcap_rx: %s", ifp->if_xname)) {
		printf("Could not start receive thread for %s (%s)\n", ifp->if_xname, sc->host_ifname);
		ether_ifdetach(ifp);
		if_free(ifp);
		return (1);
	}

	return (0);
}


int
if_pcap_detach(struct uinet_if *uif)
{
	struct if_pcap_softc *sc = uif->ifdata;

	if (sc) {
		/* XXX ether_ifdetach, stop threads */

#if notyet
		if_pcap_destroy_handle(sc->pcap_host_ctx);
		
		free(sc, M_DEVBUF);
#endif
	}

	return (0);
}


