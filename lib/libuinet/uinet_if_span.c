/*
 * Copyright (c) 2014 Adrian Chadd, Norse Inc.  All Rights Reserved.
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
#include "uinet_if_span.h"

/*
 * This implements a multi-port span interface.
 *
 * It's design to be a read-only span interface where multiple ports
 * are seeing different parts of the traffic.  So this combines all of
 * the traffic from various interfaces.
 */

extern	struct mbuf *(*bridge_input_p)(struct ifnet *, struct mbuf *);
extern	int (*bridge_output_p)(struct ifnet *, struct mbuf *,
		struct sockaddr *, struct rtentry *);

struct if_span_member;

struct if_span_member {
	LIST_ENTRY(if_span_member) bif_next;
	struct ifnet *ifp;
};

struct if_span_softc {
	struct ifnet *sc_ifp;
	const struct uinet_if *uif;
	struct ether_addr sc_addr;

	struct mtx sc_mtx;
	LIST_HEAD(, if_span_member) sc_iflist;   /* member interface list */

	/* XXX TODO: more useful state? */
};

static int span_if_count = 0;

/*
 * Process an incoming frame.  This gets called
 * from the child device ether_input path.
 */
static struct mbuf *
if_span_input(struct ifnet *ifp, struct mbuf *m)
{
	struct if_span_softc *sc;
	struct ifnet *bifp;
#if 0
	struct mbuf *mc2;
#endif

	sc = ifp->if_bridge;
	bifp = sc->sc_ifp;

	/* Note: We don't need to locally process the frame */
	m->m_pkthdr.rcvif = bifp;
	(*bifp->if_input)(bifp, m);
	return (NULL);

#if 0
	/* Duplicate; pass up to the stack */
	mc2 = m_copypacket(m, M_DONTWAIT);
	/* XXX count failure */
	if (mc2 != NULL) {
		mc2->m_pkthdr.rcvif = bifp;
		(*bifp->if_input)(bifp, mc2);
	}

	/* Return the original packet for local processing. */
	return (m);
#endif
}

/*
 */
static int
if_span_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *sa,
    struct rtentry *rt)
{

	printf("%s: m=%p; called\n", __func__, m);
	/* For now, we consume the frame */
	m_freem(m);
	return (0);
}

static void
if_span_init(void *arg)
{
	struct if_span_softc *sc = arg;
	struct ifnet *ifp = sc->sc_ifp;

	ifp->if_drv_flags = IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}

static void
if_span_stop(struct if_span_softc *sc)
{
	struct ifnet *ifp = sc->sc_ifp;

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING|IFF_DRV_OACTIVE);
}

static int
if_span_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int error = 0;
	struct if_span_softc *sc = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			if_span_init(sc);
		else if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			if_span_stop(sc);
			break;
		default:
			error = ether_ioctl(ifp, cmd, data);
		break;
		}
	return (error);
}

static int
if_span_transmit(struct ifnet *ifp, struct mbuf *m)
{

	printf("%s: m=%p; called\n", __func__, m);

	/* XXX for now, free */
	m_freem(m);
	return (ENOBUFS);
}

static void
if_span_qflush(struct ifnet *ifp)
{

}

static int
if_span_existsm_locked(struct if_span_softc *sc, struct ifnet *nifp)
{
	struct if_span_member *bif;

	/* XXX assert locked */
	LIST_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if (bif->ifp == nifp)
			return (1);
	}
	return (0);
}

static int
if_span_addm(struct if_span_softc *sc, const char *ifname)
{
	struct ifnet *nifp = NULL;
	struct if_span_member *bif;
	int error = 0;

	/* Do lookup */
	nifp = ifunit_ref(ifname);
	if (nifp == NULL) {
		printf("%s: '%s' not found\n",
		    __func__,
		    ifname);
		return (ENOENT);
	}

	mtx_lock(&sc->sc_mtx);

	/* See if this exists. Don't double-add */
	if (if_span_existsm_locked(sc, nifp)) {
		printf("%s: '%s' already is in this span\n",
		    __func__,
		    ifname);
		error = EINVAL;
		goto fail;
	}

	/* Is it a member of ANY span/bridge? */
	if (nifp->if_bridge != NULL) {
		printf("%s: '%s' is already in _a_ span\n",
		    __func__,
		    ifname);
		error = EBUSY;
		goto fail;
	}

	/* Allocate span-member entry, add to list */
	bif = malloc(sizeof(struct if_span_member), M_DEVBUF, M_NOWAIT);
	if (bif == NULL) {
		printf("%s: failed to malloc", __func__);
		error = ENOMEM;
		goto fail;
	}

	/* Add to list; link back from the ifnet to the parent span */
	bif->ifp = nifp;
	LIST_INSERT_HEAD(&sc->sc_iflist, bif, bif_next);
	nifp->if_bridge = sc;

	mtx_unlock(&sc->sc_mtx);

	/* Make promisc */
	error = ifpromisc(nifp, 1);
	if (error != 0) {
		mtx_lock(&sc->sc_mtx);
		/* XXX methodize */
		LIST_REMOVE(bif, bif_next);
		mtx_unlock(&sc->sc_mtx);
		free(bif, M_DEVBUF);
		printf("%s: '%s' couldn't make it promisc!\n", __func__, ifname);
		error = EINVAL;
		goto fail;
	}

	printf("%s: added '%s' to span\n",
	    __func__,
	    ifname);

	/* Done! */
	return (0);
fail:
	mtx_unlock(&sc->sc_mtx);
	/* Free reference */
	if (nifp)
		if_rele(nifp);

	return (error);
}


static struct ether_addr *
i_ether_aton_r(const char *a, struct ether_addr *e)
{
	int i;
	unsigned int o0, o1, o2, o3, o4, o5;

	i = sscanf(a, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);
	if (i != 6)
		return (NULL);
	e->octet[0]=o0;
	e->octet[1]=o1;
	e->octet[2]=o2;
	e->octet[3]=o3;
	e->octet[4]=o4;
	e->octet[5]=o5;
	return (e);
}

int
if_span_attach(struct uinet_if *uif)
{
	struct if_span_softc *sc = NULL;
	int error = 0;
	char *cstr = NULL, *s;

	if (NULL == uif->configstr) {
		error = EINVAL;
		goto fail;
	}

	printf("%s: configstr=%s\n", __func__, uif->configstr);
	cstr = strdup(uif->configstr, M_TEMP);
	if (cstr == NULL) {
		printf("%s: strdup failed\n", __func__);
		error = ENOMEM;
		goto fail;
	}

	sc = malloc(sizeof(struct if_span_softc), M_DEVBUF, M_WAITOK);
	if (sc == NULL) {
		printf("%s: malloc failed\n", __func__);
		error = ENOMEM;
		goto fail;
	}

	/* Set the interface name */
	snprintf(uif->name, sizeof(uif->name), "span%u", span_if_count);
	span_if_count++;

	sc->uif = uif;

	/*
	 * The ethernet path has a bunch of hard-coded
	 * span function pointers for whatever implements
	 * bridging.  It's a hack, but in order to get
	 * frames and link status changes, we need to
	 * also do the same.
	 */
	bridge_input_p = if_span_input;
	bridge_output_p = if_span_output;

	/*
	 * Setup initial local MAC address - random.
	 */
	sc->sc_addr.octet[0] = 0x62;
	sc->sc_addr.octet[1] = 0x73;
	sc->sc_addr.octet[2] = 0x64;
	sc->sc_addr.octet[3] = arc4random();
	sc->sc_addr.octet[4] = arc4random();
	sc->sc_addr.octet[5] = arc4random();

	 /*
	  * Allocate netif context.
	  */
	sc->sc_ifp = if_alloc(IFT_ETHER);
	if (sc->sc_ifp == NULL) {
		printf("%s: if_alloc failed", __func__);
		error = ENOMEM;
		goto fail;
	}
	sc->sc_ifp->if_softc = sc;

	/*
	 * Setup basic flags and such.
	 */
	if_initname(sc->sc_ifp, sc->uif->name, IF_DUNIT_NONE);
	sc->sc_ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	sc->sc_ifp->if_mtu = 1500;	/* XXX verify! */

	/*
	 * Setup netif methods.
	 */
	sc->sc_ifp->if_init = if_span_init;
	sc->sc_ifp->if_ioctl = if_span_ioctl;
	sc->sc_ifp->if_transmit = if_span_transmit;
	sc->sc_ifp->if_qflush = if_span_qflush;

	/* Mutex protecting the span list */
	mtx_init(&sc->sc_mtx, "if_span", NULL, MTX_DEF);

	/* This is our list of child interfaces */
	LIST_INIT(&sc->sc_iflist);

	/* Parse the config string */
	while ( (s = strsep(&cstr, ",")) != NULL) {
		char *ss, *a, *v;
		struct ether_addr ea;

		ss = strdup(s, M_TEMP);
		if (ss == NULL) {
			printf("%s: strdup: failed\n", __func__);
			error = ENOMEM;
			goto fail;
		}
		a = strsep(&ss, "=");
		v = strsep(&ss, "=");
		if (a == NULL || v == NULL) {
			printf("%s: invalid config chunk '%s'\n", __func__, s);
			error = ENOMEM;
			free(ss, M_TEMP);
			goto fail;
		}

		/* Now, handle the various options */
		if (strcmp(a, "if") == 0) {
			/* XXX error check */
			(void) if_span_addm(sc, v);
		} else if (strcmp(a, "mac") == 0) {
			/* XXX TODO: no ether_aton_r() in the kernel */
			if (i_ether_aton_r(v, &ea) != NULL) {
				sc->sc_addr = ea;
			}
		} else {
			printf("%5s; unknown config option '%s'\n", __func__, a);
			free(ss, M_TEMP);
			goto fail;
		}
		free(ss, M_TEMP);
	}

	/* Set local MAC now */
	ether_ifattach(sc->sc_ifp, sc->sc_addr.octet);
	sc->sc_ifp->if_capabilities = sc->sc_ifp->if_capenable = 0;

	/*
	 * Link uinet uif state back to the newly setup ifnet.
	 */
	uif->ifindex = sc->sc_ifp->if_index;
	uif->ifdata = sc;
	uif->ifp = sc->sc_ifp;

	return (0);

fail:
	if (cstr)
		free(cstr, M_TEMP);
	/* XXX TODO: deregister child interfaces */
	if (sc && sc->sc_ifp)
		if_free(sc->sc_ifp);
	if (sc)
		free(sc, M_DEVBUF);
	return (error);

}

int
if_span_detach(struct uinet_if *uif)
{
	/* XXX TODO */
	return (0);
}
