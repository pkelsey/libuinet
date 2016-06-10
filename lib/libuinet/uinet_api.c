/*
 * Copyright (c) 2015 Patrick Kelsey. All rights reserved.
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

#include "opt_passiveinet.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_promiscinet.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_promisc.h>
#include <netinet/tcp_syncache.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include "uinet_internal.h"
#include "uinet_host_interface.h"

#include "opt_inet6.h"


int
uinet_inet6_enabled(void)
{
#ifdef INET6
	return (1);
#else
	return (0);
#endif
}


int
uinet_initialize_thread(const char *name)
{
	struct uinet_thread *utd;
	int cpuid;

	/*
	 * uinet_shutdown() waits for a message from the shutdown thread
	 * indicating shutdown is complete.  If uinet_shutdown() is called
	 * from a signal handler running in a thread context that is holding
	 * a lock that the shutdown activity needs to acquire in order to
	 * complete, deadlock will occur.  Masking all signals in all
	 * threads that use the uinet API prevents such a deadlock by
	 * preventing all signal handlers (and thus any that might call
	 * uinet_shutdown()) from running in the context of any thread that
	 * might be holding a lock required by the shutdown thread.
	 */
	uhi_mask_all_signals();

	uhi_thread_set_name(name);

	utd = uhi_tls_get(kthread_tls_key);
	if (NULL == utd) {
		/* This thread has not been initialized */
		utd = uinet_thread_alloc(NULL);
		if (NULL == utd)
			return (ENOMEM);

		uhi_tls_set(kthread_tls_key, utd);
		uhi_thread_run_hooks(UHI_THREAD_HOOK_START);
	} else {
		/*
		 * If already initialized, update current cpu so
		 * uinet_initialize_thread() can be called on an already
		 * initialized thread after changing the cpu pin state to
		 * update the cached current cpu.
		 */
		cpuid = uhi_thread_bound_cpu();
		utd->td.td_oncpu = (cpuid == -1) ? 0 : cpuid % mp_ncpus;
	}

	return (0);
}


void
uinet_finalize_thread(void)
{
	struct uinet_thread *utd;

	utd = uhi_tls_get(kthread_tls_key);

	if (utd != NULL) {
		uinet_thread_free(utd);
		uhi_tls_set(kthread_tls_key, NULL);
	}
}


int
uinet_getifstat(uinet_if_t uif, struct uinet_ifstat *stat)
{
	struct ifnet *ifp;
	int error = 0;

	CURVNET_SET(uif->uinst->ui_vnet);

	ifp = ifnet_byindex_ref(uif->ifindex);
	if (NULL == ifp) {
		printf("could not find interface %s by index\n", uif->name);
		error = EINVAL;
		goto out;
	}
	
	stat->ifi_ipackets   = ifp->if_data.ifi_ipackets;
	stat->ifi_ierrors    = ifp->if_data.ifi_ierrors;
	stat->ifi_opackets   = ifp->if_data.ifi_opackets;
	stat->ifi_oerrors    = ifp->if_data.ifi_oerrors + ifp->if_snd.ifq_drops;
	stat->ifi_collisions = ifp->if_data.ifi_collisions;
	stat->ifi_ibytes     = ifp->if_data.ifi_ibytes;
	stat->ifi_obytes     = ifp->if_data.ifi_obytes;
	stat->ifi_imcasts    = ifp->if_data.ifi_imcasts;
	stat->ifi_omcasts    = ifp->if_data.ifi_omcasts;
	stat->ifi_iqdrops    = ifp->if_data.ifi_iqdrops;
	stat->ifi_noproto    = ifp->if_data.ifi_noproto;
	stat->ifi_hwassist   = ifp->if_data.ifi_hwassist;
	stat->ifi_epoch      = ifp->if_data.ifi_epoch;
	stat->ifi_icopies    = ifp->if_data.ifi_icopies;
	stat->ifi_izcopies   = ifp->if_data.ifi_izcopies;
	stat->ifi_ocopies    = ifp->if_data.ifi_ocopies;
	stat->ifi_ozcopies   = ifp->if_data.ifi_ozcopies;

	if_rele(ifp);

out:
	CURVNET_RESTORE();

	return (error);
}


void
uinet_gettcpstat(uinet_instance_t uinst, struct uinet_tcpstat *stat)
{
	CURVNET_SET(uinst->ui_vnet);
	*((struct tcpstat *)stat) = V_tcpstat;
	CURVNET_RESTORE();
}


char *
uinet_inet_ntoa(struct uinet_in_addr in, char *buf, unsigned int size)
{
	(void)size;

	return inet_ntoa_r(*((struct in_addr *)&in), buf); 
}


const char *
uinet_inet_ntop(int af, const void *src, char *dst, unsigned int size)
{
	return (inet_ntop(af, src, dst, size));
}


int
uinet_inet_pton(int af, const char *src, void *dst)
{
	return (inet_pton(af, src, dst));
}


static int
uinet_ifconfig_begin(uinet_instance_t uinst, struct socket **so,
		     struct ifreq *ifr, const char *name)
{
	struct thread *td = curthread;
	struct uinet_if *uif;
	int error;

	uif = uinet_iffind_byname(uinst, name);
	if (NULL == uif) {
		printf("could not find interface %s\n", name);
		return (EINVAL);
	}

	error = socreate(PF_INET, so, SOCK_DGRAM, 0, td->td_ucred, td, uinst->ui_vnet);
	if (0 != error) {
		printf("ifconfig socket creation failed (%d)\n", error);
		return (error);
	}

	snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", uif->name);
	
	return (0);
}


static int
uinet_ifconfig_do(struct socket *so, unsigned long what, void *req)
{
	int error;

	error = ifioctl(so, what, (caddr_t)req, curthread);
	if (error != 0)
		printf("ifioctl 0x%08lx failed %d\n", what, error);

	return (error);
}


static void
uinet_ifconfig_end(struct socket *so)
{
	soclose(so);
}


int
uinet_interface_add_alias(uinet_instance_t uinst, const char *name,
			  const char *addr, const char *braddr, const char *mask)
{
	struct socket *cfg_so;
	struct in_aliasreq ina;
	struct sockaddr_in template = {
		.sin_len = sizeof(struct sockaddr_in),
		.sin_family = AF_INET
	};
	int error;

	/*
	 * The cast of ina to (struct ifreq *) is safe because they both
	 * begin with the same size name field, and uinet_ifconfig_begin
	 * only touches the name field.
	 */
	error = uinet_ifconfig_begin(uinst, &cfg_so, (struct ifreq *)&ina, name);
	if (0 != error) {
		return (error);
	}

	ina.ifra_addr = template;
	if (inet_pton(AF_INET, addr, &ina.ifra_addr.sin_addr) <= 0) {
		error = EAFNOSUPPORT;
		goto out;
	}

	if (braddr == NULL || braddr[0] == '\0') {
		/* stack will set based on net class */
		ina.ifra_broadaddr.sin_len = 0;
	} else {
		ina.ifra_broadaddr = template;
		if (inet_pton(AF_INET, braddr, &ina.ifra_broadaddr.sin_addr) <= 0) {
			error = EAFNOSUPPORT;
			goto out;
		}
	}

	if (mask == NULL || mask[0] == '\0') {
		/* stack will set based on net class */
		ina.ifra_mask.sin_len = 0;
	} else {
		ina.ifra_mask = template;
		if (inet_pton(AF_INET, mask, &ina.ifra_mask.sin_addr) <= 0) {
			error = EAFNOSUPPORT;
			goto out;
		}
	}

	error = uinet_ifconfig_do(cfg_so, SIOCAIFADDR, &ina);

out:
	uinet_ifconfig_end(cfg_so);

	return (error);
}


int
uinet_interface_create(uinet_instance_t uinst, const char *name)
{
	struct socket *cfg_so;
	struct ifreq ifr;
	int error;

	error = uinet_ifconfig_begin(uinst, &cfg_so, &ifr, name);
	if (0 != error)
		return (error);

	error = uinet_ifconfig_do(cfg_so, SIOCIFCREATE, &ifr);

	uinet_ifconfig_end(cfg_so);

	return (error);
}


int
uinet_interface_up(uinet_instance_t uinst, const char *name, unsigned int promisc, unsigned int promiscinet)
{
	struct socket *cfg_so;
	struct ifreq ifr;
	int error;

	error = uinet_ifconfig_begin(uinst, &cfg_so, &ifr, name);
	if (0 != error)
		return (error);
	
	/* set interface to UP */

	error = uinet_ifconfig_do(cfg_so, SIOCGIFFLAGS, &ifr);
	if (0 == error) {
		ifr.ifr_flags |= IFF_UP;
		if (promisc)
			ifr.ifr_flagshigh |= IFF_PPROMISC >> 16;
		
		if (promiscinet)
			ifr.ifr_flagshigh |= IFF_PROMISCINET >> 16;
		
		error = uinet_ifconfig_do(cfg_so, SIOCSIFFLAGS, &ifr);
	}

	uinet_ifconfig_end(cfg_so);

	return (error);
}


int
uinet_mac_aton(const char *macstr, uint8_t *macout)
{

	unsigned int i;
	const char *p;
	char *endp;

	if ((NULL == macstr) || (macstr[0] == '\0')) {
		memset(macout, 0, ETHER_ADDR_LEN);
		return (0);
	}

	p = macstr;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		macout[i] = strtoul(p, &endp, 16);
		if ((endp != &p[2]) ||					/* two hex digits */
		    ((i < ETHER_ADDR_LEN - 1) && (*endp != ':')) ||	/* followed by ':', unless last pair */
		    ((i == ETHER_ADDR_LEN - 1) && (*endp != '\0'))) {	/* followed by '\0', if last pair */
			return (1);
		}
		p = endp + 1;
	}

	return (0);
}


int
uinet_make_socket_passive(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int optval, optlen;
	int error;

	optlen = sizeof(optval);

	optval = 1;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_PASSIVE, &optval, optlen)))
		goto out;
	
	optval = 1;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_REUSEPORT, &optval, optlen)))
		goto out;

	optval = 256*1024;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_RCVBUF, &optval, optlen)))
		goto out;
out:
	return (error);
}


int
uinet_make_socket_promiscuous(struct uinet_socket *so, uinet_if_t txif)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int optval, optlen;
	int error;

	optlen = sizeof(optval);

	optval = 1;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_PROMISC, &optval, optlen)))
		goto out;
	
	optval = 1;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_REUSEPORT, &optval, optlen)))
		goto out;
	
	optval = 1;
	if ((error = so_setsockopt(so_internal, IPPROTO_IP, IP_BINDANY, &optval, optlen)))
		goto out;

	if (txif != NULL && (error = uinet_sosettxif(so, txif)))
		goto out;

out:
	return (error);
}


int
uinet_getl2info(struct uinet_socket *so, struct uinet_in_l2info *l2i)
{
	struct socket *so_internal = (struct socket *)so;
	struct in_l2info l2i_internal;
	size_t optlen;
	int error = 0;


	optlen = sizeof(*l2i);
	error = so_getsockopt(so_internal, SOL_SOCKET, SO_L2INFO, &l2i_internal, &optlen);
	if (0 == error) {
		memcpy(l2i, &l2i_internal, sizeof(*l2i));
	}

	return (error);
}


int
uinet_setl2info(struct uinet_socket *so, const struct uinet_in_l2info *l2i)
{
	struct socket *so_internal = (struct socket *)so;
	int error = 0;

	error = so_setsockopt(so_internal, SOL_SOCKET, SO_L2INFO, l2i, sizeof(*l2i));

	return (error);
}


int
uinet_setl2info2(struct uinet_socket *so, const uint8_t *local_addr, const uint8_t *foreign_addr,
		 uint16_t flags, const struct uinet_in_l2tagstack *tagstack)
{
	struct uinet_in_l2info l2i;

	memset(&l2i, 0, sizeof(l2i));

	if (local_addr)
		memcpy(l2i.inl2i_local_addr, local_addr, ETHER_ADDR_LEN);

	if (foreign_addr)
		memcpy(l2i.inl2i_foreign_addr, foreign_addr, ETHER_ADDR_LEN);

	l2i.inl2i_flags = flags;

	if (tagstack) {
		memcpy(&l2i.inl2i_tagstack, tagstack, sizeof(l2i.inl2i_tagstack));
	}

	return (uinet_setl2info(so, &l2i));
}


int
uinet_l2tagstack_cmp(const struct uinet_in_l2tagstack *ts1, const struct uinet_in_l2tagstack *ts2)
{
	return (in_promisc_tagcmp((const struct in_l2tagstack *)ts1, (const struct in_l2tagstack *)ts2));
}


uint32_t
uinet_l2tagstack_hash(const struct uinet_in_l2tagstack *ts)
{
	uint32_t hash;

	if (ts->inl2t_cnt) {
		hash = in_promisc_hash32(ts->inl2t_tags, 
					 ts->inl2t_masks,
					 ts->inl2t_cnt,
					 0);
	} else {
		hash = 0;
	}

	return (hash);
}


/*
 * This is really a version of kern_accept() without the file descriptor
 * bits.  As long as SS_NBIO is set on the listen socket, it does just what
 * you want to do in an upcall on that socket, so it's a better piece of
 * functionality to expose than just wrapping a bare soaccept().  If a blocking
 * syscall/poll style API comes later, this routine will serve that need as
 * well.
 */
int
uinet_soaccept(struct uinet_socket *listener, struct uinet_sockaddr **nam, struct uinet_socket **aso)
{
	struct socket *head = (struct socket *)listener;
	struct socket *so;
#ifdef PASSIVE_INET
	struct socket *peer_so;
#endif
	struct sockaddr *sa = NULL;
	int error = 0;

	if (nam)
		*nam = NULL;

	*aso = NULL;
	CURVNET_SET(head->so_vnet);
	ACCEPT_LOCK();
	if ((head->so_state & SS_NBIO) && TAILQ_EMPTY(&head->so_comp)) {
		if (head->so_upcallprep.soup_accept != NULL) {
			head->so_upcallprep.soup_accept(head,
							head->so_upcallprep.soup_accept_arg);
		}
		ACCEPT_UNLOCK();
		error = EWOULDBLOCK;
		goto noconnection;
	}

	while (TAILQ_EMPTY(&head->so_comp) && head->so_error == 0) {
		if (head->so_rcv.sb_state & SBS_CANTRCVMORE) {
			head->so_error = ECONNABORTED;
			break;
		}
		error = msleep(&head->so_timeo, &V_accept_mtx, PSOCK | PCATCH,
		    "accept", 0);
		if (error) {
			ACCEPT_UNLOCK();
			goto noconnection;
		}
	}
	if (head->so_error) {
		error = head->so_error;
		head->so_error = 0;
		ACCEPT_UNLOCK();
		goto noconnection;
	}

	so = TAILQ_FIRST(&head->so_comp);
	KASSERT(!(so->so_qstate & SQ_INCOMP), ("uinet_soaccept: so_qstate SQ_INCOMP"));
	KASSERT(so->so_qstate & SQ_COMP, ("uinet_soaccept: so_qstate not SQ_COMP"));

	/*
	 * Before changing the flags on the socket, we have to bump the
	 * reference count.  Otherwise, if the protocol calls sofree(),
	 * the socket will be released due to a zero refcount.
	 */
	SOCK_LOCK(so);			/* soref() and so_state update */
	soref(so);			/* socket came from sonewconn() with an so_count of 0 */

	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	so->so_state |= (head->so_state & SS_NBIO);
	so->so_qstate &= ~SQ_COMP;
	so->so_head = NULL;

	SOCK_UNLOCK(so);

#ifdef PASSIVE_INET
	peer_so = so->so_passive_peer;
	if (so->so_options & SO_PASSIVE) {
		KASSERT(peer_so, ("uinet_soaccept: passive socket has no peer"));
		SOCK_LOCK(peer_so);
		soref(peer_so);
		peer_so->so_state |=
		    (head->so_state & SS_NBIO) | SO_PASSIVECLNT;
		SOCK_UNLOCK(peer_so);
	}
#endif
	ACCEPT_UNLOCK();

	error = soaccept(so, &sa);
	if (error) {
#ifdef PASSIVE_INET
		if (peer_so)
			soclose(peer_so);
#endif
		soclose(so);
		goto noconnection;
	}

	if (nam) {
		*nam = (struct uinet_sockaddr *)sa;
		sa = NULL;
	}

	*aso = (struct uinet_socket *)so;

noconnection:
	if (sa)
		free(sa, M_SONAME);

	CURVNET_RESTORE();
	return (error);
}


int
uinet_sobind(struct uinet_socket *so, struct uinet_sockaddr *nam)
{
	return sobind((struct socket *)so, (struct sockaddr *)nam, curthread);
}


int
uinet_soclose(struct uinet_socket *so)
{
	return soclose((struct socket *)so);
}


/*
 * This is really a version of kern_connect() without the file descriptor
 * bits.  As long as SS_NBIO is set on the socket, it does not block.  If a
 * blocking syscall/poll style API comes later, this routine will serve that
 * need as well.
 */
int
uinet_soconnect(struct uinet_socket *uso, struct uinet_sockaddr *nam)
{
	struct socket *so = (struct socket *)uso;
	int error;
	int interrupted = 0;

	if (so->so_state & SS_ISCONNECTING) {
		error = EALREADY;
		goto done1;
	}

	error = soconnect(so, (struct sockaddr *)nam, curthread);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		error = EINPROGRESS;
		goto done1;
	}
	CURVNET_SET(so->so_vnet);
	SOCK_LOCK(so);
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = msleep(&so->so_timeo, SOCK_MTX(so), PSOCK | PCATCH,
		    "connec", 0);
		if (error) {
			if (error == EINTR || error == ERESTART)
				interrupted = 1;
			break;
		}
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	SOCK_UNLOCK(so);
	CURVNET_RESTORE();
bad:
	if (!interrupted)
		so->so_state &= ~SS_ISCONNECTING;
	if (error == ERESTART)
		error = EINTR;
done1:
	return (error);
}


int
uinet_socreate(uinet_instance_t uinst, int dom, struct uinet_socket **aso, int type, int proto)
{
	struct thread *td = curthread;

	return socreate(dom, (struct socket **)aso, type, proto, td->td_ucred, td, uinst->ui_vnet);
}


void
uinet_sogetconninfo(struct uinet_socket *so, struct uinet_in_conninfo *inc)
{
	struct socket *so_internal = (struct socket *)so;
	struct inpcb *inp = sotoinpcb(so_internal);

	CURVNET_SET(so_internal->so_vnet);
	/* XXX do we really need the INFO lock here? */
	INP_INFO_RLOCK(inp->inp_pcbinfo);
	INP_RLOCK(inp);
	memcpy(inc, &sotoinpcb(so_internal)->inp_inc, sizeof(struct uinet_in_conninfo));
	INP_RUNLOCK(inp);
	INP_INFO_RUNLOCK(inp->inp_pcbinfo);
	CURVNET_RESTORE();
}


int
uinet_sogeterror(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;

	return (so_internal->so_error);
}


uinet_instance_t
uinet_sogetinstance(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;

	return (so_internal->so_vnet->vnet_uinet);
}


struct uinet_socket *
uinet_sogetpassivepeer(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;

	return ((struct uinet_socket *)(so_internal->so_passive_peer));
}


uint64_t
uinet_sogetserialno(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;
	struct inpcb *inp = sotoinpcb(so_internal);

	return (inp->inp_serialno);
}


int
uinet_sogetsockopt(struct uinet_socket *so, int level, int optname, void *optval,
		   unsigned int *optlen)
{
	size_t local_optlen;
	int result;

	local_optlen = *optlen;
	result = so_getsockopt((struct socket *)so, level, optname, optval, &local_optlen);
	*optlen = local_optlen;

	return (result);
}


int
uinet_sogetstate(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;

	return (so_internal->so_state);
}


int
uinet_solisten(struct uinet_socket *so, int backlog)
{
	return solisten((struct socket *)so, backlog, curthread);
}


int
uinet_soreadable(struct uinet_socket *so, unsigned int in_upcall)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int avail; 
	int canread;

	CURVNET_SET(so_internal->so_vnet);
	if (so_internal->so_options & SO_ACCEPTCONN) {
		if (so_internal->so_error)
			canread = -1;
		else {
			ACCEPT_LOCK();
			canread = so_internal->so_qlen;
			ACCEPT_UNLOCK();
		}
	} else {
		if (!in_upcall)
			SOCKBUF_LOCK(&so_internal->so_rcv);

		avail = so_internal->so_rcv.sb_cc;
		if (avail || (!so_internal->so_error && !(so_internal->so_rcv.sb_state & SBS_CANTRCVMORE))) {
			if (avail > INT_MAX)
				canread = INT_MAX;
			else
				canread = avail;
		} else
			canread = -1;

		if (!in_upcall)
			SOCKBUF_UNLOCK(&so_internal->so_rcv);
	}
	CURVNET_RESTORE();

	return canread;
}


int
uinet_sowritable(struct uinet_socket *so, unsigned int in_upcall)
{
	struct socket *so_internal = (struct socket *)so;
	long space;
	int canwrite;

	CURVNET_SET(so_internal->so_vnet);
	if (so_internal->so_options & SO_ACCEPTCONN) {
		canwrite = 0;
	} else {
		if (!in_upcall)
			SOCKBUF_LOCK(&so_internal->so_snd);

		if ((so_internal->so_snd.sb_state & SBS_CANTSENDMORE) ||
		    so_internal->so_error ||
		    (so_internal->so_state & SS_ISDISCONNECTED)) {
			canwrite = -1;
		} else if ((so_internal->so_state & SS_ISCONNECTED) == 0) {
			canwrite = 0;
		} else {
			space = sbspace(&so_internal->so_snd);
			if (space > INT_MAX)
				canwrite = INT_MAX;
			else if (space < 0)
				canwrite = 0;
			else
				canwrite = space;
		}

		if (!in_upcall)
			SOCKBUF_UNLOCK(&so_internal->so_snd);
	}
	CURVNET_RESTORE();

	return canwrite;
}


int
uinet_soallocuserctx(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;
	int error;

	CURVNET_SET(so_internal->so_vnet);
	error = souserctx_alloc(so_internal);
	CURVNET_RESTORE();

	return (error);
}


void *
uinet_sogetuserctx(struct uinet_socket *so, int key)
{
	struct socket *so_internal = (struct socket *)so;

	if ((key >= 0) && (key < SOMAXUSERCTX))
		return (so_internal->so_user_ctx[key]);
	else
		return (NULL);
		
}


void
uinet_sosetuserctx(struct uinet_socket *so, int key, void *ctx)
{
	struct socket *so_internal = (struct socket *)so;

	if ((key >= 0) && (key < SOMAXUSERCTX))
		so_internal->so_user_ctx[key] = ctx;
}


int
uinet_soreceive(struct uinet_socket *so, struct uinet_sockaddr **psa, struct uinet_uio *uio, int *flagsp)
{
	struct iovec iov[uio->uio_iovcnt];
	struct uio uio_internal;
	int i;
	int result;

	for (i = 0; i < uio->uio_iovcnt; i++) {
		iov[i].iov_base = uio->uio_iov[i].iov_base;
		iov[i].iov_len = uio->uio_iov[i].iov_len;
	}
	uio_internal.uio_iov = iov;
	uio_internal.uio_iovcnt = uio->uio_iovcnt;
	uio_internal.uio_offset = uio->uio_offset;
	uio_internal.uio_resid = uio->uio_resid;
	uio_internal.uio_segflg = UIO_SYSSPACE;
	uio_internal.uio_rw = UIO_READ;
	uio_internal.uio_td = curthread;
	
	result = soreceive((struct socket *)so, (struct sockaddr **)psa, &uio_internal, NULL, NULL, flagsp);

	uio->uio_resid = uio_internal.uio_resid;

	return (result);
}


int
uinet_sosetcatchall(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int optval, optlen;
	int error;
	
	optlen = sizeof(optval);
	optval = 1;
	error = so_setsockopt(so_internal, IPPROTO_IP, IP_CATCHALL_LISTEN, &optval, optlen);

	return (error);
}


int
uinet_sosetcopymode(struct uinet_socket *so, unsigned int mode, uint64_t limit, uinet_if_t uif)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int optval, optlen;
	uint64_t optval64;
	int error;

	optlen = sizeof(optval);
	optval = mode;
	error = so_setsockopt(so_internal, IPPROTO_IP, IP_COPY_MODE, &optval, optlen);
	if (error)
		goto out;
	
	if (uif != NULL) {
		optlen = sizeof(optval);
		optval = uif->ifp->if_index;
		error = so_setsockopt(so_internal, IPPROTO_IP, IP_COPY_IF, &optval, optlen);
		if (error)
			goto out;
	}

	optlen = sizeof(optval64);
	optval64 = limit;
	error = so_setsockopt(so_internal, IPPROTO_IP, IP_COPY_LIMIT, &optval64, optlen);
	if (error)
		goto out;

out:
	return (error);
}


void
uinet_sosetnonblocking(struct uinet_socket *so, unsigned int nonblocking)
{
	struct socket *so_internal = (struct socket *)so;

	if (nonblocking) {
		so_internal->so_state |= SS_NBIO;
	} else {
		so_internal->so_state &= ~SS_NBIO;
	}

}


int
uinet_sosetsockopt(struct uinet_socket *so, int level, int optname, void *optval,
		   unsigned int optlen)
{
	return so_setsockopt((struct socket *)so, level, optname, optval, optlen);
}


int
uinet_sosettxif(struct uinet_socket *so, uinet_if_t uif)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int optval, optlen;

	optlen = sizeof(optval);
	optval = uif->ifp->if_index;
	return (so_setsockopt(so_internal, IPPROTO_IP, IP_TXIF, &optval, optlen));
}


void
uinet_sosetupcallprep(struct uinet_socket *so,
		      void (*soup_accept)(struct uinet_socket *, void *), void *soup_accept_arg,
		      void (*soup_receive)(struct uinet_socket *, void *, int64_t, int64_t), void *soup_receive_arg,
		      void (*soup_send)(struct uinet_socket *, void *, int64_t), void *soup_send_arg)
{
	struct socket *so_internal = (struct socket *)so;

	so_internal->so_upcallprep.soup_accept = (void (*)(struct socket *, void *))soup_accept;
	so_internal->so_upcallprep.soup_accept_arg = soup_accept_arg;
	so_internal->so_upcallprep.soup_receive = (void (*)(struct socket *, void *, int64_t, int64_t))soup_receive;
	so_internal->so_upcallprep.soup_receive_arg = soup_receive_arg;
	so_internal->so_upcallprep.soup_send = (void (*)(struct socket *, void *, int64_t))soup_send;
	so_internal->so_upcallprep.soup_send_arg = soup_send_arg;
}



int
uinet_sosend(struct uinet_socket *so, struct uinet_sockaddr *addr, struct uinet_uio *uio, int flags)
{
	struct iovec iov[uio->uio_iovcnt];
	struct uio uio_internal;
	int i;
	int result;

	for (i = 0; i < uio->uio_iovcnt; i++) {
		iov[i].iov_base = uio->uio_iov[i].iov_base;
		iov[i].iov_len = uio->uio_iov[i].iov_len;
	}
	uio_internal.uio_iov = iov;
	uio_internal.uio_iovcnt = uio->uio_iovcnt;
	uio_internal.uio_offset = uio->uio_offset;
	uio_internal.uio_resid = uio->uio_resid;
	uio_internal.uio_segflg = UIO_SYSSPACE;
	uio_internal.uio_rw = UIO_WRITE;
	uio_internal.uio_td = curthread;

	result = sosend((struct socket *)so, (struct sockaddr *)addr, &uio_internal, NULL, NULL, flags, curthread);

	uio->uio_resid = uio_internal.uio_resid;

	return (result);
}


int
uinet_soshutdown(struct uinet_socket *so, int how)
{
	return soshutdown((struct socket *)so, how);
}


int
uinet_sogetpeeraddr(struct uinet_socket *so, struct uinet_sockaddr **sa)
{
	struct socket *so_internal = (struct socket *)so;
	int rv;

	*sa = NULL;

	CURVNET_SET(so_internal->so_vnet);
	rv = (*so_internal->so_proto->pr_usrreqs->pru_peeraddr)(so_internal, (struct sockaddr **)sa);
	CURVNET_RESTORE();

	return (rv);
}


int
uinet_sogetsockaddr(struct uinet_socket *so, struct uinet_sockaddr **sa)
{
	struct socket *so_internal = (struct socket *)so;
	int rv;

	*sa = NULL;
	
	CURVNET_SET(so_internal->so_vnet);
	rv = (*so_internal->so_proto->pr_usrreqs->pru_sockaddr)(so_internal, (struct sockaddr **)sa);
	CURVNET_RESTORE();

	return (rv);
}


void
uinet_free_sockaddr(struct uinet_sockaddr *sa)
{
	free(sa, M_SONAME);
}


void
uinet_soupcall_lock(struct uinet_socket *so, int which)
{
	struct socket *so_internal = (struct socket *)so;
	struct sockbuf *sb;

	switch(which) {
	case UINET_SO_RCV:
		sb = &so_internal->so_rcv;
		break;
	case UINET_SO_SND:
		sb = &so_internal->so_snd;
		break;
	default:
		return;
	}
	
	CURVNET_SET(so_internal->so_vnet);
	SOCKBUF_LOCK(sb);
	CURVNET_RESTORE();
}


void
uinet_soupcall_unlock(struct uinet_socket *so, int which)
{
	struct socket *so_internal = (struct socket *)so;
	struct sockbuf *sb;

	switch(which) {
	case UINET_SO_RCV:
		sb = &so_internal->so_rcv;
		break;
	case UINET_SO_SND:
		sb = &so_internal->so_snd;
		break;
	default:
		return;
	}
	
	CURVNET_SET(so_internal->so_vnet);
	SOCKBUF_UNLOCK(sb);
	CURVNET_RESTORE();
}


void
uinet_soupcall_set(struct uinet_socket *so, int which,
		   int (*func)(struct uinet_socket *, void *, int), void *arg)
{
	struct socket *so_internal = (struct socket *)so;
	struct sockbuf *sb;

	switch(which) {
	case UINET_SO_RCV:
		sb = &so_internal->so_rcv;
		break;
	case UINET_SO_SND:
		sb = &so_internal->so_snd;
		break;
	default:
		return;
	}

	CURVNET_SET(so_internal->so_vnet);
	SOCKBUF_LOCK(sb);
	uinet_soupcall_set_locked(so, which, func, arg);
	SOCKBUF_UNLOCK(sb);
	CURVNET_RESTORE();
}


void
uinet_soupcall_set_locked(struct uinet_socket *so, int which,
			  int (*func)(struct uinet_socket *, void *, int), void *arg)
{
	struct socket *so_internal = (struct socket *)so;
	soupcall_set(so_internal, which, (int (*)(struct socket *, void *, int))func, arg);
}


void
uinet_soupcall_clear(struct uinet_socket *so, int which)
{
	struct socket *so_internal = (struct socket *)so;
	struct sockbuf *sb;

	switch(which) {
	case UINET_SO_RCV:
		sb = &so_internal->so_rcv;
		break;
	case UINET_SO_SND:
		sb = &so_internal->so_snd;
		break;
	default:
		return;
	}

	CURVNET_SET(so_internal->so_vnet);
	SOCKBUF_LOCK(sb);
	uinet_soupcall_clear_locked(so, which);
	SOCKBUF_UNLOCK(sb);
	CURVNET_RESTORE();
}


void
uinet_soupcall_clear_locked(struct uinet_socket *so, int which)
{
	struct socket *so_internal = (struct socket *)so;
	soupcall_clear(so_internal, which);
}


static int
uinet_api_synfilter_callback(struct inpcb *inp, void *inst_arg, struct syn_filter_cbarg *arg)
{
	struct uinet_api_synfilter_ctx *ctx = inst_arg;
	
	return (ctx->callback((struct uinet_socket *)inp->inp_socket, ctx->arg, arg));
}

static void *
uinet_api_synfilter_ctor(struct inpcb *inp, char *arg)
{
	void *result;
	memcpy(&result, arg, sizeof(result));
	return result;
}


static void
uinet_api_synfilter_dtor(struct inpcb *inp, void *arg)
{
	free(arg, M_DEVBUF);
}


static struct syn_filter synf_uinet_api = {
	"uinet_api",
	uinet_api_synfilter_callback,
	uinet_api_synfilter_ctor,
	uinet_api_synfilter_dtor,
};

static moduledata_t synf_uinet_api_mod = {
	"uinet_api_synf",
	syn_filter_generic_mod_event,
	&synf_uinet_api
};

DECLARE_MODULE(synf_uinet_api, synf_uinet_api_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);


uinet_synf_deferral_t
uinet_synfilter_deferral_alloc(struct uinet_socket *so, uinet_api_synfilter_cookie_t cookie)
{
	struct syn_filter_cbarg *cbarg = cookie;
	struct syn_filter_cbarg *result;
	
	/* XXX might want to get these from a pool for better speed */
	result = malloc(sizeof(*result), M_DEVBUF, M_WAITOK);
	*result = *cbarg;

	return result;
}


void
uinet_synfilter_deferral_free(uinet_synf_deferral_t deferral)
{
	free(deferral, M_DEVBUF);
}


uinet_api_synfilter_cookie_t
uinet_synfilter_deferral_get_cookie(uinet_synf_deferral_t deferral)
{
	return ((uinet_api_synfilter_cookie_t)deferral);
}


int
uinet_synfilter_deferral_deliver(struct uinet_socket *so, uinet_synf_deferral_t deferral, int decision)
{
	struct socket *so_internal = (struct socket *)so;
	struct syn_filter_cbarg *cbarg = deferral;
	int error;

	cbarg->decision = decision;
	error = so_setsockopt(so_internal, IPPROTO_IP, IP_SYNFILTER_RESULT, cbarg, sizeof(*cbarg));

	free(deferral, M_DEVBUF);
	
	return (error);
}


void
uinet_synfilter_getconninfo(uinet_api_synfilter_cookie_t cookie, struct uinet_in_conninfo *inc)
{
	struct syn_filter_cbarg *cbarg = cookie;
	memcpy(inc, &cbarg->inc, sizeof(struct uinet_in_conninfo));
}


void
uinet_synfilter_getl2info(uinet_api_synfilter_cookie_t cookie, struct uinet_in_l2info *l2i)
{
	struct syn_filter_cbarg *cbarg = cookie;

	memcpy(l2i, cbarg->l2i, sizeof(*l2i));
}


void
uinet_synfilter_setl2info(uinet_api_synfilter_cookie_t cookie, struct uinet_in_l2info *l2i)
{
	struct syn_filter_cbarg *cbarg = cookie;

	memcpy(cbarg->l2i, l2i, sizeof(*l2i));
}


void
uinet_synfilter_set_txif(uinet_api_synfilter_cookie_t cookie, uinet_if_t uif)
{
	struct syn_filter_cbarg *cbarg = cookie;
	
	cbarg->txif = uif->ifp;
}


void
uinet_synfilter_go_active_on_timeout(uinet_api_synfilter_cookie_t cookie, unsigned int ms)
{
	struct syn_filter_cbarg *cbarg = cookie;
	
	cbarg->inc.inc_flags |= INC_CONVONTMO;
	cbarg->initial_timeout = (ms > INT_MAX / hz) ? INT_MAX / 1000 : (ms * hz) / 1000;
}


int
uinet_synfilter_install(struct uinet_socket *so, uinet_api_synfilter_callback_t callback, void *arg)
{
	struct socket *so_internal = (struct socket *)so;
	struct uinet_api_synfilter_ctx *ctx;
	struct syn_filter_optarg synf;
	int error = 0;

	ctx = malloc(sizeof(*ctx), M_DEVBUF, M_WAITOK);
	ctx->callback = callback;
	ctx->arg = arg;

	memset(&synf, 0, sizeof(synf));
	strlcpy(synf.sfa_name, synf_uinet_api.synf_name, SYNF_NAME_MAX);
	memcpy(synf.sfa_arg, &ctx, sizeof(ctx));

	if ((error = so_setsockopt(so_internal, IPPROTO_IP, IP_SYNFILTER, &synf, sizeof(synf)))) {
		free(ctx, M_DEVBUF);
	}

	return (error);
}


int
uinet_sysctlbyname(uinet_instance_t uinst, const char *name, char *oldp, size_t *oldplen,
    const char *newp, size_t newplen, size_t *retval, int flags)
{
	int error;

	CURVNET_SET(uinst->ui_vnet);
	error = kernel_sysctlbyname(curthread, name, oldp, oldplen,
	    newp, newplen, retval, flags);
	CURVNET_RESTORE();
	return (error);
}


int
uinet_sysctl(uinet_instance_t uinst, const int *name, u_int namelen, void *oldp, size_t *oldplen,
    const void *newp, size_t newplen, size_t *retval, int flags)
{
	int error;

	CURVNET_SET(uinst->ui_vnet);
	error = kernel_sysctl(curthread, name, namelen, oldp, oldplen,
	    newp, newplen, retval, flags);
	CURVNET_RESTORE();
	return (error);
}


static int
uinet_pfil_hook_wrapper(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir,
			struct inpcb *inp)
{
	struct uinet_pfil_cb *cb = arg;
	struct ifl2info *l2i_tag;
	int result;

	l2i_tag = (struct ifl2info *)m_tag_locate(*mp,
						  MTAG_PROMISCINET,
						  MTAG_PROMISCINET_L2INFO,
						  NULL);

	result = cb->f(cb->arg, (struct uinet_mbuf **)mp, ifp ? uinet_iftouif(ifp)  : NULL, dir,
		       l2i_tag ? (struct uinet_in_l2info *)&l2i_tag->ifl2i_info : NULL);
	if (*mp == NULL)
		result = ENOBUFS;

	return (result);
}


int
uinet_pfil_add_hook(uinet_instance_t uinst, struct uinet_pfil_cb *cb, int af)
{
	int error;
	struct pfil_head *pfh;

	CURVNET_SET(uinst->ui_vnet);
	if (cb == NULL || cb->f == NULL) {
		CURVNET_RESTORE();
		return (EINVAL);
	}

	pfh = pfil_head_get(PFIL_TYPE_AF, af);
	if (pfh == NULL) {
		CURVNET_RESTORE();
		return (EINVAL);
	}

	error = pfil_add_hook(uinet_pfil_hook_wrapper, cb,
	    cb->flags | PFIL_WAITOK, pfh);

	CURVNET_RESTORE();
	return (error);
}


int
uinet_pfil_remove_hook(uinet_instance_t uinst, struct uinet_pfil_cb *cb, int af)
{
	int error;
	struct pfil_head *pfh;

	CURVNET_SET(uinst->ui_vnet);
	if (cb == NULL || cb->f == NULL) {
		CURVNET_RESTORE();
		return (EINVAL);
	}

	pfh = pfil_head_get(PFIL_TYPE_AF, af);
	if (pfh == NULL) {
		CURVNET_RESTORE();
		return (EINVAL);
	}

	error = pfil_remove_hook(uinet_pfil_hook_wrapper, cb,
	    cb->flags, pfh);

	CURVNET_RESTORE();
	return (error);
}


static VNET_DEFINE(uinet_pfil_cb_t, uinet_pfil_cb) = NULL;
#define V_uinet_pfil_cb VNET(uinet_pfil_cb)
static VNET_DEFINE(void *, uinet_pfil_cbdata) = NULL;
#define V_uinet_pfil_cbdata VNET(uinet_pfil_cbdata)
static VNET_DEFINE(struct ifnet *, uinet_pfil_ifp) = NULL;
#define V_uinet_pfil_ifp VNET(uinet_pfil_ifp)

/*
 * Hook for processing IPv4 frames.
 */
static int
uinet_pfil_in_hook_v4(void *arg, struct mbuf **m, struct ifnet *ifp, int dir,
    struct inpcb *inp)
{
	struct ifl2info *l2i_tag;
	struct uinet_in_l2info uinet_l2i;

	/*
	 * No hook? Turf out.
	 */
	if (V_uinet_pfil_cb == NULL)
		return (0);

	/*
	 * Check if the ifp matches the ifp name we're interested in.
	 * When doing bridging we will see incoming frames for the
	 * physical incoming interface (eg netmap0, netmap1) and
	 * the bridge interface (bridge0).  We may actually not want
	 * that.
	 */
	if (V_uinet_pfil_ifp && (V_uinet_pfil_ifp != ifp))
		return (0);

	/*
	 * See if there's L2 information for this frame.
	 */
	l2i_tag = (struct ifl2info *)m_tag_locate(*m,
	    MTAG_PROMISCINET,
	    MTAG_PROMISCINET_L2INFO,
	    NULL);

#if 0
	if (l2i_tag == NULL) {
		printf("%s: no L2 information\n",
		    __func__);
	} else {
		printf("%s: src=%s",
		    __func__,
		    ether_sprintf(l2i_tag->ifl2i_info.inl2i_local_addr));
		printf(" dst=%s\n",
		    ether_sprintf(l2i_tag->ifl2i_info.inl2i_foreign_addr));
	}
#endif

	/*
	 * Populate the libuinet L2 header type
	 *
	 * XXX this should be a method!
	 */
	if (l2i_tag != NULL)
		memcpy(&uinet_l2i, &l2i_tag->ifl2i_info, sizeof(uinet_l2i));

	/*
	 * Call our callback to process the frame
	 */
	V_uinet_pfil_cb((const struct uinet_mbuf *) *m,
	    l2i_tag != NULL ? &uinet_l2i : NULL);

	/* Pass all for now */
	return (0);
}

/*
 * Register a single hook for the AF_INET pfil.
 */
int
uinet_register_pfil_in(uinet_instance_t uinst, uinet_pfil_cb_t cb, void *arg, const char *ifname)
{
	int error;
	struct pfil_head *pfh;

	CURVNET_SET(uinst->ui_vnet);
	if (V_uinet_pfil_cb != NULL) {
		printf("%s: callback already registered in this instance!\n", __func__);
		CURVNET_RESTORE();
		return (-1);
	}

	V_uinet_pfil_cb = cb;
	V_uinet_pfil_cbdata = arg;

	/* Take a reference to the ifnet if we're interested in it */
	if (ifname != NULL) {
		V_uinet_pfil_ifp = ifunit_ref(ifname);
	}

	/* XXX TODO: ipv6 */
	pfh = pfil_head_get(PFIL_TYPE_AF, AF_INET);
	error = pfil_add_hook(uinet_pfil_in_hook_v4, NULL,
	    PFIL_IN | PFIL_WAITOK, pfh);

	CURVNET_RESTORE();
	return (0);
}

/*
 * Get a pointer to the given mbuf data.
 *
 * This only grabs the pointer to this first mbuf; not the whole
 * chain worth of data.  That's a different API (which likely should
 * be implemented at some point.)
 */
const char *
uinet_mbuf_data(const struct uinet_mbuf *m)
{
	const struct mbuf *mb = (const struct mbuf *) m;

	return mtod(mb, const char *);
}

size_t
uinet_mbuf_len(const struct uinet_mbuf *m)
{
	const struct mbuf *mb = (const struct mbuf *) m;

	return (mb->m_len);
}

/*
 * Queue this buffer for transmit.
 *
 * The transmit path will take a copy of the data; it won't reference it.
 *
 * Returns 0 on OK, non-zero on error.
 *
 * Note: this reaches into kernel code, so you need to have set up all
 * the possible transmit threads as uinet threads, or this call will
 * fail.
 */
int
uinet_if_xmit(uinet_if_t uif, const char *buf, int len)
{
	struct mbuf *m;
	struct ifnet *ifp;
	int retval;

	/* Create mbuf; populate it with the given buffer */
	m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (ENOBUFS);

	if (! m_append(m, (size_t) len, (const void *) buf)) {
		m_freem(m);
		return (ENOMEM);
	}

	/* Call if_transmit() on the given interface */
	ifp = uif->ifp;
	CURVNET_SET(ifp->if_vnet)
	retval = (ifp->if_transmit)(ifp, m);
	CURVNET_RESTORE();
	return (retval);
}

int
uinet_lock_log_set_file(const char *file)
{

	uhi_lock_log_set_file(file);
	return (0);
}

int
uinet_lock_log_enable(void)
{

	uhi_lock_log_enable();
	return (0);
}


int
uinet_lock_log_disable(void)
{

	uhi_lock_log_disable();
	return (0);
}


void
uinet_default_cfg(struct uinet_global_cfg *cfg, enum uinet_global_cfg_type which)
{
	switch (which) {
	case UINET_GLOBAL_CFG_SMALL:
		*cfg = (struct uinet_global_cfg) {
			.ncpus = 1,
			.netmap_extra_bufs = 1000,
			.epoch_number = 0,
			.kern = {
				.ipc = {
					.maxsockets = 1024,
					.nmbclusters = 4*1024,
					.somaxconn = 128,
				},
			},
			.net = {
				.inet = {
					.tcp = {
						.syncache = {
							.hashsize = 512,
							.bucketlimit = 30,
							.cachelimit = 15360, /* (512 * 30) */
						},
						.tcbhashsize = 512,
					},
				},
			},
		};
		break;
	default:
	case UINET_GLOBAL_CFG_MEDIUM:
		*cfg = (struct uinet_global_cfg) {
			.ncpus = 1,
			.netmap_extra_bufs = 10000,
			.kern = {
				.ipc = {
					.maxsockets = 128*1024,
					.nmbclusters = 128*1024,
					.somaxconn = 1024,
				},
			},
			.net = {
				.inet = {
					.tcp = {
						.syncache = {
							.hashsize = 2048,
							.bucketlimit = 30,
							.cachelimit = 61440, /* (2048 * 30) */
						},
						.tcbhashsize = 8192,
					},
				},
			},
		};
		break;
	case UINET_GLOBAL_CFG_LARGE:
		*cfg = (struct uinet_global_cfg) {
			.ncpus = 1,
			.netmap_extra_bufs = 40000,
			.kern = {
				.ipc = {
					.maxsockets = 256*1024,
					.nmbclusters = 512*1024,
					.somaxconn = 2048,
				},
			},
			.net = {
				.inet = {
					.tcp = {
						.syncache = {
							.hashsize = 4096,
							.bucketlimit = 30,
							.cachelimit = 122880, /* (4096 * 30) */
						},
						.tcbhashsize = 32768,
					},
				},
			},
		};
		break;
	}
}


void
uinet_print_cfg(struct uinet_global_cfg *cfg)
{
#define PRINT_TUNABLE(t) printf("%s=%u\n", #t, cfg->t)

	printf("ncpus=%u netmap_extra_bufs=%u\n", cfg->ncpus, cfg->netmap_extra_bufs);
	PRINT_TUNABLE(net.inet.tcp.syncache.hashsize);
	PRINT_TUNABLE(net.inet.tcp.syncache.bucketlimit);
	PRINT_TUNABLE(net.inet.tcp.syncache.cachelimit);
	PRINT_TUNABLE(net.inet.tcp.tcbhashsize);
	PRINT_TUNABLE(kern.ipc.maxsockets);
	PRINT_TUNABLE(kern.ipc.nmbclusters);
	PRINT_TUNABLE(kern.ipc.somaxconn);

#undef PRINT_TUNABLE	
}


void
uinet_instance_default_cfg(struct uinet_instance_cfg *cfg)
{
	memset(cfg, 0, sizeof(struct uinet_instance_cfg));
}

int
uinet_instance_init(struct uinet_instance *uinst, struct vnet *vnet,
		    struct uinet_instance_cfg *cfg)
{
	struct uinet_instance_cfg default_cfg;
	int error = 0;

	if (cfg == NULL) {
		uinet_instance_default_cfg(&default_cfg);
		cfg = &default_cfg;
	}

	uinst->ui_vnet = vnet;
	uinst->ui_vnet->vnet_uinet = uinst;
	uinst->ui_sts = cfg->sts;
	uinst->ui_userdata = cfg->userdata;
	uinst->ui_index = instance_count++;
	
	CURVNET_SET(uinst->ui_vnet);
	V_syncache_event_cb = (syncache_event_callback_t)(cfg->syncache_event_cb);
	V_syncache_event_cb_arg = cfg->syncache_event_cb_arg;
	CURVNET_RESTORE();

	/*
	 * Don't respond with a reset to TCP segments that the stack will
	 * not claim nor with an ICMP port unreachable message to UDP
	 * datagrams that the stack will not claim.
	 */
	uinet_config_blackhole(uinst, UINET_BLACKHOLE_TCP_ALL);
	uinet_config_blackhole(uinst, UINET_BLACKHOLE_UDP_ALL);

	if (cfg->loopback) {
		int error;

		uinet_interface_up(uinst, "lo0", 0, 0);

		if (0 != (error = uinet_interface_add_alias(uinst, "lo0", "127.0.0.1", "0.0.0.0", "255.0.0.0"))) {
			printf("Loopback alias add failed %d\n", error);
		}
	}

	if (uinst->ui_sts.sts_enabled) {
		uinst->ui_sts_evinstctx =
		    uinst->ui_sts.sts_instance_created_cb(uinst->ui_sts.sts_evctx, uinst);
		if (uinst->ui_sts_evinstctx == NULL)
			return (-1);
		
		vnet->vnet_sts.sts_event_notify     = cfg->sts.sts_instance_event_notify_cb;
		vnet->vnet_sts.sts_event_notify_arg = uinst->ui_sts_evinstctx;
	}

	return (error);
}


/*
 * This routine exists because for sts-mode vnets, the sts enable and
 * callout routines must be initialized before the VNET_SYSINITs are run
 * when the vnet is allocated because some VNET_SYSINITs configure callouts.
 * This routine is used to partially initialize a struct vnet_sts, which is
 * then passed to vnet_alloc().  The rest of the struct vnet_sts
 * initialization happens in uinet_instance_init() after the rest of the
 * uinet_instance_t construction has occurred, in part because the rest of
 * the struct vnet_sts initialization depends on information obtained from
 * the external event system at that point.
 *
 * Note that as vnet0 is allocated in a SYSINIT, the vnet0_sts structure
 * must be initialized by calling this routine in uinet_init() before the
 * SYSINITs are run.
 *
 */
void
uinet_instance_init_vnet_sts(struct vnet_sts *sts, struct uinet_instance_cfg *cfg)
{
	memset(sts, 0, sizeof(*sts));

	if (cfg == NULL)
		return;

	sts->sts_enabled            = cfg->sts.sts_enabled;
	sts->sts_callout_ctx        = cfg->sts.sts_evctx;
	sts->sts_callout_init       = cfg->sts.sts_callout_init;
	sts->sts_callout_reset      = cfg->sts.sts_callout_reset;
	sts->sts_callout_schedule   = cfg->sts.sts_callout_schedule;
	sts->sts_callout_pending    = cfg->sts.sts_callout_pending;
	sts->sts_callout_active     = cfg->sts.sts_callout_active;
	sts->sts_callout_deactivate = cfg->sts.sts_callout_deactivate;
	sts->sts_callout_msecs_remaining = cfg->sts.sts_callout_msecs_remaining;
	sts->sts_callout_stop       = cfg->sts.sts_callout_stop;
	sts->sts_event_notify       = cfg->sts.sts_instance_event_notify_cb;

	/*
	 * The rest of the struct vnet_sts is initialized in
	 * uinet_instance_init().
	 *
	 * sts->sts_event_notify     = ...
	 * sts->sts_event_notify_arg = ...
	 */
}


uinet_instance_t
uinet_instance_create(struct uinet_instance_cfg *cfg)
{
#ifdef VIMAGE
	struct uinet_instance *uinst;
	struct vnet *vnet;
	struct vnet_sts sts;

	uinst = malloc(sizeof(struct uinet_instance), M_DEVBUF, M_WAITOK);
	if (uinst != NULL) {
		uinet_instance_init_vnet_sts(&sts, cfg);
		vnet = vnet_alloc(&sts);
		if (vnet == NULL) {
			free(uinst, M_DEVBUF);
			return (NULL);
		}

		if (-1 == uinet_instance_init(uinst, vnet, cfg)) {
			vnet_destroy(vnet);
			free(uinst, M_DEVBUF);
			return (NULL);
		}
	}

	return (uinst);
#else
	return (NULL);  /* XXX use uinst0 instead of NULL? */
#endif
}


uinet_instance_t
uinet_instance_default(void)
{
	return (&uinst0);
}


unsigned int
uinet_instance_sts_enabled(uinet_instance_t uinst)
{
	return uinst->ui_sts.sts_enabled;
}

void
uinet_instance_sts_events_process(uinet_instance_t uinst)
{
	vnet_sts_events_process(uinst->ui_vnet);
}

uint32_t
uinet_instance_index(uinet_instance_t uinst)
{
	return (uinst ? uinst->ui_index : 0);
}

unsigned int
uinet_sts_callout_max_size(void)
{
	return (VNET_CALLOUT_SIZE);
}

void
uinet_instance_shutdown(uinet_instance_t uinst)
{
	uinet_ifdestroy_all(uinst);
}


void
uinet_instance_destroy(uinet_instance_t uinst)
{
	KASSERT(uinst != uinet_instance_default(), ("uinet_instance_destroy: cannot destroy default instance"));
#ifdef VIMAGE
	if (uinst->ui_sts.sts_enabled)
		uinst->ui_sts.sts_instance_destroyed_cb(uinst->ui_sts_evinstctx);

	uinet_instance_shutdown(uinst);
	vnet_destroy(uinst->ui_vnet);
	free(uinst, M_DEVBUF);
#endif
}


void
uinet_if_default_config(uinet_iftype_t type, struct uinet_if_cfg *cfg)
{
	const struct uinet_if_type_info *ti;

	ti = uinet_if_get_type_info(type);
	if (ti && cfg) {
		cfg->type = type;
		cfg->configstr = NULL;
		cfg->alias = NULL;
		cfg->rx_cpu = -1;
		cfg->tx_cpu = -1;
		cfg->rx_batch_size = 512;
		cfg->tx_inject_queue_len = 2048;
		cfg->first_look_handler = NULL;
		cfg->first_look_handler_arg = NULL;
		cfg->timestamp_mode = UINET_IF_TIMESTAMP_NONE;

		if (ti->default_cfg)
			ti->default_cfg(&cfg->type_cfg);
	}
}


int
uinet_if_set_batch_event_handler(uinet_if_t uif,
				 void (*handler)(void *arg, int event),
				 void *arg)
{
	int error = EINVAL;

	if (NULL != uif) {
		uif->batch_event_handler = handler;
		uif->batch_event_handler_arg = arg;
		error = 0;
	}

	return (error);
}


struct uinet_pd_list *
uinet_pd_list_alloc(uint32_t num_descs)
{
	struct uinet_pd_list *list;

	list = malloc(sizeof(*list) + num_descs * sizeof(struct uinet_pd),
		      M_DEVBUF, M_WAITOK);
	if (list == NULL)
		return (NULL);

	list->num_descs = num_descs;
	return (list);
}


void
uinet_pd_list_free(struct uinet_pd_list *list)
{
	free(list, M_DEVBUF);
}


void
uinet_if_pd_alloc(uinet_if_t uif, struct uinet_pd_list *pkts)
{
	UIF_PD_ALLOC(uif, pkts);
}


void
uinet_if_inject_tx_packets(uinet_if_t uif, struct uinet_pd_list *pkts)
{
	UIF_INJECT_TX(uif, pkts);
}


unsigned int
uinet_if_batch_rx(uinet_if_t uif, int *fd, uint64_t *wait_ns)
{
	return (UIF_BATCH_RX(uif, fd, wait_ns));
}


unsigned int
uinet_if_batch_tx(uinet_if_t uif, int *fd, uint64_t *wait_ns)
{
	return (UIF_BATCH_TX(uif, fd, wait_ns));
}


/*
 * Increment the refcount of each packet descriptor as required based on the
 * descriptor flags.  This routine does not atomically increment the
 * refcounts as it is meant to be used in first-look handler implementations
 * - it is only safe to use to adjust the refcounts of packet descriptors
 * that have a refcount of one (meaning the caller is the owner of the sole
 * reference to the descriptor).
 *
 * num_extra is the number of extra refs needed beyond what would be
 * required for passage to the stack and/or injection to a single interface.
 * This routine correctly adds any needed refs for passage to the stack
 * and/or injection to a single interface, based on the UINET_PD_INJECT and
 * UINET_PD_TO_STACK flags and only needs to be informed about refs required
 * above and beyond those.
 *
 * The idea is that you mark the packet descriptors as required for
 * injection and passage to the stack, you set UINET_PD_EXTRA_REFS if you
 * want to tx-inject the packet into more that one interface or need
 * additional refs for application use, then you call this routine with
 * num_extra set to the number additional tx-injection interfaces above 1
 * plus the number of application refs, and voila, the refs are correctly
 * set.
 */
void
uinet_pd_ref_acquire(struct uinet_pd_list *pkts, unsigned int num_extra)
{
	struct uinet_pd *pd;
	unsigned int refs;
	uint32_t i;

	for (i = 0; i < pkts->num_descs; i++) {
		pd = &pkts->descs[i];

		if (pd->flags & UINET_PD_MGMT_ONLY)
			continue;

		/*
		 * If the packet is to be both injected into the transmit
		 * path of another interface and sent to the stack, one
		 * extra ref is needed.  If neither or only one of those
		 * actions is to be taken, no extra refs are needed.
		 */
		refs = ((pd->flags & (UINET_PD_INJECT|UINET_PD_TO_STACK)) ==
			(UINET_PD_INJECT|UINET_PD_TO_STACK));

		if (pd->flags & UINET_PD_EXTRA_REFS)
			refs += num_extra;

		/*
		 * Only perform the increment if refs is non-zero to avoid
		 * pulling packet descriptor context, and possibly external
		 * refcount storage, into the cache unnecessarily.
		 */
		if (refs) {
			pd->ctx->flags &= ~UINET_PD_CTX_SINGLE_REF;
			*(pd->ctx->refcnt) += refs;
		}
	}
}


void
uinet_pd_ref_release(struct uinet_pd_ctx *pdctx[], uint32_t n)
{
	uint32_t i;
	struct uinet_pd_ctx *cur_pdctx;
	struct uinet_pd_ctx *free_group[UINET_PD_FREE_BATCH_SIZE];
	struct uinet_pd_pool_info *pool;
	unsigned int cur_pool_id;
	uint32_t free_group_count;

	/*
	 * The list of packet descriptor contexts to free will in general
	 * contain packet descriptor contexts originating from different
	 * pools and having different reference counts.  This implementation
	 * will batch up sequential (not necessarily consecutive) packet
	 * descriptor contexts in the list that are from the same pool and
	 * are ready to be freed and will free them in a single operation.
	 */

	cur_pool_id = 0xffffffff;
	free_group_count = 0;
	for (i = 0; i < n; i++) {
		cur_pdctx = pdctx[i];

		/*
		 * The test for UINET_PD_CTX_SINGLE_REF is first so that
		 * when it is set, the potentially costly refcnt derefence
		 * (cache miss) and atomic_fetchadd() (inter-cpu coherency
		 * op) are avoided.
		 */
		if ((cur_pdctx->flags & UINET_PD_CTX_SINGLE_REF) ||
		    (*(cur_pdctx->refcnt) == 1) ||
		    (atomic_fetchadd_int(cur_pdctx->refcnt, -1) == 1)) {
			if ((cur_pdctx->pool_id != cur_pool_id) ||
			    (free_group_count == UINET_PD_FREE_BATCH_SIZE)) {
				if (free_group_count) {
					pool = uinet_pd_pool_get(cur_pool_id);
					pool->free(free_group, free_group_count);
					free_group_count = 0;
				}
				cur_pool_id = cur_pdctx->pool_id;
			}
			free_group[free_group_count++] = cur_pdctx;
		}
	}
	if (free_group_count) {
		pool = uinet_pd_pool_get(cur_pool_id);
		pool->free(free_group, free_group_count);
	}
}


void
uinet_pd_deliver_to_stack(struct uinet_if *uif, struct uinet_pd_list *pkts)
{
	struct ifnet *ifp;
	struct uinet_pd *pd;
	struct uinet_pd_ctx *pdctx;
	struct mbuf *m;
	uint32_t i;

	ifp = uif->ifp;
	for (i = 0; i < pkts->num_descs; i++) {
		pd = &pkts->descs[i];

		if (pd->flags & UINET_PD_TO_STACK) {
			pdctx = pd->ctx;
			pdctx->flags &= ~UINET_PD_CTX_SINGLE_REF;  /* no telling how many refs the stack will add */
			pdctx->flags |= UINET_PD_CTX_MBUF_USED;
			pdctx->m_orig_len = pd->length;
			m = pdctx->m;
			m->m_pkthdr.len = m->m_len = pd->length;
			m->m_pkthdr.rcvif = ifp;
			ifp->if_input(ifp, m);
		}
	}
}


void
uinet_pd_drop(struct uinet_pd_list *pkts)
{
	uint32_t i;
	struct uinet_pd *pd;
	struct uinet_pd_ctx *pdctx;
	struct uinet_pd_ctx *free_group[UINET_PD_FREE_BATCH_SIZE];
	struct uinet_pd_pool_info *pool;
	unsigned int cur_pool_id;
	uint32_t free_group_count;

	/*
	 * The list of packet descriptor contexts to free will in general
	 * contain packet descriptor contexts originating from different
	 * pools.  This implementation will batch up sequential (not
	 * necessarily consecutive) packet descriptor contexts in the list
	 * that are from the same pool and are marked for drop and will free
	 * them in a single operation.
	 */
	pd = &pkts->descs[0];
	cur_pool_id = 0xffffffff;
	free_group_count = 0;
	for (i = 0; i < pkts->num_descs; i++, pd++) {
		if (pd->flags & UINET_PD_DROP) {
			pdctx = pd->ctx;
			if ((pdctx->pool_id != cur_pool_id) ||
			    (free_group_count == UINET_PD_FREE_BATCH_SIZE)) {
				if (free_group_count) {
					pool = uinet_pd_pool_get(cur_pool_id);
					pool->free(free_group, free_group_count);
					free_group_count = 0;
				}
				cur_pool_id = pdctx->pool_id;
			}
			free_group[free_group_count++] = pdctx;
		}
	}
	if (free_group_count) {
		pool = uinet_pd_pool_get(cur_pool_id);
		pool->free(free_group, free_group_count);
	}
}
