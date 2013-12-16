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
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_promisc.h>

#include "uinet_api.h"
#include "uinet_config_internal.h"
#include "uinet_host_interface.h"

#include "opt_inet6.h"


extern struct thread *uinet_thread_alloc(struct proc *p);


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
uinet_initialize_thread(void)
{
	struct thread *td;

	if (NULL == uhi_thread_get_thread_specific_data()) {
		td = uinet_thread_alloc(NULL);
		if (NULL == td)
			return (ENOMEM);
		
		td->td_proc = &proc0;

		KASSERT(sizeof(td->td_wchan) >= sizeof(uhi_thread_t), ("uinet_initialize_thread: can't safely store host thread id"));
		td->td_wchan = (void *)uhi_thread_self();

		uhi_thread_set_thread_specific_data(td);
	}

	return (0);
}


void
uinet_finalize_thread(void)
{
	struct thread *td = curthread;
	
	free(td, M_TEMP);
}


char *
uinet_inet_ntoa(struct uinet_in_addr in, char *buf, unsigned int size)
{
	(void)size;

	return inet_ntoa_r(*((struct in_addr *)&in), buf); 
}


int
uinet_inet_pton(int af, const char *src, void *dst)
{
	return (inet_pton(af, src, dst));
}


static int
uinet_ifconfig_begin(struct socket **so, struct ifreq *ifr, const char *name)
{
	struct thread *td = curthread;
	struct uinet_config_if *ifcfg;
	int error;

	ifcfg = uinet_iffind_byname(name);
	if (NULL == ifcfg) {
		printf("could not find interface %s\n", name);
		return (EINVAL);
	}

	printf("found interface %s (ifname=%s alias=%s)\n", name, ifcfg->name, ifcfg->alias);

	error = socreate(PF_INET, so, SOCK_DGRAM, 0, td->td_ucred, td);
	if (0 != error) {
		printf("ifconfig socket creation failed (%d)\n", error);
		return (error);
	}

	snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", ifcfg->name);
	
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
uinet_interface_add_alias(const char *name, const char *addr, const char *braddr, const char *mask)
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
	error = uinet_ifconfig_begin(&cfg_so, (struct ifreq *)&ina, name);
	if (0 != error) {
		return (error);
	}

	ina.ifra_addr = template;
	if (inet_pton(AF_INET, addr, &ina.ifra_addr.sin_addr) <= 0) {
		error = EAFNOSUPPORT;
		goto out;
	}

	ina.ifra_broadaddr = template;
	if (inet_pton(AF_INET, braddr, &ina.ifra_broadaddr.sin_addr) <= 0) {
		error = EAFNOSUPPORT;
		goto out;
	}

	ina.ifra_mask = template;
	if (inet_pton(AF_INET, mask, &ina.ifra_mask.sin_addr) <= 0) {
		error = EAFNOSUPPORT;
		goto out;
	}

	error = uinet_ifconfig_do(cfg_so, SIOCAIFADDR, &ina);

out:
	uinet_ifconfig_end(cfg_so);

	return (error);
}


int
uinet_interface_create(const char *name)
{
	struct socket *cfg_so;
	struct ifreq ifr;
	int error;

	error = uinet_ifconfig_begin(&cfg_so, &ifr, name);
	if (0 != error)
		return (error);

	error = uinet_ifconfig_do(cfg_so, SIOCIFCREATE, &ifr);

	uinet_ifconfig_end(cfg_so);

	return (error);
}


int
uinet_interface_up(const char *name, unsigned int promisc)
{
	struct socket *cfg_so;
	struct ifreq ifr;
	int error;

	error = uinet_ifconfig_begin(&cfg_so, &ifr, name);
	if (0 != error)
		return (error);
	
	/* set interface to UP */

	error = uinet_ifconfig_do(cfg_so, SIOCGIFFLAGS, &ifr);
	if (0 == error) {
		ifr.ifr_flags |= IFF_UP;
		if (promisc)
			ifr.ifr_flagshigh |= (IFF_PPROMISC | IFF_PROMISCINET) >> 16;
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
uinet_make_socket_promiscuous(struct uinet_socket *so, unsigned int fib)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int optval, optlen;
	int error;

	optlen = sizeof(optval);

	optval = 1;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_PROMISC, &optval, optlen)))
		goto out;
	
	optval = fib;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_SETFIB, &optval, optlen)))
		goto out;

	optval = 1;
	if ((error = so_setsockopt(so_internal, SOL_SOCKET, SO_REUSEPORT, &optval, optlen)))
		goto out;
	
	optval = 1;
	if ((error = so_setsockopt(so_internal, IPPROTO_IP, IP_BINDANY, &optval, optlen)))
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
uinet_setl2info(struct uinet_socket *so, struct uinet_in_l2info *l2i)
{
	struct socket *so_internal = (struct socket *)so;
	int error = 0;

	error = so_setsockopt(so_internal, SOL_SOCKET, SO_L2INFO, l2i, sizeof(*l2i));

	return (error);
}


int
uinet_setl2info2(struct uinet_socket *so, uint8_t *local_addr, uint8_t *foreign_addr,
		 uint16_t flags, struct uinet_in_l2tagstack *tagstack)
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
	struct sockaddr *sa = NULL;
	int error;

	if (nam)
		*nam = NULL;

	*aso = NULL;

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
		error = msleep(&head->so_timeo, &accept_mtx, PSOCK | PCATCH,
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
	ACCEPT_UNLOCK();

	error = soaccept(so, &sa);
	if (error) {
		soclose(so);
		return (error);
	}

	if (nam) {
		*nam = (struct uinet_sockaddr *)sa;
		sa = NULL;
	}

	*aso = (struct uinet_socket *)so;

noconnection:
	if (sa)
		free(sa, M_SONAME);

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
bad:
	if (!interrupted)
		so->so_state &= ~SS_ISCONNECTING;
	if (error == ERESTART)
		error = EINTR;
done1:
	return (error);
}


int
uinet_socreate(int dom, struct uinet_socket **aso, int type, int proto)
{
	struct thread *td = curthread;

	return socreate(dom, (struct socket **)aso, type, proto, td->td_ucred, td);
}


void
uinet_sogetconninfo(struct uinet_socket *so, struct uinet_in_conninfo *inc)
{
	struct socket *so_internal = (struct socket *)so;
	struct inpcb *inp = sotoinpcb(so_internal);

	/* XXX do we really need the INFO lock here? */
	INP_INFO_RLOCK(inp->inp_pcbinfo);
	INP_RLOCK(inp);
	memcpy(inc, &sotoinpcb(so_internal)->inp_inc, sizeof(struct uinet_in_conninfo));
	INP_RUNLOCK(inp);
	INP_INFO_RUNLOCK(inp->inp_pcbinfo);
}


int
uinet_sogeterror(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;

	return (so_internal->so_error);
}


unsigned int
uinet_sogetrxavail(struct uinet_socket *so)
{
	struct socket *so_internal = (struct socket *)so;
	unsigned int avail;

	SOCKBUF_LOCK(&so_internal->so_rcv);
	avail = so_internal->so_rcv.sb_cc;
	SOCKBUF_UNLOCK(&so_internal->so_rcv);

	return avail;
}


int
uinet_sogetsockopt(struct uinet_socket *so, int level, int optname, void *optval,
		   unsigned int *optlen)
{
	size_t local_optlen;
	int result;

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

	*sa = NULL;
	return (*so_internal->so_proto->pr_usrreqs->pru_peeraddr)(so_internal, (struct sockaddr **)sa);
}


int
uinet_sogetsockaddr(struct uinet_socket *so, struct uinet_sockaddr **sa)
{
	struct socket *so_internal = (struct socket *)so;

	*sa = NULL;
	return (*so_internal->so_proto->pr_usrreqs->pru_sockaddr)(so_internal, (struct sockaddr **)sa);
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
	
	SOCKBUF_LOCK(sb);
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
	
	SOCKBUF_UNLOCK(sb);
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

	SOCKBUF_LOCK(sb);
	uinet_soupcall_set_locked(so, which, func, arg);
	SOCKBUF_UNLOCK(sb);
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

	SOCKBUF_LOCK(sb);
	uinet_soupcall_clear_locked(so, which);
	SOCKBUF_UNLOCK(sb);

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





