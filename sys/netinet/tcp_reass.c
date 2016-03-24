/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp_input.c	8.12 (Berkeley) 5/24/95
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.1.0/sys/netinet/tcp_reass.c 228058 2011-11-28 11:10:12Z lstewart $");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_tcpdebug.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <vm/uma.h>

#include <net/if.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_options.h>
#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet6/tcp6_var.h>
#include <netinet/tcpip.h>
#ifdef TCPDEBUG
#include <netinet/tcp_debug.h>
#endif /* TCPDEBUG */

static int tcp_reass_sysctl_maxseg(SYSCTL_HANDLER_ARGS);
static int tcp_reass_sysctl_qsize(SYSCTL_HANDLER_ARGS);

SYSCTL_NODE(_net_inet_tcp, OID_AUTO, reass, CTLFLAG_RW, 0,
    "TCP Segment Reassembly Queue");

static VNET_DEFINE(int, tcp_reass_maxseg) = 0;
#define	V_tcp_reass_maxseg		VNET(tcp_reass_maxseg)
SYSCTL_VNET_PROC(_net_inet_tcp_reass, OID_AUTO, maxsegments,
    CTLTYPE_INT | CTLFLAG_RDTUN,
    &VNET_NAME(tcp_reass_maxseg), 0, &tcp_reass_sysctl_maxseg, "I",
    "Global maximum number of TCP Segments in Reassembly Queue");

static VNET_DEFINE(int, tcp_reass_qsize) = 0;
#define	V_tcp_reass_qsize		VNET(tcp_reass_qsize)
SYSCTL_VNET_PROC(_net_inet_tcp_reass, OID_AUTO, cursegments,
    CTLTYPE_INT | CTLFLAG_RD,
    &VNET_NAME(tcp_reass_qsize), 0, &tcp_reass_sysctl_qsize, "I",
    "Global number of TCP Segments currently in Reassembly Queue");

static VNET_DEFINE(int, tcp_reass_overflows) = 0;
#define	V_tcp_reass_overflows		VNET(tcp_reass_overflows)
SYSCTL_VNET_INT(_net_inet_tcp_reass, OID_AUTO, overflows,
    CTLTYPE_INT | CTLFLAG_RD,
    &VNET_NAME(tcp_reass_overflows), 0,
    "Global number of TCP Segment Reassembly Queue Overflows");

static VNET_DEFINE(uma_zone_t, tcp_reass_zone);
#define	V_tcp_reass_zone		VNET(tcp_reass_zone)

/* Initialize TCP reassembly queue */
static void
tcp_reass_zone_change(void *tag)
{

	V_tcp_reass_maxseg = nmbclusters / 16;
	uma_zone_set_max(V_tcp_reass_zone, V_tcp_reass_maxseg);
}

void
tcp_reass_init(void)
{

	V_tcp_reass_maxseg = nmbclusters / 16;
	TUNABLE_INT_FETCH("net.inet.tcp.reass.maxsegments",
	    &V_tcp_reass_maxseg);
	V_tcp_reass_zone = uma_zcreate("tcpreass", sizeof (struct tseg_qent),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	uma_zone_set_max(V_tcp_reass_zone, V_tcp_reass_maxseg);
	EVENTHANDLER_REGISTER(nmbclusters_change,
	    tcp_reass_zone_change, NULL, EVENTHANDLER_PRI_ANY);
}

#ifdef VIMAGE
void
tcp_reass_destroy(void)
{

	uma_zdestroy(V_tcp_reass_zone);
}
#endif

void
tcp_reass_flush(struct tcpcb *tp)
{
	struct tseg_qent *qe;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	while ((qe = LIST_FIRST(&tp->t_segq)) != NULL) {
		LIST_REMOVE(qe, tqe_q);
		m_freem(qe->tqe_m);
		uma_zfree(V_tcp_reass_zone, qe);
		tp->t_segqlen--;
	}

	KASSERT((tp->t_segqlen == 0),
	    ("TCP reass queue %p segment count is %d instead of 0 after flush.",
	    tp, tp->t_segqlen));
}

static int
tcp_reass_sysctl_maxseg(SYSCTL_HANDLER_ARGS)
{
	V_tcp_reass_maxseg = uma_zone_get_max(V_tcp_reass_zone);
	return (sysctl_handle_int(oidp, arg1, arg2, req));
}

static int
tcp_reass_sysctl_qsize(SYSCTL_HANDLER_ARGS)
{
	V_tcp_reass_qsize = uma_zone_get_cur(V_tcp_reass_zone);
	return (sysctl_handle_int(oidp, arg1, arg2, req));
}

#ifdef PASSIVE_INET
static int
tcp_reass_next_hole_deadline(struct tcpcb *tp)
{
	struct tseg_qent *q;
	int delta;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	q = TAILQ_FIRST(&tp->t_segageq);
	if (q) {
		delta = ticks - q->tqe_ticks;
		if (delta < TP_REASSDL(tp)) {
			return (TP_REASSDL(tp) - delta);
		} else {
			return (1);
		}
	}

	return (0);
}

void
tcp_reass_deliver_holes(struct tcpcb *tp)
{
	struct socket *so = tp->t_inpcb->inp_socket;
	struct tseg_qent *q, *p, *qtmp;
	int delta;
	int hole_size;
	struct mbuf *m_hole;
	int contiguous;

	INP_WLOCK_ASSERT(tp->t_inpcb);

	/* Search into the sequence space for the furthest expired segment. */
	p = NULL;
	LIST_FOREACH(q, &tp->t_segq, tqe_q) {
		delta = ticks - q->tqe_ticks;
		if (delta >= TP_REASSDL(tp))
			p = q;
	}

	if (p) {
		contiguous = 0;
		LIST_FOREACH_SAFE(q, &tp->t_segq, tqe_q, qtmp) {
			if (contiguous && q->tqe_seq != tp->rcv_nxt)
				break;

			SOCKBUF_LOCK(&so->so_rcv);

			if (!(so->so_rcv.sb_state & SBS_CANTRCVMORE)) {
				hole_size = q->tqe_seq - tp->rcv_nxt;
				if (hole_size) {
					if (hole_size < 0) {
						panic("%s: hole_size=%d, should be >= 0\n", __func__, hole_size);
					}

					m_hole = m_gethole(M_NOWAIT, MT_DATA);
					m_hole->m_len = hole_size;
					
					/* XXX any reasonable way to ensure this doesn't happen or have a better outcome if it does? */
					KASSERT(m_hole != NULL, ("%s: mbuf allocation for hole failed", __func__));

					sbappendstream_locked(&so->so_rcv, m_hole);
				}
			}

			tp->rcv_nxt = q->tqe_seq + q->tqe_len;

			LIST_REMOVE(q, tqe_q);
			TAILQ_REMOVE(&tp->t_segageq, q, tqe_ageq);

			if (so->so_rcv.sb_state & SBS_CANTRCVMORE)
				m_freem(q->tqe_m);
			else
				sbappendstream_locked(&so->so_rcv, q->tqe_m);

			SOCKBUF_UNLOCK(&so->so_rcv);

			if (q->tqe_flags & TH_FIN) {
				socantrcvmore(so);
				tp->rcv_nxt++;

				switch (tp->t_state) {
				case TCPS_SYN_RECEIVED:
					tp->t_starttime = ticks;
					/* FALLTHROUGH */
				case TCPS_ESTABLISHED:
					tp->t_state = TCPS_CLOSE_WAIT;
					break;
				case TCPS_FIN_WAIT_1:
					tp->t_state = TCPS_CLOSING;
					break;
				case TCPS_FIN_WAIT_2:
#if 0
					INP_INFO_WLOCK_ASSERT(&V_tcbinfo);
					KASSERT(ti_locked == TI_WLOCKED,
						("%s: dodata "
						 "TCP_FIN_WAIT_2 ti_locked: %d", __func__,
						 ti_locked));
					
					tcp_twstart(tp);
					INP_INFO_WUNLOCK(&V_tcbinfo);
#else
					printf(">>>>>>>>>>>>>>>> enter TIME WAIT\n");
#endif
					break;
				}
			}

			tp->t_segqlen--;
			if (q == p) {
				contiguous = 1;
			}

			uma_zfree(V_tcp_reass_zone, q);
		}

		tcp_timer_activate(tp, TT_REASSDL, tcp_reass_next_hole_deadline(tp));

		ND6_HINT(tp);
		sorwakeup(so);  /* XXX should we only wakeup if we delivered data and didn't determine cantrcvmore? */
	}
}
#endif /* PASSIVE_INET */

int
tcp_reass(struct tcpcb *tp, struct tcphdr *th, int *tlenp, struct mbuf *m)
{
	struct tseg_qent *q;
	struct tseg_qent *p = NULL;
	struct tseg_qent *nq;
	struct tseg_qent *te = NULL;
	struct socket *so = tp->t_inpcb->inp_socket;
	char *s = NULL;
	int flags;
	struct tseg_qent tqs;
#ifdef PASSIVE_INET
	int deliver_leading_hole = 0;
	int replace_tqs_in_list = 0;
	int passive;
	int hole_size;
	struct mbuf *m_hole;
	struct tseg_qent *reclaimed_tqe = NULL;
#endif

	INP_WLOCK_ASSERT(tp->t_inpcb);

#ifdef PASSIVE_INET
	passive = tp->t_inpcb->inp_flags2 & INP_PASSIVE;
#endif

	/*
	 * XXX: tcp_reass() is rather inefficient with its data structures
	 * and should be rewritten (see NetBSD for optimizations).
	 */

	/*
	 * Call with th==NULL after become established to
	 * force pre-ESTABLISHED data up to user socket.
	 */
	if (th == NULL)
		goto present;

	/*
	 * Limit the number of segments that can be queued to reduce the
	 * potential for mbuf exhaustion. For best performance, we want to be
	 * able to queue a full window's worth of segments. The size of the
	 * socket receive buffer determines our advertised window and grows
	 * automatically when socket buffer autotuning is enabled. Use it as the
	 * basis for our queue limit.
	 * Always let the missing segment through which caused this queue.
	 * NB: Access to the socket buffer is left intentionally unlocked as we
	 * can tolerate stale information here.
	 *
	 * XXXLAS: Using sbspace(so->so_rcv) instead of so->so_rcv.sb_hiwat
	 * should work but causes packets to be dropped when they shouldn't.
	 * Investigate why and re-evaluate the below limit after the behaviour
	 * is understood.
	 */

	if ((th->th_seq != tp->rcv_nxt || !TCPS_HAVEESTABLISHED(tp->t_state)) &&
	    tp->t_segqlen >= (so->so_rcv.sb_hiwat / tp->t_maxseg) + 1) {
		V_tcp_reass_overflows++;
#ifdef PASSIVE_INET
		/*
		 * In the passive case, we will deliver the leading hole and
		 * the first queue entry in response to the resource
		 * shortage, instead of dropping the current packet.
		 * Dropping the current packet isn't a winning strategy here
		 * - as passive observers of the packet stream, retransmits
		 * will not occur due to our drops.
		 */
		if (passive)
			deliver_leading_hole = 1;
		else {
#endif
			TCPSTAT_INC(tcps_rcvmemdrop);
			m_freem(m);
			*tlenp = 0;
			if ((s = tcp_log_addrs(&tp->t_inpcb->inp_inc, th, NULL, NULL))) {
				log(LOG_DEBUG, "%s; %s: queue limit reached, "
				    "segment dropped\n", s, __func__);
				free(s, M_TCPLOG);
			}
			return (0);
#ifdef PASSIVE_INET
		}
#endif
	}

	/*
	 * Allocate a new queue entry. If we can't, or hit the zone limit
	 * just drop the pkt.
	 *
	 * Use a temporary structure on the stack for the missing segment
	 * when the zone is exhausted. Otherwise we may get stuck.
	 */
	te = uma_zalloc(V_tcp_reass_zone, M_NOWAIT);
	if (te == NULL) {
		if (th->th_seq != tp->rcv_nxt || !TCPS_HAVEESTABLISHED(tp->t_state)) {
#ifdef PASSIVE_INET
			/*
			 * In the passive case, we will deliver the leading
			 * hole and the first queue entry in response to the
			 * resource shortage, instead of dropping the
			 * current packet.  Dropping the current packet
			 * isn't a winning strategy here - as passive
			 * observers of the packet stream, retransmits will
			 * not occur due to our drops.
			 */
			if (passive)
				deliver_leading_hole = 1;
			else {
#endif
				TCPSTAT_INC(tcps_rcvmemdrop);
				m_freem(m);
				*tlenp = 0;
				if ((s = tcp_log_addrs(&tp->t_inpcb->inp_inc, th, NULL,
						       NULL))) {
					log(LOG_DEBUG, "%s; %s: global zone limit "
					    "reached, segment dropped\n", s, __func__);
					free(s, M_TCPLOG);
				}
				return (0);
#ifdef PASSIVE_INET
			}
#endif
		}
		
		bzero(&tqs, sizeof(struct tseg_qent));
		te = &tqs;
		if ((s = tcp_log_addrs(&tp->t_inpcb->inp_inc, th, NULL,
				       NULL))) {
			log(LOG_DEBUG,
			    "%s; %s: global zone limit reached, using "
			    "stack for missing segment\n", s, __func__);
			free(s, M_TCPLOG);
		}
	}
	tp->t_segqlen++;

	/*
	 * Find a segment which begins after this one does.
	 */
	LIST_FOREACH(q, &tp->t_segq, tqe_q) {
		if (SEQ_GT(q->tqe_seq, th->th_seq))
			break;
		p = q;
	}

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
	 */
	if (p != NULL) {
		int i;
		/* conversion to int (in i) handles seq wraparound */
		i = p->tqe_seq + p->tqe_len - th->th_seq;
		if (i > 0) {
			if (i >= *tlenp) {
				TCPSTAT_INC(tcps_rcvduppack);
				TCPSTAT_ADD(tcps_rcvdupbyte, *tlenp);
				m_freem(m);
				if (te != &tqs)
					uma_zfree(V_tcp_reass_zone, te);
				tp->t_segqlen--;
				/*
				 * Try to present any queued data
				 * at the left window edge to the user.
				 * This is needed after the 3-WHS
				 * completes.
				 */
				goto present;	/* ??? */
			}
			m_adj(m, i);
			*tlenp -= i;
			th->th_seq += i;
		}
	}
	tp->t_rcvoopack++;
	TCPSTAT_INC(tcps_rcvoopack);
	TCPSTAT_ADD(tcps_rcvoobyte, *tlenp);

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	while (q) {
		int i = (th->th_seq + *tlenp) - q->tqe_seq;
		if (i <= 0)
			break;
		if (i < q->tqe_len) {
			q->tqe_seq += i;
			q->tqe_len -= i;
			m_adj(q->tqe_m, i);
			break;
		}

		nq = LIST_NEXT(q, tqe_q);
		LIST_REMOVE(q, tqe_q);
		m_freem(q->tqe_m);
		uma_zfree(V_tcp_reass_zone, q);
		tp->t_segqlen--;
		q = nq;
	}

	/* Insert the new segment queue entry into place. */
	te->tqe_m = m;
	te->tqe_seq = th->th_seq;
	te->tqe_flags = th->th_flags;
	te->tqe_len = *tlenp;
#ifdef PASSIVE_INET
	te->tqe_ticks = ticks;

	TAILQ_INSERT_TAIL(&tp->t_segageq, te, tqe_ageq);
#endif

	if (p == NULL) {
		LIST_INSERT_HEAD(&tp->t_segq, te, tqe_q);
	} else {
#ifdef PASSIVE_INET
		if (passive && te == &tqs)
			replace_tqs_in_list = 1;
		else {
#endif
			KASSERT(te != &tqs, ("%s: temporary stack based entry not "
					     "first element in queue", __func__));
#ifdef PASSIVE_INET
		}
#endif
		LIST_INSERT_AFTER(p, te, tqe_q);
	}

present:
	/*
	 * Present data to user, advancing rcv_nxt through
	 * completed sequence space.
	 */
	if (!TCPS_HAVEESTABLISHED(tp->t_state))
		return (0);
	q = LIST_FIRST(&tp->t_segq);
#ifdef PASSIVE_INET
	if (!q || (q->tqe_seq != tp->rcv_nxt && !deliver_leading_hole)) {
		if (passive && q && q->tqe_seq != tp->rcv_nxt) {
			tcp_timer_activate(tp, TT_REASSDL, tcp_reass_next_hole_deadline(tp));
		}
		return (0);
	}
#else
	if (!q || q->tqe_seq != tp->rcv_nxt)
		return (0);
#endif
	SOCKBUF_LOCK(&so->so_rcv);
#ifdef PASSIVE_INET
	if (deliver_leading_hole) {
		if (!(so->so_rcv.sb_state & SBS_CANTRCVMORE)) {
			hole_size = q->tqe_seq - tp->rcv_nxt;

			m_hole = m_gethole(M_NOWAIT, MT_DATA);
			m_hole->m_len = hole_size;

			/* XXX any reasonable way to ensure this doesn't happen or have a better outcome if it does? */
			KASSERT(m_hole != NULL, ("%s: mbuf allocation for hole failed", __func__));

			sbappendstream_locked(&so->so_rcv, m_hole);
		}
		tp->rcv_nxt = q->tqe_seq;
	}	
#endif
	do {
		tp->rcv_nxt += q->tqe_len;
		flags = q->tqe_flags & TH_FIN;
		nq = LIST_NEXT(q, tqe_q);
		LIST_REMOVE(q, tqe_q);
#ifdef PASSIVE_INET
		TAILQ_REMOVE(&tp->t_segageq, q, tqe_ageq);
#endif
		if (so->so_rcv.sb_state & SBS_CANTRCVMORE)
			m_freem(q->tqe_m);
		else
			sbappendstream_locked(&so->so_rcv, q->tqe_m);
		if (q != &tqs) {
#ifdef PASSIVE_INET
			if (replace_tqs_in_list && !reclaimed_tqe)
				reclaimed_tqe = q;
			else
#endif
				uma_zfree(V_tcp_reass_zone, q);
		}
#ifdef PASSIVE_INET
		else
			replace_tqs_in_list = 0;
#endif
		tp->t_segqlen--;
		q = nq;
	} while (q && q->tqe_seq == tp->rcv_nxt);
#ifdef PASSIVE_INET
	if (replace_tqs_in_list) {
		*reclaimed_tqe = tqs;
		LIST_INSERT_AFTER(&tqs, reclaimed_tqe, tqe_q);
		LIST_REMOVE(&tqs, tqe_q);

		TAILQ_INSERT_AFTER(&tp->t_segageq, &tqs, reclaimed_tqe, tqe_ageq);
		TAILQ_REMOVE(&tp->t_segageq, &tqs, tqe_ageq);
	}

	int next_deadline = tcp_reass_next_hole_deadline(tp);
	if (!tcp_timer_active(tp, TT_REASSDL) || next_deadline == 0)
		tcp_timer_activate(tp, TT_REASSDL, next_deadline);
#endif
	ND6_HINT(tp);
	sorwakeup_locked(so);
	return (flags);
}
