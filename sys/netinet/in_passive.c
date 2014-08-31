/*-
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

/*
 * Kernel support routines for Passive INET functionality.
 */

#include "opt_passiveinet.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <vm/uma.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_passive.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/tcp_var.h>



int
in_passive_inpcb_init(struct inpcb *inp, int flags)
{

	if (inp->inp_socket->so_options & SO_PASSIVE)
		inp->inp_flags2 |= INP_PASSIVE;

	return (0);
}


/* Consistently order a coupled pair of passive-reassembly sockets */
static void
in_passive_ordered_socks(struct socket *so, struct socket **primary_so,
			 struct socket **secondary_so)
{
	if (so->so_options & SO_PASSIVECLNT) {
		*primary_so = so->so_passive_peer;
		*secondary_so = so;
	} else {
		*primary_so = so;
		*secondary_so = so->so_passive_peer;
	}
}


static void
in_passive_ordered_inps(struct socket *so, struct inpcb **primary_inp,
			struct inpcb **secondary_inp)
{
	struct socket *primary_so;
	struct socket *secondary_so;

	in_passive_ordered_socks(so, &primary_so, &secondary_so);

	*primary_inp = sotoinpcb(primary_so);
	*secondary_inp = sotoinpcb(secondary_so);
}


void
in_passive_acquire_locks(struct socket *so)
{
	struct inpcb *primary_inp;
	struct inpcb *secondary_inp;

	in_passive_ordered_inps(so, &primary_inp, &secondary_inp);

	INP_WLOCK(primary_inp);
	INP_WLOCK(secondary_inp);
}


void
in_passive_release_locks(struct socket *so)
{
	struct inpcb *primary_inp;
	struct inpcb *secondary_inp;

	in_passive_ordered_inps(so, &primary_inp, &secondary_inp);

	INP_WUNLOCK(secondary_inp);
	INP_WUNLOCK(primary_inp);
}


void
in_passive_acquire_sock_locks(struct socket *so)
{
	struct socket *primary_so;
	struct socket *secondary_so;

	in_passive_ordered_socks(so, &primary_so, &secondary_so);

	SOCK_LOCK(primary_so);
	SOCK_LOCK(secondary_so);
}


void
in_passive_release_sock_locks(struct socket *so)
{
	struct socket *primary_so;
	struct socket *secondary_so;

	in_passive_ordered_socks(so, &primary_so, &secondary_so);

	SOCK_UNLOCK(secondary_so);
	SOCK_UNLOCK(primary_so);
}


void
in_passive_convert_to_active(struct socket *so)
{
	struct socket *peer_so;
	struct inpcb *inp;
	struct inpcb *peer_inp;
	struct tcpcb *tp;
	struct tcpcb *peertp;

	peer_so = so->so_passive_peer;

	inp = sotoinpcb(so);
	peer_inp = sotoinpcb(peer_so);

	INP_WLOCK_ASSERT(inp);
	INP_WLOCK_ASSERT(peer_inp);

	tp = intotcpcb(inp);
	peertp = intotcpcb(peer_inp);

	inp->inp_flags2 &= ~INP_PASSIVE;
	peer_inp->inp_flags2 &= ~INP_PASSIVE;

	in_passive_acquire_sock_locks(so);
	so->so_options &= ~(SO_PASSIVE|SO_PASSIVECLNT);
	peer_so->so_options &= ~(SO_PASSIVE|SO_PASSIVECLNT);
	in_passive_release_sock_locks(so);

	tp->snd_una = peertp->rcv_nxt;
	tp->snd_max = peertp->rcv_nxt;
	tp->snd_nxt = peertp->rcv_nxt;

	/*
	 * Turn off sending of timestamps.  In order to send proper
	 * timestamps (at a minimum, ones that won't fail checks at the
	 * receiver), when they are being used by the endpoint we are taking
	 * over as, we have to:
	 *
	 *   1. Figure out the tick rate that endpoint was using
	 *
	 *   2. Properly update last_ack based on ACKs seen on the other
	 *      passively reassembled connection so that we correctly update
	 *      ts_recent on our flow.
	 *
	 *  Accomplishing (1) is not terrible, but would require at least
	 *  two timestamp-bearing segments to be seen from a given endpoint
	 *  in order to estimate its tick rate.  Estimating the tick rate of
	 *  the server would require one timestamped post-handshake segment
	 *  to be seen, so we'd have to do without timestamps in at least
	 *  the case where such a segment has not yet arrived.
	 *
	 *  Accomplishing (2) would rather expensively couple the two flows,
	 *  and we'd still have to deal with relative-order-of-events issues
	 *  in the sequence of events we see in our passive reassembly
	 *  versus what the endpoints themselves see.
	 *
	 *  Given the above, the fact that sending timestamps is optional
	 *  even when they are requested, and that the connections from this
	 *  point on are expected to be short lived, it seems better just to
	 *  avoid timestamps entirely.
	 */
	tp->t_flags &= ~TF_RCVD_TSTMP;

	peertp->snd_una = tp->rcv_nxt;
	peertp->snd_max = tp->rcv_nxt;
	peertp->snd_nxt = tp->rcv_nxt;

	/* See above treatise on timestamps */
	peertp->t_flags &= ~TF_RCVD_TSTMP;

	/* Send an RST to the endpoint we will be impersonating. */
	if (tcp_drop(peertp, ECONNABORTED))
		INP_WUNLOCK(peer_inp);
}
