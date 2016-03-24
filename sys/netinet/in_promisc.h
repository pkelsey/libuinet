/*-
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
 *  Userland interface for Promiscuous INET functionality.
 */

#ifndef _NETINET_IN_PROMISC_H_
#define _NETINET_IN_PROMISC_H_

#include <sys/module.h>
#include <sys/socketvar.h>

#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>


#define IN_PROMISC_PORT_ANY	0


/* N.B. The code in ether_input_internal() assumes the source and
 * destination MAC addresses, the maximum number of VLAN tags that can fit
 * in IN_L2INFO_TAG_DATA_MAX, and one following EtherType field can fit
 * within the MHLEN data bytes of an M_PKTHDR mbuf.  As of this writing,
 * that means IN_L2INFO_MAX_TAGS should be less than about 154/4 = 38.
 */
#define IN_L2INFO_MAX_TAGS	16
#define IN_L2INFO_ADDR_MAX	ETHER_ADDR_LEN

struct in_l2tagstack {
	uint16_t inl2t_cnt;		/* number of tags stored in
					 * inl2t_tags */
	uint32_t inl2t_masks[IN_L2INFO_MAX_TAGS]; /* per-tag masks, in
						   * network byte order, to
						   * be applied during
						   * hashing and comparing */
	uint32_t inl2t_tags[IN_L2INFO_MAX_TAGS]; /* in network byte order */
};


/* flags for inl2i_flags */
#define INL2I_TAG_ANY		0x01

struct in_l2info {
	uint8_t inl2i_local_addr[IN_L2INFO_ADDR_MAX];
	uint8_t inl2i_foreign_addr[IN_L2INFO_ADDR_MAX];
	uint16_t inl2i_flags;
	struct in_l2tagstack inl2i_tagstack;
};


/*
 * Via the IP_SYNFILTER option, a SYN filter can be set on a PF_INET,
 * SOCK_STREAM listen socket that has the SO_PROMISC option set.  It will be
 * invoked on each arriving SYN that matches the listen criteria and isn't
 * already in the SYN cache in order to determine whether to respond to the
 * SYN or discard it.
 *
 * SYN filters are modeled on accept filters.
 */

#define SYNF_NAME_MAX		16	/* including trailing '\0' */
#define SYNF_ARG_STRUCT_MAX	256
#define SYNF_ARG_MAX		(SYNF_ARG_STRUCT_MAX - SYNF_NAME_MAX)

struct syn_filter_optarg {
	char	sfa_name[SYNF_NAME_MAX];	/* Name of SYN filter to attach to socket. */
	char	sfa_arg[SYNF_ARG_MAX];		/* Arg passed to SYN filter
						 * constructor, which uses
						 * the value to create the
						 * instance-specific arg
						 * passed to each invocation
						 * of the syn filter on this
						 * socket.
						 */
};


struct syn_filter_cbarg {
	struct in_conninfo inc;
	struct tcpopt to;
	struct tcphdr th;
	
	// XXX mbuf should be tracked with a cookie that is then passed back to user space,
	// XXX and l2i should be a copy, not a pointer, if IP_SYNFILTER_RESULT is ever to be used
	// XXX from user space
	struct mbuf *m;		/*
				 * If the listen socket is closed before the
				 * SYN filter renders a deferred decision,
				 * the filter must free this mbuf.
				 */
	struct in_l2info *l2i;
	int decision;
	int initial_timeout;	/* modified syncache timeout for passive-to-active-on-timeout */
	struct ifnet *txif;	/* interface to use for syncache responses after a passive-to-active transition */
};


#ifdef _KERNEL

struct syn_filter {
	char	synf_name[SYNF_NAME_MAX];

	/*
	 * This callback passes judgment on every original SYN heard by a
	 * listening promiscuous socket.  Runs with INP_RLOCK(inp) held.
	 */
#define SYNF_ACCEPT		0	/* Process SYN normally */
#define SYNF_ACCEPT_PASSIVE	1	/* Process SYN for passive reassembly */
#define SYNF_REJECT_RST		2	/* Discard SYN, send RST */
#define SYNF_REJECT_SILENT	3	/* Discard SYN silently */
#define SYNF_DEFER		4	/* Decision will be returned later via setsockopt() */
	int	(*synf_callback)(struct inpcb *inp, void *inst_arg,
				 struct syn_filter_cbarg *arg);

	/*
	 * SYN filter instance constructor - provided arg is sfa_arg from
	 * the setsockopt() call and it runs with INP_WLOCK(inp) held.
	 * Returns a pointer to be passed as arg parameter of synf_callback,
	 * with NULL indicating failure.
	 */
	void *	(*synf_create)
		(struct inpcb *inp, char *arg);

	/*
	 * SYN filter instance destructor.  Runs with INP_WLOCK(inp) held.
	 * arg is the value returned by the instance constructor.
	 */
	void	(*synf_destroy)
		(struct inpcb *inp, void *arg);
};

struct in_l2info *in_promisc_l2info_alloc(int flags);
void in_promisc_l2info_free(struct in_l2info *l2info);
void in_promisc_l2info_copy(struct in_l2info *dst, const struct in_l2info *src);
void in_promisc_l2info_copy_swap(struct in_l2info *dst, const struct in_l2info *src);
void in_promisc_l2tagstack_copy(struct in_l2tagstack *dst, const struct in_l2tagstack *src);
int in_promisc_tagcmp(const struct in_l2tagstack *l2ts1, const struct in_l2tagstack *l2ts2);
int in_promisc_socket_init(struct socket *so, int flags);
void in_promisc_socket_destroy(struct socket *so);
void in_promisc_socket_newconn(struct socket *head, struct socket *so);
int in_promisc_inpcb_init(struct inpcb *inp, int flags);
void in_promisc_inpcb_destroy(struct inpcb *inp);

int syn_filter_generic_mod_event(module_t mod, int event, void *data);
int syn_filter_getopt(struct socket *so, struct sockopt *sopt);
int syn_filter_setopt(struct socket *so, struct sockopt *sopt);
int syn_filter_run_callback(struct inpcb *inp, struct syn_filter_cbarg *arg);

uint32_t in_promisc_hash32(const uint32_t *key, const uint32_t *masks, int nblocks, uint32_t seed);

#endif /* _KERNEL */

#endif /* !_NETINET_IN_PROMISC_H_ */
