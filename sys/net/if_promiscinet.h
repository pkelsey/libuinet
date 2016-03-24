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

#ifndef _NET_IF_PROMISCINET_H_
#define _NET_IF_PROMISCINET_H_


#ifdef _KERNEL

#include <sys/mbuf.h>

#include <vm/uma.h>


#include <net/ethernet.h>
#include <netinet/in_promisc.h>


#define MTAG_PROMISCINET	1366240237
#define MTAG_PROMISCINET_L2INFO	0


#define IF_PROMISCINET_MAX_ETHER_VLANS	IN_L2INFO_MAX_TAGS

struct ifl2info {
	struct m_tag ifl2i_mtag;	/* must be first in the struct */
	struct ifnet *rcvif;
	struct in_l2info ifl2i_info;
};

#define MTAG_PROMISCINET_L2INFO_LEN (sizeof(struct ifl2info) - sizeof(struct m_tag))


extern uma_zone_t if_promiscinet_tag_zone;


int if_promiscinet_add_tag(struct mbuf *m, struct in_l2info *l2i);
static __inline struct ifl2info *if_promiscinet_tag_alloc(void);

static __inline struct ifl2info *
if_promiscinet_tag_alloc(void)
{

	return (uma_zalloc(if_promiscinet_tag_zone, 0));
}



#endif /* _KERNEL */

#endif /* !_NET_IF_PROMISCINET_H_ */
