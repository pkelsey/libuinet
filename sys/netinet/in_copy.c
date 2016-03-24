/*-
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


#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_copy.h>
#include <netinet/in_pcb.h>

#include "uinet_if.h"
#include "uinet_pkt_desc.h"


void
in_copy(struct inpcb *inp, struct mbuf *m)
{
	if (inp->inp_copy_mode & IP_COPY_MODE_RX) {
		while (m && (!inp->inp_copy_limit ||
			     (inp->inp_copy_total < inp->inp_copy_limit))) {
			inp->inp_copy_total +=
			    uinet_pd_xlist_add_mbuf(&inp->inp_copyq, &inp->inp_copyq_tail,
						    m, UINET_PD_INJECT, inp->inp_serialno);

			/* If mode is ON, flush whenever the vector fills. */
			if ((inp->inp_copy_mode & IP_COPY_MODE_ON) &&
			    inp->inp_copyq &&
			    (inp->inp_copyq->list.num_descs == UINET_PD_XLIST_MAX_DESCS)) {
				in_copy_flush(inp, 0);
			}
			m = m->m_next;
		}
	}
}


void
in_copy_dispose(struct inpcb *inp)
{
	uinet_pd_xlist_release_all(inp->inp_copyq);
	inp->inp_copyq = inp->inp_copyq_tail =
	    uinet_pd_xlist_free(inp->inp_copyq, NULL);
}


/*
 * Flush queued descriptors to the copy-to interface if one is defined,
 * otherwise release the references to them, and release uinet_pd_xlist
 * entries.
 *
 * If 'finished' is zero, then only the full uinet_pd_xlist entries are
 * flushed and disposed of, otherwise all entries are flushed and disposed
 * of.
 */
void
in_copy_flush(struct inpcb *inp, unsigned int finished)
{
	struct uinet_pd_xlist *cur;
	struct uinet_if *uif;
	unsigned int injected;
	struct uinet_pd_list_single flush_list;
	
	uif = inp->inp_copyif ? uinet_iftouif(inp->inp_copyif) : NULL;
	cur = inp->inp_copyq;
	injected = 0;
	while (cur &&
	       ((cur->list.num_descs == UINET_PD_XLIST_MAX_DESCS) ||
		finished)) {
		if (cur->list.num_descs > 0) {
			if (uif) {
				/*
				 * Mark the last descriptor with the flush
				 * flag.  Because the xlists are allocated
				 * on demand and only one empty xlist is
				 * retained when doing a non-finish flush,
				 * either there's a single empty xlist or
				 * the last xlist in the chain contains the
				 * last descriptor.
				 */
				if (finished && (cur->next == NULL))
					cur->list.descs[cur->list.num_descs - 1].flags |= UINET_PD_FLUSH_FLOW;
				UIF_INJECT_TX(uif, &cur->list);
				injected = 1;
			} else
				uinet_pd_xlist_release(cur);
		}
		cur = cur->next;
	}
	inp->inp_copyq = inp->inp_copyq_tail =
	    uinet_pd_xlist_free(inp->inp_copyq, cur);

	/*
	 * If we are doing a finish flush, we haven't injected anything
	 * above (which means we didn't have the opportunity to mark the
	 * last descriptor with the flush flag), there's an interface to
	 * inject to and we've replicated at least one packet, inject a
	 * flush pd.
	 */
	if (finished && !injected && uif && (inp->inp_copy_total > 0)) {
		flush_list.num_descs = 1;
		flush_list.descs[0].flags = UINET_PD_INJECT | UINET_PD_FLUSH_FLOW | UINET_PD_MGMT_ONLY;
		flush_list.descs[0].serialno = inp->inp_serialno;
		UIF_INJECT_TX(uif, (struct uinet_pd_list *)&flush_list);
	}
}
