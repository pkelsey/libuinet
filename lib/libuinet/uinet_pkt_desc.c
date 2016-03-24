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


#include <sys/ctype.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>

#include <vm/uma.h>

#include "uinet_api.h"
#include "uinet_pkt_desc.h"

static void uinet_pd_mbuf_free_ctx(struct uinet_pd_ctx *pdctx);

static uma_zone_t zone_pd_mbuf_ctx;
static struct uinet_pd_pool_info pd_mbuf_ctx_pool = {
	.type = UINET_PD_TYPE_MBUF,
	.bufsize = MCLBYTES,
	.ctx = NULL,
	.free = uinet_pd_mbuf_free_descs
};
static unsigned int pd_mbuf_ctx_pool_id;

#define UINET_PD_MAX_POOLS	32

static struct uinet_pd_pool_info *pd_pool_table[UINET_PD_MAX_POOLS];

static uma_zone_t zone_pd_xlist;


/*
 * The pool of UINET_PD_MBUF type packet descriptors uses pre-allcoated
 * cluster mbufs to provide both the mbuf packet header and the packet
 * buffer.  The struct uinet_pd_ctx shares the reference count with mbuf
 * cluster, using the refcount storage already allocated for the cluster.
 * The mbufs are configured so that when processed by the usual mbuf
 * machinery, the refcount on the cluster will be decremented as usual, and
 * when the last reference is released, our pool free routine will be
 * invoked and the mbuf header will *not* be disposed of, allowing us to
 * reinitialze it and put it back in our pool for reuse.
 *
 * This pool, once warmed up, replaces otherwise separate and recurring
 * struct uinet_pd_ctx and cluster mbuf allocations with recurring struct
 * uinet_pd_ctx allocations and mbuf header initializations.
 */

/*
 * A UINET_PD_MBUF type packet descriptor is freed via this routine if the
 * final reference is released via the mbuf api.
 */
static void
uinet_pd_mbuf_ext_free(void *arg1, void *arg2)
{
	struct uinet_pd_ctx *pdctx;

	pdctx = arg1;
	uinet_pd_mbuf_free_ctx(pdctx);
}


static int
uinet_pd_mbuf_zinit_pd_ctx(void *mem, int size, int how)
{
	struct uinet_pd_ctx *pdctx;
	struct mbuf *m;

	pdctx = (struct uinet_pd_ctx *)mem;
	
	/* get an mbuf with cluster from zone_pack */
	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (ENOMEM);

	/* call the free routine when the last reference is released */
	m->m_ext.ext_type = EXT_EXTREF;
	m->m_ext.ext_free = uinet_pd_mbuf_ext_free;
	m->m_ext.ext_arg2 = pdctx;

	pdctx->m = m;
	pdctx->refcnt = m->m_ext.ref_cnt;
	pdctx->pool_id = pd_mbuf_ctx_pool_id;

	return (0);
}


static void
uinet_pd_mbuf_zfini_pd_ctx(void *mem, int size)
{
	struct uinet_pd_ctx *pdctx;
	struct mbuf *m;

	pdctx = (struct uinet_pd_ctx *)mem;
	m = pdctx->m;

	/*
	 * Restore the m_ext settings to what is expected of an mbuf in
	 * zone_pack and return the mbuf to that zone.
	 */
	m->m_ext.ext_type = EXT_PACKET;	
	m->m_ext.ext_free = NULL;
	m->m_ext.ext_arg2 = NULL;

	/* mb_free_ext(), case EXT_PACKET */
	if (*(m->m_ext.ref_cnt) == 0)
		*(m->m_ext.ref_cnt) = 1;
	uma_zfree(zone_pack, m);
}


static int
uinet_pd_mbuf_ctor_pd_ctx(void *mem, int size, void *arg, int how)
{
	struct uinet_pd_ctx *pdctx;
	struct mbuf *m;
	int error;

	pdctx = (struct uinet_pd_ctx *)mem;
	m = pdctx->m;

	/*
	 * Reset fields that may have been adjusted the last time the
	 * descriptor was in use.
	 */

	/* Do this first as it resets m_data and we override below */
	error = m_pkthdr_init(m, how);
	if (error)
		return error;

	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_data = m->m_ext.ext_buf;
	m->m_len = 0;

	/* Set M_NOFREE so mbuf machinery doesn't free the mbuf. */
	m->m_flags = (M_PKTHDR | M_NOFREE | M_EXT);
	m->m_type = MT_DATA;

	pdctx->flags = UINET_PD_CTX_SINGLE_REF;
	pdctx->timestamp = 0;
	*(pdctx->refcnt) = 1;

	return (0);
}


static void
uinet_pd_mbuf_dtor_pd_ctx(void *mem, int size, void *arg)
{
	struct uinet_pd_ctx *pdctx;
	struct mbuf *m;

	pdctx = (struct uinet_pd_ctx *)mem;
	m = pdctx->m;

	/*
	 * Remove any tags that were attached to the mbuf
	 *
	 * XXX could avoid deallocating and reallocating the l2tag by leaving it attached here
	 * but that would require adding and plumbing through a valid flag in the l2tag as 
	 * currently its presence on an mbuf indicates its validity
	 */
	if ((m->m_flags & M_PKTHDR) != 0)
		m_tag_delete_chain(m, NULL);
}


static void
uinet_pd_mbuf_init(const void *unused __unused)
{
	/* register pool before creating zone so pool id is valid during zone init. */
	pd_mbuf_ctx_pool_id = uinet_pd_pool_register(&pd_mbuf_ctx_pool);

	zone_pd_mbuf_ctx = uma_zcreate("pd_mbuf_ctx", sizeof(struct uinet_pd_ctx),
				       uinet_pd_mbuf_ctor_pd_ctx, uinet_pd_mbuf_dtor_pd_ctx,
				       uinet_pd_mbuf_zinit_pd_ctx, uinet_pd_mbuf_zfini_pd_ctx,
				       UMA_ALIGN_PTR, 0);
}
SYSINIT(uinet_pd_mbuf_init, SI_SUB_INIT_IF, SI_ORDER_ANY, uinet_pd_mbuf_init, 0);



/*
 * XXX currently assumes all table mods occur in a single thread and there
 * are no outstanding references to a given table slot at the time it is
 * cleared 
 */
int
uinet_pd_pool_register(struct uinet_pd_pool_info *pool_info)
{
	unsigned int i;

	for (i = 0; i < UINET_PD_MAX_POOLS; i++)
		if (pd_pool_table[i] == NULL) {
			pd_pool_table[i] = pool_info;
			return (i);
		}

	return (-1);
}


struct uinet_pd_pool_info *
uinet_pd_pool_get(unsigned int pool_id)
{
	return (pd_pool_table[pool_id]);
}


void
uinet_pd_pool_deregister(unsigned int pool_id)
{
	pd_pool_table[pool_id] = NULL;
}


/*
 *  Attempt to allocate n mbuf packet descriptors.  The data buffers are
 *  mbuf clusters and the packet descriptor reference counters are the same
 *  as the ones allocated with the clusters.
 */
unsigned int
uinet_pd_mbuf_alloc_descs(struct uinet_pd_list *to, uint32_t n)
{
	uint32_t i;
	struct uinet_pd_ctx *pdctx;
	struct uinet_pd *pd;

	/* add to end of list */
	pd = &to->descs[to->num_descs];
	for (i = 0; i < n; i++, pd++) {
		pdctx = uma_zalloc(zone_pd_mbuf_ctx, M_NOWAIT);
		if (pdctx == NULL)
			break;

		pd->flags = UINET_PD_TYPE_MBUF;
		pd->length = MCLBYTES;
		pd->pool_id = pdctx->pool_id;
		pd->ref = (uintptr_t)pdctx->m;
		pd->data = mtod(pdctx->m, void *);
		pd->ctx = pdctx;
	}
	to->num_descs += i;

	return i;
}


static void
uinet_pd_mbuf_free_ctx(struct uinet_pd_ctx *pdctx)
{
	uma_zfree(zone_pd_mbuf_ctx, pdctx);
}


void
uinet_pd_mbuf_free_descs(struct uinet_pd_ctx *pdctx[], unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		uinet_pd_mbuf_free_ctx(pdctx[i]);
}


struct uinet_pd_ring *
uinet_pd_ring_alloc(uint32_t num_descs)
{
	struct uinet_pd_ring *ring;

	if (num_descs == 0)
		num_descs = 1;

	ring = malloc(sizeof(*ring) + num_descs * sizeof(struct uinet_pd),
		      M_DEVBUF, M_WAITOK);
	if (ring == NULL)
		return (ring);

	ring->num_descs = num_descs;
	ring->put = 0;
	ring->take = 0;
	ring->drops = 0;

	return (ring);
}


void
uinet_pd_ring_free(struct uinet_pd_ring *ring)
{
	free(ring, M_DEVBUF);
}


void
uinet_pd_drop_injected(struct uinet_pd *pd, uint32_t n)
{
	uint32_t i;
	struct uinet_pd *cur_pd;
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
		cur_pd = &pd[i];
		cur_pdctx = cur_pd->ctx;
		if ((cur_pd->flags & UINET_PD_INJECT) &&
		    ((cur_pdctx->flags & UINET_PD_CTX_SINGLE_REF) ||
		     (*(cur_pdctx->refcnt) == 1) ||
		     (atomic_fetchadd_int(cur_pdctx->refcnt, -1) == 1))) {
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


static int
uinet_pd_xlist_pool_ctor(void *mem, int size, void *arg, int how)
{
	struct uinet_pd_xlist *xlist;

	xlist = (struct uinet_pd_xlist *)mem;
	xlist->next = NULL;
	xlist->list.num_descs = 0;

	return (0);
}


static void
uinet_pd_xlist_pool_init(const void *unused __unused)
{
	zone_pd_xlist = uma_zcreate("pd_xlist", sizeof(struct uinet_pd_xlist) + sizeof(struct uinet_pd) * UINET_PD_XLIST_MAX_DESCS,
				    uinet_pd_xlist_pool_ctor, NULL,
				    NULL, NULL,
				    UMA_ALIGN_PTR, 0);
}
SYSINIT(uinet_pd_xlist_pool_init, SI_SUB_INIT_IF, SI_ORDER_ANY, uinet_pd_xlist_pool_init, 0);


struct uinet_pd_xlist *
uinet_pd_xlist_pool_alloc(void)
{
	return uma_zalloc(zone_pd_xlist, M_NOWAIT);
}


void
uinet_pd_xlist_pool_free(struct uinet_pd_xlist *xlist)
{
	uma_zfree(zone_pd_xlist, xlist);
}


int
uinet_pd_xlist_add_mbuf(struct uinet_pd_xlist **head, struct uinet_pd_xlist **tail,
			struct mbuf *m, uint16_t flags, uint64_t serialno)
{
	struct uinet_pd_xlist *cur;
	struct uinet_pd *pd;
	struct uinet_pd_ctx *pdctx;
	uint64_t total_bytes;

	total_bytes = 0;
	cur = *tail;
	if ((cur == NULL) || (cur->list.num_descs == UINET_PD_XLIST_MAX_DESCS)) {
		cur = uinet_pd_xlist_pool_alloc();
		if (cur == NULL)
			return (1);
		if (*tail)
			(*tail)->next = cur;
		*tail = cur;
		if (*head == NULL)
			*head = cur;
	}

	/*
	 * The pdctx pointer is always in ext_arg2, regardless of pool of
	 * origin.
	 */
	pdctx = m->m_ext.ext_arg2;
	pd = &cur->list.descs[cur->list.num_descs];
	cur->list.num_descs++;
	pd->flags = UINET_PD_CTX_MBUF_USED | flags;
	pd->length = pdctx->m_orig_len;
	pd->pool_id = pdctx->pool_id;
	pd->ref = pdctx->ref;
	pd->data = (uint32_t *)m->m_ext.ext_buf;
	pd->ctx = pdctx;
	pd->serialno = serialno;

	atomic_add_int(m->m_ext.ref_cnt, 1);

	return (0);
}


void
uinet_pd_xlist_release(struct uinet_pd_xlist *xlist)
{
	struct uinet_pd_ctx *pdctx[UINET_PD_XLIST_MAX_DESCS];
	unsigned int i;

	if (xlist == NULL)
		return;
	
	for (i = 0; i < xlist->list.num_descs; i++)
		pdctx[i] = xlist->list.descs[i].ctx;

	uinet_pd_ref_release(pdctx, xlist->list.num_descs);
}


void
uinet_pd_xlist_release_all(struct uinet_pd_xlist *xlist)
{
	struct uinet_pd_xlist *cur;

	cur = xlist;
	while (cur) {
		uinet_pd_xlist_release(cur);
		cur = cur->next;
	}
}


struct uinet_pd_xlist *
uinet_pd_xlist_free(struct uinet_pd_xlist *xlist, struct uinet_pd_xlist *stop_at)
{
	struct uinet_pd_xlist *cur, *tmp;

	cur = xlist;
	while (cur && (cur != stop_at)) {
		tmp = cur->next;
		uinet_pd_xlist_pool_free(cur);
		cur = tmp;
	}

	return (cur);
}
