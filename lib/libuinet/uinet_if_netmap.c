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
#include "uinet_if_netmap.h"
#include "uinet_if_netmap_host.h"



static void if_netmap_default_config(union uinet_if_type_cfg *cfg);

static struct uinet_if_type_info if_netmap_type_info = {
	.type = UINET_IFTYPE_NETMAP,
	.type_name = "netmap",
	.default_cfg = if_netmap_default_config
};
UINET_IF_REGISTER_TYPE(NETMAP, &if_netmap_type_info);


/*
 * Overview
 * ========
 *
 * This provides a packet interface for a single netmap tx/rx ring pair.
 *
 * A pool of UINET_PD_NETMAP type packet descriptors is maintained for
 * zero-copy movement of packets to/from the rings, stack, and application.
 * A UINET_PD_NETMAP packet descriptor contains a netmap buffer index and an
 * mbuf that points to the netmap buffer corresponding to the buffer index.
 * At initialization time, a packet descriptor is created for each netmap
 * buffer in the tx and rx rings, as well as each buffer in the
 * (configurable) netmap extra pool, if any.  The 'pointer' member of the
 * netmap ring slot structure is used to store a pointer to the associated
 * packet descriptor context in each ring slot.
 *
 * Receive Operation
 * =================
 *
 * Each iteration of the receive loop processes packets on the receive ring
 * up to the given batch size.  If there are enough free packet descriptors
 * to replenish the ring, all packets are received in a zero-copy fashion,
 * otherwise each packet for which there is not a free packet descriptor to
 * replenish the corresponding ring slot is copied to the buffer in a
 * UINET_PD_MBUF type packet descriptor.  If no UINET_PD_MBUF type packet
 * descriptor is available, the packet is dropped.
 *
 * The entire batch of received packets is passed to the first-look handler
 * if one is installed.  Any packets remaining after the first-look handler
 * runs (or all, if one isn't installed) are then passed to the stack.
 *
 * Transmit Operation
 * ==================
 *
 * The transmit loop services two queues: the driver transmit queue from the
 * stack and the direct-injection queue.  Currently, the contents of mbufs
 * from the driver transmit queue are copied to the netmap buffers in
 * available transmit ring slots, as are the contents of UINET_PD_MBUF,
 * UINET_PD_PTR, and UINET_PD_NETMAP-from-another-pool packet descriptors in
 * the direct-injection queue.  UINET_PD_NETMAP packet descriptors in the
 * direct-injection queue that are from the same pool that the given
 * interface instance uses are attached to available slots in the transmit
 * ring and their buffer indexes are written to the corresponding slots.
 * The UINET_PD_NETMAP packet descriptors that were in those transmit ring
 * slots are then returned to the packet descriptor pool(s) used by the
 * originating interface(s).
 *
 */


#define TRACE_ENABLE 0

#define PKT_TRACE_DEPTH		64

#define TRACE_CFG		0x00000001
#define TRACE_RX_BATCH		0x00000010
#define TRACE_RX_PKT		0x00000020
#define TRACE_RX_RING_OPS	0x00000040
#define TRACE_RX_RING_STATE	0x00000080
#define TRACE_RX_DELIVERY	0x00000100
#define TRACE_TX_BATCH		0x00001000
#define TRACE_TX_PKT		0x00002000
#define TRACE_TX_RING_OPS	0x00004000
#define TRACE_TX_RING_STATE	0x00008000
#define TRACE_PD_POOL		0x00010000

#if TRACE_ENABLE
#define TRACE(mask, ...)	do {					\
	if (sc->trace_mask & (mask)) {					\
		printf("%s: ", sc->uif->name);				\
		printf(__VA_ARGS__);					\
	}								\
} while (0)

#define TRACE_PLAIN(mask, ...)	do {					\
	if (sc->trace_mask & (mask)) {					\
		printf(__VA_ARGS__);					\
	}								\
} while (0)
#else
#define TRACE(mask, ...) (void)sc
#define TRACE_PLAIN(mask, ...) (void)sc
#endif


/*
 * XXX Should move pool from just a list of struct uinet_pd_ctx pointers to
 * a list of struct uinet_pd that points to those struct uinet_pd_ctx - the
 * struct uinet_pd_ctx are already being derefernced in the free path, so
 * the data is already available at no extra cost to reinit the struct
 * uinet_pd, and having the initialized struct uinet_pd in the pool will
 * eliminate another dereference of the struct uinet_pd_ctx post-allocate in
 * the receive path
 *
 * XXX does every vale port really live in a separate netmap memory domain
 * within a single process?  we currently assume this - needs investigation.
 *
 */
struct if_netmap_pd_pool {
	struct mtx lock;
	struct uinet_pd_ctx **free_list;
	unsigned int num_free;
	unsigned int pool_id;
	struct uinet_pd_pool_info *pool_info;
	struct uinet_pd_ctx *extra_mem;
	unsigned int num_extra;
	uint32_t *extra_indices;
	unsigned int num_interfaces;
	unsigned int initialized;
};
static struct if_netmap_pd_pool global_desc_pool;
static unsigned int interface_count;
static unsigned int physical_interface_count;
uint32_t if_netmap_num_extra_bufs;

static void if_netmap_pd_pool_free(struct uinet_pd_ctx *pdctx[], unsigned int n);
static struct uinet_pd_pool_info global_desc_pool_info;


struct if_netmap_softc {
	struct ifnet *ifp;
	struct uinet_if *uif;
	uint8_t addr[ETHER_ADDR_LEN];
	int isvale;
	int fd;
	char host_ifname[IF_NAMESIZE];
	uint16_t queue;
	uint32_t trace_mask;

	struct if_netmap_host_context *nm_host_ctx;
	uint32_t rxslots;
	uint32_t txslots;
	uint32_t bufsize;

	struct if_netmap_pd_pool *pd_pool;
	uint32_t rx_batch_size;
	uint32_t rx_new_pd_ctx_max;
	uint32_t num_new_pd_ctx;
	uint32_t rx_avail;
	struct uinet_pd_ctx **rx_new_pd_ctx;
	struct uinet_pd_list *rx_pkts;

	struct if_netmap_pd_pool vale_desc_pool;
	struct uinet_pd_pool_info vale_desc_pool_info;
	unsigned int vale_num_extra_bufs;
	struct uinet_pd_ctx *rxring_pd_ctx_mem;
	struct uinet_pd_ctx *txring_pd_ctx_mem;
	struct thread *rx_thread;
	struct thread *tx_thread;
	uint32_t *rx_ring_bufs;
	uint32_t *tx_ring_bufs;

	struct mtx tx_lock;
	struct cv tx_cv;
	int tx_pkts_to_send;
	struct uinet_pd_ring *tx_inject_ring;
	struct uinet_pd_ctx **tx_pdctx_to_free;
};


#define TX_LOCK(sc_) if (!uinet_uifsts((sc_)->uif)) mtx_lock(&((sc_)->tx_lock))
#define TX_UNLOCK(sc_) if (!uinet_uifsts((sc_)->uif)) mtx_unlock(&((sc_)->tx_lock))


static int if_netmap_setup_interface(struct if_netmap_softc *sc);
static void if_netmap_free(void *arg1, void *arg2);


static void
if_netmap_default_config(union uinet_if_type_cfg *cfg)
{
	struct uinet_if_netmap_cfg *nmcfg;

	nmcfg = &cfg->netmap;

	nmcfg->trace_mask = 0;
	nmcfg->vale_num_extra_bufs = 1024;
}


static int
if_netmap_pd_ctx_init_mutables(struct uinet_pd_pool_info *pool, struct uinet_pd_ctx *pdctx)
{
	struct mbuf *m;
	int error;

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

	/*
	 * Reset fields that may have been adjusted the last time the
	 * descriptor was in use.
	 */

	/* Do this first as it resets m_data and we override below */
	error = m_pkthdr_init(m, M_NOWAIT);
	if (error)
		return error;

	m->m_next = NULL;
	m->m_nextpkt = NULL;
	m->m_data = m->m_ext.ext_buf;
	m->m_len = 0;

	/* Set M_NOFREE so mbuf machinery doesn't free the mbuf. */
	m->m_flags = (M_PKTHDR | M_NOFREE | M_EXT);
	m->m_type = MT_DATA;

	*(pdctx->refcnt) = 1;

	return (0);
}


static int
if_netmap_pd_ctx_init(struct uinet_pd_pool_info *pool, struct uinet_pd_ctx *pdctx,
		      uint32_t slotindex, void *slotbuf)
{
	struct if_netmap_pd_pool *nm_pool;
	struct mbuf *m;

	nm_pool = pool->ctx;

	pdctx->flags = UINET_PD_CTX_SINGLE_REF;
	pdctx->ref = slotindex;
	pdctx->refcnt = &pdctx->builtin_refcnt;
	pdctx->pool_id = nm_pool->pool_id;
	m = m_gethdr(M_DONTWAIT, MT_DATA);
	if (NULL == m)
		return (-1);
	pdctx->m = m;
	m->m_ext.ref_cnt = &pdctx->builtin_refcnt;
	m_extadd(m, slotbuf, pool->bufsize, if_netmap_free, nm_pool, pdctx, M_NOFREE,
		 EXT_EXTREF);
	
	return (if_netmap_pd_ctx_init_mutables(pool, pdctx));
}


static int
if_netmap_pd_ctx_pool_init_txring(struct if_netmap_softc *sc, struct uinet_pd_pool_info *pool)
{
	uint32_t i;
	uint32_t curslot;
	uint32_t curindex;
	uint32_t *slotbuf;
	void *slotptr;
	struct uinet_pd_ctx *pdctx;

	sc->txring_pd_ctx_mem = malloc(sizeof(*(sc->txring_pd_ctx_mem)) * sc->txslots,
				       M_DEVBUF, M_WAITOK|M_ZERO);
	if (sc->txring_pd_ctx_mem == NULL)
		return (-1);

	curslot = 0;
        pdctx = sc->txring_pd_ctx_mem;
	for (i = 0; i < sc->txslots; i++, pdctx++) {
		slotbuf = if_netmap_txslot(sc->nm_host_ctx, curslot, &curindex, &slotptr);
		sc->tx_ring_bufs[i] = curindex;
		if (if_netmap_pd_ctx_init(pool, pdctx, curindex, slotbuf))
			return (-1);
		if_netmap_txsetslotptr(sc->nm_host_ctx, curslot, pdctx);
		curslot = if_netmap_txslotnext(sc->nm_host_ctx, curslot);
	}

	return (0);
}


static int
if_netmap_pd_ctx_pool_init_rxring(struct if_netmap_softc *sc, struct uinet_pd_pool_info *pool)
{
	uint32_t i;
	uint32_t curslot;
	uint32_t curindex;
	uint32_t pktlen;
	uint32_t *slotbuf;
	void *slotptr;
	struct uinet_pd_ctx *pdctx;

	sc->rxring_pd_ctx_mem = malloc(sizeof(*(sc->rxring_pd_ctx_mem)) * sc->rxslots,
				       M_DEVBUF, M_WAITOK|M_ZERO);
	if (sc->rxring_pd_ctx_mem == NULL)
		return (-1);

	curslot = 0;
	pdctx = sc->rxring_pd_ctx_mem;
	for (i = 0; i < sc->rxslots; i++, pdctx++) {
		slotbuf = if_netmap_rxslot(sc->nm_host_ctx, curslot, &curindex, &slotptr, &pktlen);
		sc->rx_ring_bufs[i] = curindex;
		if (if_netmap_pd_ctx_init(pool, pdctx, curindex, slotbuf))
			return (-1);
		if_netmap_rxsetslotptr(sc->nm_host_ctx, curslot, pdctx);
		curslot = if_netmap_rxslotnext(sc->nm_host_ctx, curslot);
	}

	return (0);
}


static int
if_netmap_pd_ctx_pool_init(struct if_netmap_softc *sc, struct if_netmap_pd_pool *pool,
			   struct uinet_pd_pool_info *pool_info, uint32_t *extra)
{
	uint32_t curindex;
	uint32_t i;
	struct uinet_pd_ctx *pdctx;

	pool_info->type = UINET_PD_TYPE_NETMAP;
	pool_info->bufsize = sc->bufsize;
	pool_info->ctx = pool;
	pool_info->free = if_netmap_pd_pool_free;

	pool->pool_id = uinet_pd_pool_register(pool_info);
	if (pool->pool_id == -1)
		return (-1);
	pool->pool_info = pool_info;
	pool->num_extra = 0;
	pool->num_interfaces = 1;
	if (*extra) {
		pool->extra_mem = malloc(sizeof(*(pool->extra_mem)) * (*extra),
					 M_DEVBUF, M_WAITOK|M_ZERO);
		if (pool->extra_mem == NULL) {
			if_printf(sc->ifp, "Failed to alloc extra slot contexts\n");
			*extra = 0;
		} else {
			pool->free_list = malloc(sizeof(*(pool->free_list)) * (*extra),
						 M_DEVBUF, M_WAITOK);
			if (pool->free_list == NULL) {
				if_printf(sc->ifp, "Failed to alloc extra slot context free list\n");
				free(pool->extra_mem, M_DEVBUF);
				*extra = 0;
			} else {
				pool->extra_indices = malloc(sizeof(*pool->extra_indices) * (*extra), M_DEVBUF, M_WAITOK);
				if (pool->extra_indices == NULL) {
					if_printf(sc->ifp, "Failed to alloc storage for copy of extra ring buffer indices\n");
					free(pool->free_list, M_DEVBUF);
					free(pool->extra_mem, M_DEVBUF);
					*extra = 0;
				}
			}
		}
	} else
		pool->extra_mem = NULL;

	pool->num_extra = *extra;
	curindex = if_netmap_get_bufshead(sc->nm_host_ctx);

	/*
	 * The extra bufs list is reconstructed during detach, and in the
	 * case of shared pools, by the last interface leaving the shared
	 * pool, so the list in the netmap context is resest to empty here
	 * to avoid double frees in the case where the extra buffers are
	 * freed via an interface that is different than the one used to
	 * allocate them.
	 */
	if_netmap_set_bufshead(sc->nm_host_ctx, 0);
	pdctx = pool->extra_mem;
	for (i = 0; i < pool->num_extra; i++, pdctx++) {
		if (curindex == 0) {
			if_printf(sc->ifp, "Unexpected end of extra bufs list\n");
			return (-1);
		}

		pool->extra_indices[i] = curindex;
		pool->free_list[i] = pdctx;
		if (if_netmap_pd_ctx_init(pool->pool_info, pdctx, curindex,
					  if_netmap_buffer_address(sc->nm_host_ctx, curindex)))
			return (-1);
		curindex = if_netmap_buffer_get_next(sc->nm_host_ctx, curindex);
	}
	pool->num_free = pool->num_extra;

	return (0);
}


static void
if_netmap_pd_ctx_pool_init_final(struct if_netmap_softc *sc, struct if_netmap_pd_pool *pool)
{
	mtx_init(&pool->lock, "nmpdpllk", NULL, MTX_DEF);
	pool->initialized = 1;
}


static int
if_netmap_pd_ctx_pool_init_global(struct if_netmap_softc *sc)
{
	if (global_desc_pool.num_interfaces == 0) {
		if (if_netmap_pd_ctx_pool_init(sc, &global_desc_pool, &global_desc_pool_info,
					       &if_netmap_num_extra_bufs) != 0)
			return (-1);
	} else
		global_desc_pool.num_interfaces++;

	if (if_netmap_pd_ctx_pool_init_rxring(sc, &global_desc_pool_info) != 0)
		return (-1);

	if (if_netmap_pd_ctx_pool_init_txring(sc, &global_desc_pool_info) != 0)
		return (-1);

	if_netmap_pd_ctx_pool_init_final(sc, &global_desc_pool);

	return (0);
}


static int
if_netmap_pd_ctx_pool_init_vale(struct if_netmap_softc *sc)
{
	if (if_netmap_pd_ctx_pool_init(sc, &sc->vale_desc_pool, &sc->vale_desc_pool_info,
					 &sc->vale_num_extra_bufs) != 0)
		return (-1);

	if (if_netmap_pd_ctx_pool_init_rxring(sc, &sc->vale_desc_pool_info) != 0)
		return (-1);

	if (if_netmap_pd_ctx_pool_init_txring(sc, &sc->vale_desc_pool_info) != 0)
		return (-1);

	if_netmap_pd_ctx_pool_init_final(sc, &sc->vale_desc_pool);

	return (0);
}


static int
if_netmap_pd_ctx_pool_destroy(struct if_netmap_softc *sc)
{
	struct if_netmap_pd_pool *p;
	unsigned int i;

	if (sc->rxring_pd_ctx_mem) {
		for (i = 0; i < sc->rxslots; i++)
			m_free(sc->rxring_pd_ctx_mem[i].m);

		free(sc->rxring_pd_ctx_mem, M_DEVBUF);
	}

	if (sc->txring_pd_ctx_mem) {
		for (i = 0; i < sc->txslots; i++)
			m_free(sc->txring_pd_ctx_mem[i].m);

		free(sc->txring_pd_ctx_mem, M_DEVBUF);
	}
	
	if (!sc->isvale) {
		physical_interface_count--;
		if (physical_interface_count != 0)
			return (0);
	}

	p = sc->isvale ? &sc->vale_desc_pool : &global_desc_pool;

	if (p->initialized)
		mtx_destroy(&p->lock);

	if (p->extra_mem) {
		for (i = 0; i < p->num_extra; i++)
			m_free(p->extra_mem[i].m);

		free(p->extra_indices, M_DEVBUF);
		free(p->free_list, M_DEVBUF);
		free(p->extra_mem, M_DEVBUF);
	}

	return (0);
}


static uint32_t
if_netmap_pd_alloc(struct if_netmap_softc *sc, struct uinet_pd_ctx **to, uint32_t n)
{
	struct if_netmap_pd_pool *p;
	uint32_t alloc_size;

	p = sc->pd_pool;

	mtx_lock(&p->lock);
	alloc_size = n > p->num_free ? p->num_free : n;
	TRACE(TRACE_PD_POOL, "Allocating %u descriptors from pool %p, %u remaining\n", alloc_size, p, p->num_free - alloc_size);
	if (alloc_size) {
		/* take alloc_size entries from the end of the free list */
		memcpy(to, &p->free_list[p->num_free - alloc_size],
		       alloc_size * sizeof(p->free_list[0])); 
		p->num_free -= alloc_size;
	}
	mtx_unlock(&p->lock);

	return (alloc_size);
}


static void
if_netmap_pd_alloc_user(struct uinet_if *uif, struct uinet_pd_list *pkts)
{
	struct if_netmap_softc *sc;
	struct if_netmap_pd_pool *p;
	struct uinet_pd *cur_pd;
	struct uinet_pd_ctx *cur_pdctx;
	uint32_t alloc_size;
	uint32_t i, free_list_index;

	sc = uif->ifdata;
	p = sc->pd_pool;

	mtx_lock(&p->lock);
	alloc_size = pkts->num_descs > p->num_free ? p->num_free : pkts->num_descs;
	TRACE(TRACE_PD_POOL, "Allocating %u user descriptors from pool %p, %u remaining\n", alloc_size, p, p->num_free - alloc_size);
	for (i = 0, free_list_index = p->num_free - alloc_size; i < alloc_size; i++, free_list_index++) {
		cur_pd = &pkts->descs[i];
		cur_pdctx = p->free_list[free_list_index];

		cur_pd->flags = UINET_PD_TYPE_NETMAP;
		cur_pd->length = p->pool_info->bufsize;
		cur_pd->pool_id = p->pool_id;
		cur_pd->ref = cur_pdctx->ref;
		cur_pd->data = if_netmap_buffer_address(sc->nm_host_ctx, cur_pd->ref);
		cur_pd->ctx = cur_pdctx;
	}
	p->num_free -= alloc_size;
	mtx_unlock(&p->lock);

	pkts->num_descs = alloc_size;
}


static void
if_netmap_pd_free(struct if_netmap_pd_pool *pool, struct uinet_pd_ctx *pdctx[], uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (pdctx[i]->flags & UINET_PD_CTX_MBUF_USED)
			if_netmap_pd_ctx_init_mutables(pool->pool_info, pdctx[i]);
		pdctx[i]->flags = UINET_PD_CTX_SINGLE_REF;
		pdctx[i]->timestamp = 0;
	}

	mtx_lock(&pool->lock);
	memcpy(&pool->free_list[pool->num_free], pdctx, n * sizeof(pdctx[0]));
	pool->num_free += n;
	mtx_unlock(&pool->lock);
}


/*
 * Descriptor free routine for pool-info interface.
 */
static void
if_netmap_pd_pool_free(struct uinet_pd_ctx *pdctx[], unsigned int n)
{
	struct uinet_pd_pool_info *pool;

	pool = uinet_pd_pool_get(pdctx[0]->pool_id);
	if_netmap_pd_free(pool->ctx, pdctx, n);
}


/*
 * A UINET_PD_NETMAP type packet descriptor from this interface is freed via
 * this routine when the final reference is released via the mbuf api.
 */
static void
if_netmap_free(void *arg1, void *arg2)
{
	struct if_netmap_pd_pool *pool;
	struct uinet_pd_ctx *pdctx;

	pool = arg1;
	pdctx = arg2;

	pdctx->flags = UINET_PD_CTX_SINGLE_REF;
	if_netmap_pd_ctx_init_mutables(pool->pool_info, pdctx);

	mtx_lock(&pool->lock);
	pool->free_list[pool->num_free] = pdctx;
	pool->num_free++;
	mtx_unlock(&pool->lock);
}


static int
if_netmap_process_configstr(struct if_netmap_softc *sc)
{
	char *configstr = sc->uif->configstr;
	int error = 0;
	char *last_colon;
	char *p;
	int namelen;

	if (0 == strncmp(configstr, "vale", 4)) {
		sc->isvale = 1;
		sc->queue = 0;

		if (strlen(configstr) > (sizeof(sc->host_ifname) - 1)) {
			error = ENAMETOOLONG;
			goto out;
		}
		strcpy(sc->host_ifname, configstr);
	} else {
		sc->isvale = 0;

		last_colon = strchr(configstr, ':');
		if (last_colon) {
			if (last_colon == configstr) {
				/* no name */
				error = EINVAL;
				goto out;
			}

			p = last_colon + 1;
			if ('\0' == *p) {
				/* colon at the end */
				error = EINVAL;
				goto out;
			}

			while (isdigit(*p) && ('\0' != *p))
				p++;
			
			if ('\0' != *p) {
				/* non-numeric chars after colon */
				error = EINVAL;
				goto out;
			}

			sc->queue = strtoul(last_colon + 1, NULL, 10);
			
			namelen = last_colon - configstr;
			if (namelen > (sizeof(sc->host_ifname) - 1)) {
				error = ENAMETOOLONG;
				goto out;
			}
			
			memcpy(sc->host_ifname, configstr, namelen);
			sc->host_ifname[namelen] = '\0';
		} else {
			sc->queue = 0;
			strlcpy(sc->host_ifname, configstr, sizeof(sc->host_ifname));
		}
	}

out:
	return (error);
}


int
if_netmap_attach(struct uinet_if *uif)
{
	struct if_netmap_softc *sc = NULL;
	int fd = -1;
	int error = 0;
	struct uinet_if_netmap_cfg *nm_cfg;
	uint32_t *num_extra_bufs, num_requested_extra_bufs;

	nm_cfg = &uif->type_cfg.netmap;
	
	if (NULL == uif->configstr) {
		error = EINVAL;
		goto fail;
	}

	printf("%s: configstr is %s\n", __func__, uif->configstr);

	snprintf(uif->name, sizeof(uif->name), "netmap%u", interface_count);
	interface_count++;

	sc = malloc(sizeof(struct if_netmap_softc), M_DEVBUF, M_WAITOK);
	if (NULL == sc) {
		printf("%s: if_netmap_softc allocation failed\n", uif->name);
		error = ENOMEM;
		goto fail;
	}
	memset(sc, 0, sizeof(struct if_netmap_softc));

	sc->uif = uif;
	sc->trace_mask = nm_cfg->trace_mask;

	error = if_netmap_process_configstr(sc);
	if (0 != error) {
		goto fail;
	}

	fd = uhi_open("/dev/netmap", UHI_O_RDWR);
	if (fd < 0) {
		printf("%s: /dev/netmap open failed\n", uif->name);
		error = ENXIO;
		goto fail;
	}

	sc->fd = fd;

	if (sc->isvale) {
		sc->vale_num_extra_bufs = nm_cfg->vale_num_extra_bufs;
		num_extra_bufs = &sc->vale_num_extra_bufs;
	} else if (global_desc_pool.num_interfaces == 0) 
		num_extra_bufs = &if_netmap_num_extra_bufs;
	else {
		num_requested_extra_bufs = 0;
		num_extra_bufs = &num_requested_extra_bufs;
	}
	num_requested_extra_bufs = *num_extra_bufs;
	sc->nm_host_ctx = if_netmap_register_if(sc->fd, sc->host_ifname, sc->isvale, sc->queue, num_extra_bufs);
	if (NULL == sc->nm_host_ctx) {
		printf("%s: Failed to register netmap interface\n", uif->name);
		error = ENXIO;
		goto fail;
	}

	sc->bufsize = if_netmap_rxbufsize(sc->nm_host_ctx);
	sc->rxslots = if_netmap_rxslots(sc->nm_host_ctx);
	sc->txslots = if_netmap_txslots(sc->nm_host_ctx);

	sc->rx_ring_bufs = malloc(sizeof(*sc->rx_ring_bufs) * sc->rxslots, M_DEVBUF, M_WAITOK);
	if (sc->rx_ring_bufs == NULL) {
		printf("%s: Failed to allocate storage for copy of rx ring buffer indices\n", uif->name);
		error = ENXIO;
		goto fail;
	}

	sc->tx_ring_bufs = malloc(sizeof(*sc->tx_ring_bufs) * sc->txslots, M_DEVBUF, M_WAITOK);
	if (sc->tx_ring_bufs == NULL) {
		printf("%s: Failed to allocate storage for copy of tx ring buffer indices\n", uif->name);
		error = ENXIO;
		goto fail;
	}

	sc->rx_batch_size = uif->rx_batch_size;
	if (sc->rx_batch_size < 1)
		sc->rx_batch_size = 1;
	else if (sc->rx_batch_size > sc->rxslots)
		sc->rx_batch_size = sc->rxslots;

	if (num_requested_extra_bufs != *num_extra_bufs)
		printf("%s: Requested %u extra netmap buffers, %u provided\n", uif->name, num_requested_extra_bufs, *num_extra_bufs);

	if (!sc->isvale) {
		if (0 != if_netmap_pd_ctx_pool_init_global(sc)) {
			printf("%s: packet descriptor pool init failed\n", uif->name);
			goto fail;
		}
		sc->pd_pool = &global_desc_pool;

		if (0 != uhi_get_ifaddr(sc->host_ifname, sc->addr)) {
			printf("%s: failed to find interface address\n", uif->name);
			error = ENXIO;
			goto fail;
		}
	} else {
		if (0 != if_netmap_pd_ctx_pool_init_vale(sc)) {
			printf("%s: packet descriptor pool init failed\n", uif->name);
			goto fail;
		}
		sc->pd_pool = &sc->vale_desc_pool;
	}

	sc->rx_pkts = uinet_pd_list_alloc(sc->rx_batch_size);
	if (sc->rx_pkts == NULL) {
		printf("%s: Failed to allocate receive packet descriptor list\n", uif->name);
		error = ENOMEM;
		goto fail;
	}

	sc->rx_new_pd_ctx_max = sc->rx_batch_size;
	sc->rx_new_pd_ctx = malloc(sizeof(struct uinet_pd_ctx) * sc->rx_new_pd_ctx_max,
				   M_DEVBUF, M_WAITOK);
	if (sc->rx_new_pd_ctx == NULL) {
		printf("%s: Failed to allocate receive descriptor ctx list\n", uif->name);
		error = ENOMEM;
		goto fail;
	}

	sc->tx_inject_ring = uinet_pd_ring_alloc(uif->tx_inject_queue_len);
	if (sc->tx_inject_ring == NULL) {
		printf("%s: Failed to allocate transmit injection ring\n", uif->name);
		error = ENOMEM;
		goto fail;
	}

	sc->tx_pdctx_to_free = malloc(sizeof(*sc->tx_pdctx_to_free) * sc->tx_inject_ring->num_descs,
				      M_DEVBUF, M_WAITOK);
	if (sc->tx_pdctx_to_free == NULL) {
		printf("%s: Failed to allocate transmit pdctx retirement list\n", uif->name);
		error = ENOMEM;
		goto fail;
	}

	if (0 != if_netmap_setup_interface(sc)) {
		error = ENXIO;
		goto fail;
	}

	if (!sc->isvale)
		physical_interface_count++;

	return (0);

fail:
	if (sc) {
		if_netmap_pd_ctx_pool_destroy(sc);

		if (sc->tx_pdctx_to_free)
			free(sc->tx_pdctx_to_free, M_DEVBUF);

		if (sc->tx_inject_ring)
			uinet_pd_ring_free(sc->tx_inject_ring);

		if (sc->rx_new_pd_ctx)
			free(sc->rx_new_pd_ctx, M_DEVBUF);

		if (sc->rx_pkts)
			uinet_pd_list_free(sc->rx_pkts);
		
		if (sc->tx_ring_bufs)
			free(sc->tx_ring_bufs, M_DEVBUF);

		if (sc->rx_ring_bufs)
			free(sc->rx_ring_bufs, M_DEVBUF);

		if (sc->nm_host_ctx)
			if_netmap_deregister_if(sc->nm_host_ctx);

		if (sc->fd >= 0)
			uhi_close(sc->fd);

		free(sc, M_DEVBUF);
	}

	return (error);
}


static void
if_netmap_init(void *arg)
{
	struct if_netmap_softc *sc = arg;
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}


static void
if_netmap_sts_init(void *arg)
{
	struct if_netmap_softc *sc = arg;
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags |= IFF_DRV_OACTIVE; /* never call start */
}


static void
if_netmap_send_queue_has_grown_locked(struct if_netmap_softc *sc)
{
	if (!uinet_uifsts(sc->uif)) {
		sc->tx_pkts_to_send++;
		if (sc->tx_pkts_to_send == 1)
			cv_signal(&sc->tx_cv);
	}
}


static void
if_netmap_start(struct ifnet *ifp)
{
	struct if_netmap_softc *sc = ifp->if_softc;

	TX_LOCK(sc);
	if_netmap_send_queue_has_grown_locked(sc);
	TX_UNLOCK(sc);
}


static void
if_netmap_sts_start(struct ifnet *ifp)
{
	/* nothing to do */
}


static void
if_netmap_inject_tx_pkts(struct uinet_if *uif, struct uinet_pd_list *pkts)
{
	struct if_netmap_softc *sc = (struct if_netmap_softc *)(uif->ifdata);
	struct uinet_pd_ring *txr;
	struct uinet_pd *pd;
	struct uinet_pd *first_drop_pd;
	uint32_t i;
	uint32_t space;
	uint32_t cur;
	uint32_t num_drops;
	uint32_t pds_to_check_for_drops;

	txr = sc->tx_inject_ring;
	pd = &pkts->descs[0];

	TX_LOCK(sc);
	space = uinet_pd_ring_space(txr);
	cur = txr->put;
	num_drops = 0;
	pds_to_check_for_drops = 0;
	for (i = 0; i < pkts->num_descs; i++, pd++) {
		if (pd->flags & UINET_PD_INJECT) {
			if (space) {
				txr->descs[cur] = *pd;
				cur = uinet_pd_ring_next(txr, cur);
				space--;
			} else {
				if (num_drops == 0) {
					first_drop_pd = pd;
					pds_to_check_for_drops = pkts->num_descs - i;
				}
				num_drops++;
			}
		}
	}
	txr->put = cur;
	txr->drops += num_drops;
	if_netmap_send_queue_has_grown_locked(sc);
	TX_UNLOCK(sc);

	if (pds_to_check_for_drops)
		uinet_pd_drop_injected(first_drop_pd, pds_to_check_for_drops); 
}


static int
if_netmap_wait_for_avail(struct if_netmap_softc *sc, uint32_t *avail, unsigned int poll_type,
			 uint32_t (*avail_func)(struct if_netmap_host_context *), int poll_timo_ms)
{
	int done = 0;
	int rv;
	struct uhi_pollfd pfd;

	if (*avail == 0)
		TRACE((poll_type == UHI_POLLIN) ? TRACE_RX_RING_OPS : TRACE_TX_RING_OPS,
		      "%s Waiting for %s\n",
		      (poll_type == UHI_POLLIN) ? "rx:" : " tx:",
		      (poll_type == UHI_POLLIN) ? "packets" : "space");
	else
		done = kthread_stop_check();

	while (*avail == 0 && !done) {
		memset(&pfd, 0, sizeof(pfd));

		pfd.fd = sc->fd;
		pfd.events = poll_type;
				
		rv = uhi_poll(&pfd, 1, poll_timo_ms);
		if (rv == -1)
			if_printf(sc->ifp, "error from poll (type=%u)\n", poll_type);
		else if (rv != -2)
			*avail = avail_func(sc->nm_host_ctx);

		done = kthread_stop_check();
	}

	return (done);
}


static uint32_t
if_netmap_process_tx_inject_ring(struct if_netmap_softc *sc, uint32_t avail, uint32_t *curslot,
				 uint32_t *cur_inject_take, uint32_t cur_inject_put,
				 struct uinet_pd_ctx ***pdctx_to_free,
				 uint32_t *n_zero_copy, uint32_t *n_copy, uint32_t *total_bytes)
{
	struct uinet_pd_ring *txr;
	struct uinet_pd *cur_pd;
	struct uinet_pd_ctx *slot_pdctx, **local_pdctx_to_free;
	uint32_t *slotbuf;
	uint32_t local_curslot;
	uint32_t pktlen;
	uint32_t bufindex;
	uint32_t local_n_zero_copy, local_n_copy, local_total_bytes;
	uint32_t local_cur_inject_take;
	unsigned int desc_type;
	unsigned int this_pd_pool_id;
	unsigned int i;

	txr = sc->tx_inject_ring;
	this_pd_pool_id = sc->pd_pool->pool_id;
	local_n_zero_copy = *n_zero_copy;
	local_n_copy = *n_copy;
	local_total_bytes = *total_bytes;
	local_cur_inject_take = *cur_inject_take;
	local_curslot = *curslot;
	local_pdctx_to_free = *pdctx_to_free;
	while (avail && (local_cur_inject_take != cur_inject_put)) {
		cur_pd = &txr->descs[local_cur_inject_take];

		if (!(cur_pd->flags & UINET_PD_MGMT_ONLY)) {
			pktlen = cur_pd->length;
			local_total_bytes += pktlen;

			TRACE(TRACE_TX_PKT, " tx: pktlen=%u [", pktlen);
			for (i = 0; i < PKT_TRACE_DEPTH; i++)
				TRACE_PLAIN(TRACE_TX_PKT, " %02x", cur_pd->data[i]);
			TRACE_PLAIN(TRACE_TX_PKT, " ]\n");

			slotbuf = if_netmap_txslot(sc->nm_host_ctx, local_curslot, &bufindex, (void **)&slot_pdctx);
			TRACE(TRACE_TX_RING_STATE, " tx: slot %u: bufindex=%u ptr=%p\n", local_curslot, bufindex, slot_pdctx);
			desc_type = uinet_pd_type(cur_pd);
			if ((desc_type == UINET_PD_TYPE_NETMAP) && (cur_pd->pool_id == this_pd_pool_id)) {
				TRACE(TRACE_TX_RING_OPS, " tx: slot %u: writing bufindex %u, freeing bufindex %u\n",
				      local_curslot, (unsigned int)cur_pd->ref, bufindex);

				local_n_zero_copy++;

				/*
				 * Swap the outbound packet descriptor with the one in the slot.
				 */
				*local_pdctx_to_free++ = slot_pdctx;
				slot_pdctx = cur_pd->ctx;
				bufindex = cur_pd->ref;
			} else {
				TRACE(TRACE_TX_RING_OPS, " tx: slot %u: copying %s data to bufindex %u\n",
				      local_curslot,
				      (desc_type == UINET_PD_TYPE_MBUF) ? "mbuf" :
				      (desc_type == UINET_PD_TYPE_NETMAP) ? "netmap-from-other-pool" :
				      (desc_type == UINET_PD_TYPE_PTR) ? "ptr" : "<unknown>", bufindex);

				local_n_copy++;
				memcpy(slotbuf, cur_pd->data, pktlen);
				*local_pdctx_to_free++ = cur_pd->ctx;
			}

			avail--;
			TRACE(TRACE_TX_RING_OPS, " tx: slot %u: setting bufindex=%u ptr=%p len=%u\n",
			      local_curslot, bufindex, slot_pdctx, pktlen);
			if_netmap_txsetslot(sc->nm_host_ctx, &local_curslot, bufindex, slot_pdctx, pktlen, 0);
		}

		local_cur_inject_take = uinet_pd_ring_next(txr, local_cur_inject_take);
	}
	*curslot = local_curslot;
	*cur_inject_take = local_cur_inject_take;
	*pdctx_to_free = local_pdctx_to_free;
	*n_zero_copy = local_n_zero_copy;
	*n_copy = local_n_copy;
	*total_bytes = local_total_bytes;

	return (avail);
}


static uint32_t
if_netmap_process_drv_queue(struct if_netmap_softc *sc, struct mbuf **m,
			    uint32_t avail, uint32_t *curslot,
			    uint32_t *n_copy, int always_dequeue)
{
	struct ifnet *ifp;
	struct mbuf *last_m, *local_m;
	struct uinet_pd_ctx *slot_pdctx;
	uint32_t *slotbuf;
	uint32_t local_curslot;
	uint32_t bufindex;
	uint32_t pktlen;
	uint32_t local_n_copy;
	unsigned int i;

	ifp = sc->ifp;
	local_n_copy = *n_copy;
	local_m = *m;
	last_m = NULL;
	local_curslot = *curslot;
	while (local_m && avail) {
		local_n_copy++;

		pktlen = m_length(local_m, NULL);

		slotbuf = if_netmap_txslot(sc->nm_host_ctx, local_curslot, &bufindex, (void **)&slot_pdctx);
		TRACE(TRACE_TX_RING_STATE, " tx: slot %u: bufindex=%u ptr=%p\n", local_curslot, bufindex, slot_pdctx);
		TRACE(TRACE_TX_RING_OPS, " tx: slot %u: copying mbuf data to bufindex %u\n", local_curslot, bufindex);
		m_copydata(local_m, 0, pktlen, (caddr_t)slotbuf); 
		TRACE(TRACE_TX_RING_OPS, " tx: slot %u: setting bufindex=%u ptr=%p len=%u\n",
		      local_curslot, bufindex, slot_pdctx, pktlen);
		if_netmap_txsetslot(sc->nm_host_ctx, &local_curslot, bufindex, slot_pdctx, pktlen, 0);

		TRACE(TRACE_TX_PKT, " tx: pktlen=%u [", pktlen);
		for (i = 0; i < PKT_TRACE_DEPTH; i++)
			TRACE_PLAIN(TRACE_TX_PKT, " %02x", ((uint8_t *)slotbuf)[i]);
		TRACE_PLAIN(TRACE_TX_PKT, " ]\n");

		if (last_m)
			last_m->m_nextpkt = local_m;
		last_m = local_m;

		avail--;
		if (avail || always_dequeue)
			IFQ_DRV_DEQUEUE(&ifp->if_snd, local_m);
	}
	*curslot = local_curslot;
	*n_copy = local_n_copy;
	*m = local_m;

	return (avail);
}


static void
if_netmap_tx_release_packets(struct if_netmap_softc *sc, uint32_t num_pd, struct mbuf *m_to_free)
{
	struct mbuf *m;

	TRACE(TRACE_TX_BATCH, " tx: Releasing packet descriptors\n");
	uinet_pd_ref_release(sc->tx_pdctx_to_free, num_pd);

	TRACE(TRACE_TX_BATCH, " tx: Freeing mbufs\n");
	while (m_to_free) {
		m = m_to_free;
		m_to_free = m_to_free->m_nextpkt;
		m_freem(m);
	}
}


static int
if_netmap_batch_send(struct uinet_if *uif, int *fd, uint64_t *wait_ns)
{
	struct ifnet *ifp;
	struct if_netmap_softc *sc;
	struct uinet_pd_ring *txr;
	struct mbuf *m, *m_to_free;
	struct uinet_pd_ctx **pdctx_to_free;
	uint32_t avail;
	uint32_t curslot;
	uint32_t n_pd_copy, n_m_copy, n_zero_copy, total_bytes;
	uint32_t inject_drops;
	int rv;

	*wait_ns = 0;
	ifp = uif->ifp;
	sc = uif->ifdata;
	txr = sc->tx_inject_ring;

	curslot = if_netmap_txcur(sc->nm_host_ctx);
	avail = if_netmap_txavail(sc->nm_host_ctx);
	n_pd_copy = 0;
	n_m_copy = 0;
	n_zero_copy = 0;
	total_bytes = 0;

	TRACE(TRACE_TX_BATCH, " tx: Processing direct-injection queue\n");

	inject_drops = txr->drops;
	txr->drops = 0;
	pdctx_to_free = &sc->tx_pdctx_to_free[0];
	avail = if_netmap_process_tx_inject_ring(sc, avail, &curslot,
						 &txr->take, txr->put,
						 &pdctx_to_free,
						 &n_zero_copy, &n_pd_copy, &total_bytes);
	
	TRACE(TRACE_TX_BATCH, " tx: Processing driver queue\n");
	if (avail) {
		IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
		m_to_free = m;
		if (m)
			avail = if_netmap_process_drv_queue(sc, &m, avail, &curslot, &n_m_copy, 0);
	} else
		m_to_free = NULL;

	ifp->if_oerrors += inject_drops;
	if (n_zero_copy + n_pd_copy + n_m_copy > 0) {
		ifp->if_opackets += n_zero_copy + n_pd_copy + n_m_copy;
		ifp->if_ozcopies += n_zero_copy;
		ifp->if_ocopies += n_pd_copy + n_m_copy;
		ifp->if_obytes += total_bytes;
		
		TRACE(TRACE_TX_RING_OPS, " tx: Sync\n");
		while (EBUSY == (rv = if_netmap_txsync(sc->nm_host_ctx, &avail, &curslot)));
		if (rv != 0) {
			if_printf(ifp, "could not sync tx descriptors after transmit\n");
		}

		if_netmap_tx_release_packets(sc, n_zero_copy + n_pd_copy, m_to_free);
	}

	if (avail == 0)
		*fd = sc->fd; /* caller should block */
	else
		*fd = -1;  /* call again at earliest convenience */

	return (0);
}


static void
if_netmap_send(void *arg)
{
	struct if_netmap_softc *sc = (struct if_netmap_softc *)arg;
	struct ifnet *ifp = sc->ifp;
	struct uinet_pd_ring *txr;
	struct mbuf *m, *m_to_free;
	struct uinet_pd_ctx **pdctx_to_free;
	uint32_t avail;
	uint32_t curslot;
	uint32_t n_copy, n_zero_copy, total_bytes;
	uint32_t cur_inject_take, cur_inject_put;
	uint32_t num_pd;
	uint32_t inject_drops;
	int rv;
	int done;
	int poll_wait_ms;

	if (sc->uif->tx_cpu >= 0)
		sched_bind(curthread, sc->uif->tx_cpu);

	TRACE(TRACE_CFG, " tx: thread bound to cpu %d\n", sc->uif->tx_cpu);

	done = 0;
	avail = if_netmap_txavail(sc->nm_host_ctx);
	curslot = if_netmap_txcur(sc->nm_host_ctx);
	txr = sc->tx_inject_ring;
	poll_wait_ms = (curthread->td_stop_check_ticks * 1000) / hz;
	cur_inject_take = 0;
	do {
		TRACE(TRACE_TX_BATCH, " tx: Waiting for packets to transmit\n");

		/* Wait for more packets to send */
		mtx_lock(&sc->tx_lock);

		/* release inject ring descriptors we've processed */
		txr->take = cur_inject_take;
		while ((sc->tx_pkts_to_send == 0) && !done)
			if (EWOULDBLOCK == cv_timedwait(&sc->tx_cv, &sc->tx_lock, curthread->td_stop_check_ticks))
				done = kthread_stop_check();
		sc->tx_pkts_to_send = 0;
		cur_inject_put = txr->put;
		inject_drops = txr->drops;
		txr->drops = 0;
		mtx_unlock(&sc->tx_lock);

		TRACE(TRACE_TX_RING_STATE, " tx: avail=%u curslot=%u\n", avail, curslot);

		if (done)
			goto done;

		n_copy = 0;
		n_zero_copy = 0;
		total_bytes = 0;

		TRACE(TRACE_TX_BATCH, " tx: Processing direct-injection queue\n");
		pdctx_to_free = &sc->tx_pdctx_to_free[0];
		while (cur_inject_take != cur_inject_put) {
			done = if_netmap_wait_for_avail(sc, &avail, UHI_POLLOUT, if_netmap_txavail, poll_wait_ms);

 			if (done)
				goto done;

			avail = if_netmap_process_tx_inject_ring(sc, avail, &curslot,
								 &cur_inject_take, cur_inject_put,
								 &pdctx_to_free,
								 &n_zero_copy, &n_copy, &total_bytes);

			/* update the ring state for the benefit of subsequent calls to if_netmap_wait_for_avail() */
			if_netmap_txupdate(sc->nm_host_ctx, &avail, &curslot);
		}
		num_pd = n_zero_copy + n_copy;

		TRACE(TRACE_TX_BATCH, " tx: Processing driver queue\n");
		IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
		m_to_free = m;
		while (m) {
			done = if_netmap_wait_for_avail(sc, &avail, UHI_POLLOUT, if_netmap_txavail, poll_wait_ms);

 			if (done)
				goto done;

			avail = if_netmap_process_drv_queue(sc, &m, avail, &curslot, &n_copy, 1);

			/* update the ring state for the benefit of subsequent calls to if_netmap_wait_for_avail() */
			if_netmap_txupdate(sc->nm_host_ctx, &avail, &curslot);
		}

		ifp->if_oerrors += inject_drops;
		if (n_zero_copy + n_copy > 0) {
			ifp->if_opackets += n_zero_copy + n_copy;
			ifp->if_ozcopies += n_zero_copy;
			ifp->if_ocopies += n_copy;
			ifp->if_obytes += total_bytes;

			TRACE(TRACE_TX_RING_OPS, " tx: Sync\n");
			while (EBUSY == (rv = if_netmap_txsync(sc->nm_host_ctx, &avail, &curslot)));
			if (rv != 0) {
				if_printf(ifp, "could not sync tx descriptors after transmit\n");
			}
			avail = if_netmap_txavail(sc->nm_host_ctx);
		}

		if_netmap_tx_release_packets(sc, num_pd, m_to_free);
	} while (1);

done:
	kthread_stop_ack();
}


static void
if_netmap_stop(struct if_netmap_softc *sc)
{
	struct ifnet *ifp = sc->ifp;

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING|IFF_DRV_OACTIVE);
}


static int
if_netmap_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int error = 0;
	struct if_netmap_softc *sc = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (uinet_uifsts(sc->uif))
				if_netmap_sts_init(sc);
			else
				if_netmap_init(sc);
		} else if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			if_netmap_stop(sc);
		break;
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}


static int
if_netmap_batch_receive(struct uinet_if *uif, int *fd, uint64_t *wait_ns)
{
	struct if_netmap_softc *sc;
	struct ifnet *ifp;
	struct uinet_pd_ctx *slot_pdctx, *new_pd_ctx;
	struct uinet_pd *rx_pkt_desc;
	uint32_t *slotbuf;
	uint32_t bufindex;
	uint32_t pktlen;
	uint32_t curslot;
	uint32_t avail;
	uint32_t batch_size;
	uint32_t total_bytes;
	uint32_t n, n_zero_copy, n_copy, n_drop;
	uint32_t new_pd_ctx_fill_size;
	uint32_t num_new_pd_ctx;
	int rv;
	unsigned int i;

	sc = uif->ifdata;
	ifp = uif->ifp;
	*wait_ns = 0;

	curslot = if_netmap_rxcur(sc->nm_host_ctx);
	avail = sc->rx_avail;
	total_bytes = 0;

	TRACE(TRACE_RX_RING_STATE, "rx: avail=%u curslot=%u\n", avail, curslot);

	batch_size = avail < sc->rx_batch_size ? avail : sc->rx_batch_size;

	/*
	 * Only acquire more new pd contexts when not doing so
	 * would result in copying received packets.
	 *
	 * Subsequent math assumes the fill size is >= the receive batch
	 * size.
	 */
	new_pd_ctx_fill_size = sc->rx_new_pd_ctx_max;
	num_new_pd_ctx = sc->num_new_pd_ctx;
	if (num_new_pd_ctx < batch_size) {
		TRACE(TRACE_RX_BATCH, "rx: Trying to allocate %u new packet descriptor contexts\n",
		      new_pd_ctx_fill_size - num_new_pd_ctx);
		num_new_pd_ctx += if_netmap_pd_alloc(sc, &sc->rx_new_pd_ctx[num_new_pd_ctx],
						     new_pd_ctx_fill_size - num_new_pd_ctx);
	}
	TRACE(TRACE_RX_BATCH, "rx: There are %u new packet descriptor contexts\n", num_new_pd_ctx);

	n_zero_copy = (num_new_pd_ctx < batch_size) ? num_new_pd_ctx : batch_size;

	sc->rx_pkts->num_descs = n_zero_copy;
	n_copy = batch_size - n_zero_copy;
	n = n_copy ? uinet_pd_mbuf_alloc_descs(sc->rx_pkts, n_copy) : 0;
	n_drop = n_copy - n;
	n_copy = n;

	TRACE(TRACE_RX_BATCH, "rx: n_zero_copy=%u n_copy=%u n_drop=%u\n", n_zero_copy, n_copy, n_drop);

	rx_pkt_desc = sc->rx_pkts->descs;

	/*
	 * Zero-copy input
	 */
	if (n_zero_copy > 0) {
		for (n = 0; n < n_zero_copy; n++, rx_pkt_desc++, new_pd_ctx++) {
			new_pd_ctx = sc->rx_new_pd_ctx[num_new_pd_ctx - n_zero_copy + n];
			slotbuf = if_netmap_rxslot(sc->nm_host_ctx, curslot, &bufindex, (void **)&slot_pdctx, &pktlen);
			TRACE(TRACE_RX_RING_STATE, "rx: slot %u: bufindex=%u ptr=%p pktlen=%u\n", curslot, bufindex, slot_pdctx, pktlen);
			TRACE(TRACE_RX_PKT, " rx: pktlen=%u [", pktlen);
			for (i = 0; i < PKT_TRACE_DEPTH; i++)
				TRACE_PLAIN(TRACE_RX_PKT, " %02x", ((uint8_t *)slotbuf)[i]);
			TRACE_PLAIN(TRACE_RX_PKT, " ]\n");

			TRACE(TRACE_RX_RING_OPS, "rx: slot %u: taking bufindex %u, replacing with bufindex %u\n",
			      curslot, bufindex, (unsigned int)new_pd_ctx->ref);
			TRACE(TRACE_RX_RING_OPS, "rx: slot %u: setting bufindex=%u ptr=%p\n",
			      curslot, (unsigned int)new_pd_ctx->ref, new_pd_ctx);
			if_netmap_rxsetslot(sc->nm_host_ctx, &curslot, new_pd_ctx->ref, new_pd_ctx);
				
			rx_pkt_desc->flags = UINET_PD_TYPE_NETMAP | UINET_PD_TO_STACK;
			rx_pkt_desc->length = pktlen;
			rx_pkt_desc->pool_id = sc->pd_pool->pool_id;
			rx_pkt_desc->ref = bufindex;
			rx_pkt_desc->data = slotbuf;
			rx_pkt_desc->ctx = slot_pdctx;

			total_bytes += pktlen;
		}
		num_new_pd_ctx -= n_zero_copy;
	}
	sc->num_new_pd_ctx = num_new_pd_ctx;
		
	/*
	 * Copy input
	 */
	if (n_copy > 0) {
		for (n = 0; n < n_copy; n++, rx_pkt_desc++) {
			slotbuf = if_netmap_rxslot(sc->nm_host_ctx, curslot, &bufindex, (void **)&slot_pdctx, &pktlen);
			TRACE(TRACE_RX_RING_STATE, "rx: slot %u: bufindex=%u ptr=%p pktlen=%u\n", curslot, bufindex, slot_pdctx, pktlen);
			TRACE(TRACE_RX_PKT, " rx: pktlen=%u [", pktlen);
			for (i = 0; i < PKT_TRACE_DEPTH; i++)
				TRACE_PLAIN(TRACE_RX_PKT, " %02x", ((uint8_t *)slotbuf)[i]);
			TRACE_PLAIN(TRACE_RX_PKT, " ]\n");
			curslot = if_netmap_rxslotnext(sc->nm_host_ctx, curslot);

			/* all other rx_pkt_desc fields were initialized by uinet_pd_mbuf_alloc_descs() */
			rx_pkt_desc->flags |= UINET_PD_TO_STACK;
			rx_pkt_desc->length = pktlen;
			TRACE(TRACE_RX_RING_OPS, "rx: slot %u: copying bufindex %u to mbuf\n", curslot, bufindex);
			memcpy(rx_pkt_desc->data, slotbuf, pktlen);

			total_bytes += pktlen;
		}
	}

	/* XXX not couting dropped packet bytes - should we? */
	if (n_drop > 0)
		curslot = if_netmap_rxslotaddn(sc->nm_host_ctx, curslot, n_drop);

	ifp->if_izcopies += n_zero_copy;
	ifp->if_icopies += n_copy;
	ifp->if_iqdrops += n_drop;
	ifp->if_ipackets += batch_size;
	ifp->if_ibytes += total_bytes;

	TRACE(TRACE_RX_BATCH, "rx: Sync\n");

	/*
	 * Return the processed ring slots to netmap
	 */
	avail -= batch_size;
	while (EBUSY == (rv = if_netmap_rxsync(sc->nm_host_ctx, &avail, &curslot, NULL)));
	if (rv != 0) {
		if_printf(ifp, "could not sync rx descriptors after receive\n");
	}
	/* assign to sc->rx_avail for use on next entry */
	sc->rx_avail = if_netmap_rxavail(sc->nm_host_ctx);

	UIF_TIMESTAMP(uif, sc->rx_pkts);
	
	/*
	 * Process the packets
	 */
	UIF_BATCH_EVENT(uif, UINET_BATCH_EVENT_START);

	if (uif->first_look_handler)
		TRACE(TRACE_RX_BATCH, "rx: Giving packets to first-look handler\n");

	UIF_FIRST_LOOK(uif, sc->rx_pkts);

	TRACE(TRACE_RX_BATCH, "rx: Sending packets to stack\n");
	uinet_pd_deliver_to_stack(uif, sc->rx_pkts);

	UIF_BATCH_EVENT(uif, UINET_BATCH_EVENT_FINISH);

	if (sc->rx_avail == 0)
		*fd = sc->fd; /* caller should block */
	else
		*fd = -1;  /* call again at earliest convenience */

	/* if avail prior to sync was non-zero, we were batch-limited */
	return (avail > 0);
}


static void
if_netmap_receive(void *arg)
{
	struct if_netmap_softc *sc;
	struct uinet_if *uif;
	uint64_t wait_ns_unused;
	int fd_unused;
	int done;
	int poll_wait_ms;

	sc = (struct if_netmap_softc *)arg;
	uif = sc->uif;

	if (uif->rx_cpu >= 0)
		sched_bind(curthread, uif->rx_cpu);

	TRACE(TRACE_CFG, "rx: thread bound to cpu %d\n", uif->rx_cpu);

	done = 0;
	poll_wait_ms = (curthread->td_stop_check_ticks * 1000) / hz;

	for (;;) {
		done = if_netmap_wait_for_avail(sc, &sc->rx_avail, UHI_POLLIN, if_netmap_rxavail, poll_wait_ms);

		if (done)
			break;

		if_netmap_batch_receive(uif, &fd_unused, &wait_ns_unused);
	}

	kthread_stop_ack();
}


static int
if_netmap_setup_interface(struct if_netmap_softc *sc)
{
	struct ifnet *ifp;
	struct uinet_if *uif;

	ifp = sc->ifp = if_alloc(IFT_ETHER);
	uif = sc->uif;

	if (uinet_uifsts(uif))
		ifp->if_init = if_netmap_sts_init;
	else
		ifp->if_init = if_netmap_init;
	ifp->if_softc = sc;

	if_initname(ifp, sc->uif->name, IF_DUNIT_NONE);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = if_netmap_ioctl;
	if (uinet_uifsts(uif))
		ifp->if_start = if_netmap_sts_start;
	else
		ifp->if_start = if_netmap_start;

	/* XXX what values? */
	IFQ_SET_MAXLEN(&ifp->if_snd, sc->txslots);
	ifp->if_snd.ifq_drv_maxlen = sc->txslots;

	IFQ_SET_READY(&ifp->if_snd);

	ether_ifattach(ifp, sc->addr);
	ifp->if_capabilities = ifp->if_capenable = IFCAP_HWSTATS;

	uif->pd_alloc = if_netmap_pd_alloc_user;
	uif->inject_tx_pkts = if_netmap_inject_tx_pkts;
	uif->batch_rx = if_netmap_batch_receive;
	uif->batch_tx = if_netmap_batch_send;
	uinet_if_attach(uif, sc->ifp, sc);

	if (!uinet_uifsts(uif)) {
		mtx_init(&sc->tx_lock, "txlk", NULL, MTX_DEF);
		cv_init(&sc->tx_cv, "txcv");

		if (kthread_add(if_netmap_send, sc, NULL, &sc->tx_thread, 0, 0, "nm_tx: %s", ifp->if_xname)) {
			if_printf(ifp, "Could not start transmit thread for %s (%s)\n", ifp->if_xname, sc->host_ifname);
			ether_ifdetach(ifp);
			if_free(ifp);
			return (1);
		}


		if (kthread_add(if_netmap_receive, sc, NULL, &sc->rx_thread, 0, 0, "nm_rx: %s", ifp->if_xname)) {
			if_printf(ifp, "Could not start receive thread for %s (%s)\n", ifp->if_xname, sc->host_ifname);
			ether_ifdetach(ifp);
			if_free(ifp);
			return (1);
		}
	}

	return (0);
}


int
if_netmap_detach(struct uinet_if *uif)
{
	struct if_netmap_softc *sc = uif->ifdata;
	struct thread_stop_req rx_tsr;
	struct thread_stop_req tx_tsr;
	uint32_t slotindex;
	uint32_t i;
	struct if_netmap_pd_pool *pool;

	if (sc) {
		if (!uinet_uifsts(uif)) {
			printf("%s (%s): Stopping rx thread\n", uif->name, uif->alias[0] != '\0' ? uif->alias : "");
			kthread_stop(sc->rx_thread, &rx_tsr);
			printf("%s (%s): Stopping tx thread\n", uif->name, uif->alias[0] != '\0' ? uif->alias : "");
			kthread_stop(sc->tx_thread, &tx_tsr);

			kthread_stop_wait(&rx_tsr);
			kthread_stop_wait(&tx_tsr);
		}

		/*
		 * Restore original set of buffer indices in the rings,
		 * otherwise netmap will leak buffers due to missing buffer
		 * indices that result from this driver's zero-copy receive
		 * and transmit operation.
		 */
		slotindex = 0;
		do {
			if_netmap_rxsetslot(sc->nm_host_ctx, &slotindex, sc->rx_ring_bufs[slotindex], NULL);
		} while (slotindex);

		slotindex = 0;
		do {
			if_netmap_txsetslot(sc->nm_host_ctx, &slotindex, sc->tx_ring_bufs[slotindex], NULL, 0, 0);
		} while (slotindex);
		
		pool = sc->pd_pool;
		if (--pool->num_interfaces == 0) {
			if (pool->num_extra) {
				if_netmap_set_bufshead(sc->nm_host_ctx, pool->extra_indices[0]);
				for (i = 0; i < pool->num_extra - 1; i++)
					if_netmap_buffer_set_next(sc->nm_host_ctx, pool->extra_indices[i], pool->extra_indices[i + 1]);
				if_netmap_buffer_set_next(sc->nm_host_ctx, pool->extra_indices[i], 0);
			}
		}

		printf("%s (%s): Interface stopped\n", uif->name, uif->alias[0] != '\0' ? uif->alias : "");

		uhi_close(sc->fd);
#if notyet
		/* XXX dealloc other sc mem */

		/* XXX ether_ifdetach, stop threads */

		if_netmap_deregister_if(sc->nm_host_ctx);

		if_netmap_pd_ctx_pool_destroy(sc);

		uhi_close(sc->fd);

		free(sc, M_DEVBUF);
#endif
	}

	return (0);
}


