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

#ifndef	_UINET_PKT_DESC_H_
#define	_UINET_PKT_DESC_H_


#include "uinet_api_types.h"

/*
 * The packet descriptor facility was designed to provide an efficient means
 * for:
 *
 *     1. Zero-copy injection of packets into an interface's transmit path
 *        from the receive path of another interface or from the
 *        application
 *
 *     2. Zero-copy passing of received packets to the stack
 *
 *     3. Elimination of mbuf allocation in the receive path
 *
 *     4. Zero-copy injection of a set of packets received on one interface
 *        into the transmit path of one or more other interfaces plus
 *        zero-copy passing of the same set of packets to the stack
 *
 * The packet descriptor representation has been carefully split into two
 * parts:
 *
 *     struct uinet_pd contains the minimal set of information required to
 *     forward, after optionally inspecting the payload of, packets from one
 *     interface to another.  struct uinet_pd is always passed by value via
 *     arrays (treated either as lists or rings), so a given struct uinet_pd
 *     only has one owner at any given time.
 *
 *     struct uinet_pd_ctx contains all other information associated with
 *     each packet that might be required for processing outside of the
 *     leanest inspect-and-forward-to-single-other-interface path
 *     (refcounts, mbuf pointers...), as well as information that is
 *     sufficient for maintaining pools of interface packet buffers.
 *
 * Given the above, removal of new packets from an interface receive ring
 * consists of populating an array of struct uinet_pd using the information
 * from the array of receive ring slots.  Passing those packets to another
 * interface then requires copying that array to an input queue (another
 * array) of that interface, and subsequent transmission on that second
 * interface requires populating its transmit ring using the information
 * from that input queue (array).  This is the leanest packet transfer
 * sequence, requiring no payload data accesses and no dereferencing of
 * struct uinet_pd_ctx data (which are in general allocated from a pool and
 * thus non-colocated in memory).
 *
 * If packet inspection is required in the above transfer path, then the
 * overhead of payload access (via the data pointer in struct uinet_pd) is
 * added.
 *
 * If the packets are to go to more than one destination, then the overhead
 * of dereferencing the struct uinet_pd_ctx pointer in struct uinet_pd is
 * added, as is the overhead of incrementing the reference count pointed to
 * by struct uinet_pd_ctx (which may or may not be contained in struct
 * uinet_pd_ctx, depending on the descriptor type).
 *
 * If one of the packet destinations is the stack, then there is the
 * overhead of dereferencing the mbuf pointed to by struct uinet_pd_ctx (to
 * initialize its length and receive interface members).  Of course, this
 * path also means you are going to spend a lot in stack processing anyway.
 *
 * The allocation path for struct uinet_pd_ctx, at least for ring-based
 * packet interfaces, is meant to be from a pool that allows arrays of
 * descriptors to be allocated in one operation.
 *
 * The free path for struct uinet_pd_ctx, given arrays of descriptors,
 * batches descriptors being returned to the same pool to be freed in single
 * operations whenever it can.
 *
 */


#define UINET_PD_FREE_BATCH_SIZE	32

struct uinet_pd_pool_info {
	unsigned int type;
	unsigned int bufsize;
	void *ctx;

	/*
	 * Invoked on packet descriptors whose last reference has been
	 * released.
	 */
	void (*free)(struct uinet_pd_ctx *first[], unsigned int n);
};


#define UINET_PD_TYPE_MASK	0x0007

/* XXX now that there are pool ids, these should be able to go away */
#define UINET_PD_TYPE_NETMAP	0x0000
#define UINET_PD_TYPE_MBUF	0x0001
#define UINET_PD_TYPE_PTR	0x0002

#define UINET_PD_CTX_SINGLE_REF	0x0001	/* Packet descriptor will be freed without examining refcount */
#define UINET_PD_CTX_MBUF_USED	0x0002	/* The associated mbuf must be reinitialized upon release of last ref */

#define uinet_pd_type(pd)	((pd)->flags & UINET_PD_TYPE_MASK)

struct uinet_pd_ctx {
	uint64_t timestamp;  /* this should really be in the pd and in the mbuf instead of here */
	struct mbuf *m;
	uintptr_t ref;
	uint16_t m_orig_len; /* used for remembering original packet length when passing to the stack */
	uint16_t flags;
	uint16_t pool_id;
	volatile unsigned int *refcnt;
	volatile unsigned int builtin_refcnt;
};

/* XXX struct uinet_pd, struct uinet_pd_list in uinet_api_types.h
 */

#define UINET_PD_XLIST_MAX_DESCS	16

/* extensible pd list */
/* XXX maybe this should merge with uinet_pd_list? */
struct uinet_pd_xlist {
	struct uinet_pd_xlist *next;
	struct uinet_pd_list list;
};


struct uinet_pd_ring {
	uint32_t num_descs;
	uint32_t put;
	uint32_t take;
	uint32_t drops;
	struct uinet_pd descs[0];
};


static inline uint32_t
uinet_pd_ring_space(const struct uinet_pd_ring *ring)
{
	/*  
	 * (1) put == take means ring empty
	 * (2) put == take - 1 (mod ring size) means ring full
	 * (3) one slot is always kept empty to ensure (1)
	 *     (the maxmimum return value is thus num_descs - 1)
	 */
	int space = (int)ring->take - (int)ring->put - 1;
	if (space < 0)
		space += ring->num_descs;
	return ((uint32_t)space);
}


static inline uint32_t
uinet_pd_ring_avail(const struct uinet_pd_ring *ring)
{
	return (ring->num_descs - uinet_pd_ring_space(ring) - 1);
}


static inline uint32_t
uinet_pd_ring_next(const struct uinet_pd_ring *ring, uint32_t cur)
{
	return ((cur + 1 == ring->num_descs) ? 0 : cur + 1);
}


int uinet_pd_pool_register(struct uinet_pd_pool_info *pool_info);
void uinet_pd_pool_deregister(unsigned int pool_id);
struct uinet_pd_pool_info *uinet_pd_pool_get(unsigned int pool_id);

unsigned int uinet_pd_mbuf_alloc_descs(struct uinet_pd_list *to, unsigned int n);
void uinet_pd_mbuf_free_descs(struct uinet_pd_ctx *pdctx[], unsigned int n);

struct uinet_pd_ring *uinet_pd_ring_alloc(uint32_t num_descs);
void uinet_pd_ring_free(struct uinet_pd_ring *ring);

void uinet_pd_drop_injected(struct uinet_pd *pd, uint32_t n);

struct uinet_pd_xlist *uinet_pd_xlist_pool_alloc(void);
void uinet_pd_xlist_pool_free(struct uinet_pd_xlist *xlist);
int uinet_pd_xlist_add_mbuf(struct uinet_pd_xlist **head, struct uinet_pd_xlist **tail,
			    struct mbuf *m, uint16_t flags, uint64_t serialno);
void uinet_pd_xlist_release(struct uinet_pd_xlist *xlist);
void uinet_pd_xlist_release_all(struct uinet_pd_xlist *xlist);
struct uinet_pd_xlist *uinet_pd_xlist_free(struct uinet_pd_xlist *xlist, struct uinet_pd_xlist *stop_at);

#endif /* _UINET_PKT_DESC_H_ */
