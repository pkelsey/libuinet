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
 * Kernel support routines for Promiscuous INET functionality.
 */

#include "opt_promiscinet.h"

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
#include <netinet/in_promisc.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>	/* required for icmp_var.h */
#include <netinet/icmp_var.h>	/* for ICMP_BANDLIM */
#include <netinet/tcp_syncache.h>


struct syn_filter_internal {
	struct syn_filter params;	/* must be first in struct */
	unsigned int refcount;
	SLIST_ENTRY(syn_filter_internal) next;
};

struct syn_filter_instance {
	struct syn_filter_internal *sfi;
	char ctor_arg[SYNF_ARG_MAX];
	void *instance_arg;
};

static void syn_filter_run_destructor(struct inpcb *inp);

static struct mtx syn_filter_mtx;
MTX_SYSINIT(syn_filter, &syn_filter_mtx, "syn_filter_mtx", MTX_DEF);

#define	SYN_FILTER_LOCK()		mtx_lock(&syn_filter_mtx)
#define	SYN_FILTER_UNLOCK()		mtx_unlock(&syn_filter_mtx)
#define SYN_FILTER_ASSERT_LOCKED()	mtx_assert(&syn_filter_mtx, MA_OWNED);

static SLIST_HEAD(, syn_filter_internal) syn_filter_head =
	SLIST_HEAD_INITIALIZER(syn_filter_head);

MALLOC_DEFINE(M_SYNF, "synf", "SYN filter data");

static uma_zone_t zone_label;
static int syn_filters_unloadable = 0;

SYSCTL_NODE(_net_inet, OID_AUTO, synf, CTLFLAG_RW, 0, "SYN filters");
SYSCTL_INT(_net_inet_synf, OID_AUTO, unloadable, CTLFLAG_RW, &syn_filters_unloadable, 0,
	   "Allow unload of SYN filters (not recommended)");


static void
in_promisc_init(void)
{
	zone_label = uma_zcreate("in_l2info", sizeof(struct in_l2info),
				 NULL, NULL, NULL, NULL,
				 UMA_ALIGN_PTR, 0);
}


struct in_l2info *
in_promisc_l2info_alloc(int flags)
{
	return (uma_zalloc(zone_label, flags | M_ZERO));
}


void
in_promisc_l2info_free(struct in_l2info *l2info)
{
	uma_zfree(zone_label, l2info);
}


void
in_promisc_l2info_copy(struct in_l2info *dst, const struct in_l2info *src)
{
	memcpy(dst->inl2i_local_addr, src->inl2i_local_addr,
	       IN_L2INFO_ADDR_MAX);
	memcpy(dst->inl2i_foreign_addr, src->inl2i_foreign_addr,
	       IN_L2INFO_ADDR_MAX);

	dst->inl2i_flags = src->inl2i_flags;

	in_promisc_l2tagstack_copy(&dst->inl2i_tagstack, &src->inl2i_tagstack);
}


void
in_promisc_l2info_copy_swap(struct in_l2info *dst, const struct in_l2info *src)
{
	memcpy(dst->inl2i_local_addr, src->inl2i_foreign_addr,
	       IN_L2INFO_ADDR_MAX);
	memcpy(dst->inl2i_foreign_addr, src->inl2i_local_addr,
	       IN_L2INFO_ADDR_MAX);

	dst->inl2i_flags = src->inl2i_flags;

	in_promisc_l2tagstack_copy(&dst->inl2i_tagstack, &src->inl2i_tagstack);
}


void
in_promisc_l2tagstack_copy(struct in_l2tagstack *dst, const struct in_l2tagstack *src)
{
	memcpy(dst, src, sizeof(*dst));
}


int
in_promisc_tagcmp(const struct in_l2tagstack *l2ts1, const struct in_l2tagstack *l2ts2)
{
	uint32_t tagcnt1, tagcnt2;
	uint32_t i1, i2;

	tagcnt1 = l2ts1 ? l2ts1->inl2t_cnt : 0;
	tagcnt2 = l2ts2 ? l2ts2->inl2t_cnt : 0;

	/* Fast compare for empty tag stacks */
	if (tagcnt1 + tagcnt2 == 0)
		return (0);

	/*
	 * Compare tag stacks without considering zero-masked tags.
	 */

	i1 = 0;
	i2 = 0;
	while (1) {
		/* skip zero-masked tags */
		while (tagcnt1 && !l2ts1->inl2t_masks[i1]) {
			tagcnt1--;
			i1++;
		}

		while (tagcnt2 && !l2ts2->inl2t_masks[i2]) {
			tagcnt2--;
			i2++;
		}

		if (!tagcnt1 || !tagcnt2) {
			/* Ran out of tags in one or both stacks. */

			if (!tagcnt1 && !tagcnt2) {
				/*
				 * Ran out of tags in both stacks without
				 * any miscompares.
				 */
				return (0);
			}

			/*
			 * Ran out of tags in one stack and the other stack
			 * has at least one more tag with non-zero mask.
			 */
			return (1);
		}
		
		if ((l2ts1->inl2t_tags[i1] & l2ts1->inl2t_masks[i1]) !=
		    (l2ts2->inl2t_tags[i2] & l2ts2->inl2t_masks[i2]))
			return (1);

		tagcnt1--; i1++;
		tagcnt2--; i2++;
	}
}


int
in_promisc_socket_init(struct socket *so, int flags)
{
	so->so_l2info = in_promisc_l2info_alloc(flags);
	if (NULL == so->so_l2info)
		return (ENOMEM);

	return (0);
}


void
in_promisc_socket_destroy(struct socket *so)
{
	if (so->so_l2info != NULL) {
		in_promisc_l2info_free(so->so_l2info);
		so->so_l2info = NULL;
	}
}


void
in_promisc_socket_newconn(struct socket *head, struct socket *so)
{
	so->so_l2info->inl2i_flags = head->so_l2info->inl2i_flags & ~INL2I_TAG_ANY;

	in_promisc_l2tagstack_copy(&so->so_l2info->inl2i_tagstack,
				   &head->so_l2info->inl2i_tagstack);
}


int
in_promisc_inpcb_init(struct inpcb *inp, int flags)
{
	inp->inp_l2info = in_promisc_l2info_alloc(flags);
	if (NULL == inp->inp_l2info)
		return (ENOMEM);

	if (inp->inp_socket->so_options & SO_PROMISC)
		inp->inp_flags2 |= INP_PROMISC;

	return (0);
}


void
in_promisc_inpcb_destroy(struct inpcb *inp)
{
	INP_WLOCK_ASSERT(inp);

	if (inp->inp_l2info != NULL) {
		in_promisc_l2info_free(inp->inp_l2info);
		inp->inp_l2info = NULL;
	}

	syn_filter_run_destructor(inp);
}


static struct syn_filter_internal *
syn_filter_get_locked(const char *name)
{
	struct syn_filter_internal *p;

	SYN_FILTER_ASSERT_LOCKED();

	SLIST_FOREACH(p, &syn_filter_head, next)
		if (strcmp(p->params.synf_name, name) == 0)
			break;

	return (p);
}


static struct syn_filter_internal *
syn_filter_alloc(struct syn_filter *params)
{
	struct syn_filter_internal *sfi;

	sfi = malloc(sizeof(*sfi), M_SYNF, M_WAITOK);
	if (NULL != sfi) {
		memcpy(&sfi->params, params, sizeof(*params));
		refcount_init(&sfi->refcount, 1);
	}

	return (sfi);
}


static void
syn_filter_free(struct syn_filter_internal *sfi)
{
	free(sfi, M_SYNF);
}


static void *
syn_filter_attach(const char *name)
{
	struct syn_filter_internal *sfi;

	SYN_FILTER_LOCK();
	sfi = syn_filter_get_locked(name);
	if (sfi) {
		refcount_acquire(&sfi->refcount);
	}
	SYN_FILTER_UNLOCK();

	return (sfi);
}


static void
syn_filter_detach_locked(struct syn_filter_internal *sfi)
{
	SYN_FILTER_ASSERT_LOCKED();	
	if (refcount_release(&sfi->refcount)) {
		SLIST_REMOVE(&syn_filter_head, sfi, syn_filter_internal, next);
		syn_filter_free(sfi);
	}
}


static void
syn_filter_detach(struct syn_filter_internal *sfi)
{
	SYN_FILTER_LOCK();
	syn_filter_detach_locked(sfi);
	SYN_FILTER_UNLOCK();
}


static int
syn_filter_null_callback(struct inpcb *inp, void *inst_arg,
			 struct syn_filter_cbarg *arg)
{
	return (SYNF_REJECT_SILENT);
}


/*
 * Run the filter callback safely with respect to whether the filters are
 * unloadable.
 */
int
syn_filter_run_callback(struct inpcb *inp, struct syn_filter_cbarg *arg)
{
	struct syn_filter_instance *sfinst;
	struct syn_filter_internal *sfi;
	int result = SYNF_ACCEPT;

	INP_RLOCK_ASSERT(inp);

	sfinst = (struct syn_filter_instance *)inp->inp_synf;
	if (sfinst) {
		sfi = sfinst->sfi;
		if (syn_filters_unloadable) {
			/*
			 * N.B. This serializes execution of all SYN filter
			 * routines in the system.
			 */
			SYN_FILTER_LOCK();
			result = sfi->params.synf_callback(inp,
							   sfinst->instance_arg,
							   arg);
			SYN_FILTER_UNLOCK();
		} else {
			result = sfi->params.synf_callback(inp,
							   sfinst->instance_arg,
							   arg);	
		}
	}

	return (result);
}


/*
 * Run the filter constructor safely with respect to whether the filters are
 * unloadable.
 */
static void *
syn_filter_run_constructor(struct inpcb *inp)
{
	struct syn_filter_instance *sfinst;
	struct syn_filter_internal *sfi;
	void *result = inp;  /* Default result is anything non-NULL as NULL
			      * indicates failure.
			      */

	INP_WLOCK_ASSERT(inp);

	sfinst = (struct syn_filter_instance *)inp->inp_synf;
	sfi = sfinst->sfi;
	if (syn_filters_unloadable) {
		/*
		 * N.B. This serializes execution of all SYN filter routines
		 * in the system.
		 */
		SYN_FILTER_LOCK();
		if (sfi->params.synf_create)
			result = sfi->params.synf_create(inp, sfinst->ctor_arg);
		SYN_FILTER_UNLOCK();
	} else {
		if (sfi->params.synf_create)
			result = sfi->params.synf_create(inp, sfinst->ctor_arg);	
	}

	return (result);
}


/*
 * Run the filter destructor safely with respect to whether the filters are
 * unloadable.
 */
static void
syn_filter_run_destructor(struct inpcb *inp)
{
	struct syn_filter_instance *sfinst;
	struct syn_filter_internal *sfi;

	INP_WLOCK_ASSERT(inp);

	sfinst = (struct syn_filter_instance *)inp->inp_synf;
	if (sfinst) {
		sfi = sfinst->sfi;
		if (syn_filters_unloadable) {
			/*
			 * N.B. This serializes execution of all SYN filter
			 * routines in the system.
			 */
			SYN_FILTER_LOCK();
			if (sfi->params.synf_destroy)
				sfi->params.synf_destroy(inp, sfinst->instance_arg);
			syn_filter_detach_locked(sfi);
			SYN_FILTER_UNLOCK();
		} else {
			if (sfi->params.synf_destroy)
				sfi->params.synf_destroy(inp, sfinst->instance_arg);	
			syn_filter_detach(sfi);
		}

		free(sfinst, M_SYNF);
		inp->inp_synf = NULL;
	}

	inp->inp_flags2 &= ~INP_SYNFILTER;
}


static int
syn_filter_add(struct syn_filter *sf)
{
	struct syn_filter_internal *p;
	int error = 0;

	SYN_FILTER_LOCK();
	SLIST_FOREACH(p, &syn_filter_head, next)
		if (strcmp(p->params.synf_name, sf->synf_name) == 0)  {
			if (p->params.synf_callback != syn_filter_null_callback) {
				SYN_FILTER_UNLOCK();
				return (EEXIST);
			} else {
				p->params.synf_callback = sf->synf_callback;
				SYN_FILTER_UNLOCK();
				return (0);
			}
		}
				
	if (NULL == p) {
		p = syn_filter_alloc(sf);
		if (NULL != p)
			SLIST_INSERT_HEAD(&syn_filter_head, p, next);
		else
			error = ENOMEM;
	}
	SYN_FILTER_UNLOCK();

	return (error);
}


static int
syn_filter_del(const char *name)
{
	struct syn_filter_internal *sfi;

	SYN_FILTER_LOCK();
	sfi = syn_filter_get_locked(name);
	if (sfi) {
		/*
		 * Redirect the filter callback to the null_callback to
		 * handle the case where the filter is still attached to a
		 * socket when the module is removed.
		 */
		sfi->params.synf_callback = syn_filter_null_callback;
		syn_filter_detach_locked(sfi);
	} else {
		log(LOG_WARNING, "Attempt to remove non-existent SYN filter %s", name);
	}
	SYN_FILTER_UNLOCK();

	return (0);
}


int
syn_filter_generic_mod_event(module_t mod, int event, void *data)
{
	struct syn_filter *sf = (struct syn_filter *)data;
	int error;

	switch (event) {
	case MOD_LOAD:
		error = syn_filter_add(sf);
		break;

	case MOD_UNLOAD:
		if (syn_filters_unloadable)
			error = syn_filter_del(sf->synf_name);
		else
			error = EOPNOTSUPP;

		break;

	case MOD_SHUTDOWN:
		error = 0;
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}


int
syn_filter_getopt(struct socket *so, struct sockopt *sopt)
{
	struct inpcb *inp = sotoinpcb(so);
	struct syn_filter_instance *sfinst;
	struct syn_filter_internal *sfi;
	struct syn_filter_optarg *sfa_out;
	int error = 0;

	sfa_out = malloc(sizeof(*sfa_out), M_TEMP, M_WAITOK | M_ZERO);

	if ((so->so_options & SO_PROMISC) == 0) {
		error = EINVAL;
		goto out;
	}

	INP_RLOCK(inp);
	sfinst = (struct syn_filter_instance *)inp->inp_synf;
	sfi = sfinst->sfi;
	if (sfi) {
		strcpy(sfa_out->sfa_name, sfi->params.synf_name);
		/* use memcpy, not strcpy, to support non-string uses of sfa_arg */
		memcpy(sfa_out->sfa_arg, sfinst->ctor_arg, sizeof(sfa_out->sfa_arg));
	} else {
		sfa_out->sfa_name[0] = '\0';
		sfa_out->sfa_arg[0] = '\0';
	}
	INP_RUNLOCK(inp);

out:
	if (0 == error)
		error = sooptcopyout(sopt, sfa_out, sizeof(*sfa_out));
	free(sfa_out, M_TEMP);
	return (error);
}


int
syn_filter_setopt(struct socket *so, struct sockopt *sopt)
{
	struct inpcb *inp = sotoinpcb(so);
	int error = 0;

	if ((so->so_options & SO_PROMISC) == 0) {
		return (EINVAL);
	}

	switch (sopt->sopt_name) {
	case IP_SYNFILTER:
	{
		struct syn_filter_optarg *sfa;
		struct syn_filter_internal *sfi;
		struct syn_filter_instance *sfinst = NULL;

		/*
		 * Handle the simple delete case first.
		 */
		if (sopt->sopt_val == NULL) {
			INP_WLOCK(inp);
			syn_filter_run_destructor(inp);
			INP_WUNLOCK(inp);

			return (0);
		}

		sfa = malloc(sizeof(*sfa), M_TEMP, M_WAITOK);
		sfinst = malloc(sizeof(*sfinst), M_SYNF, M_WAITOK);

		error = sooptcopyin(sopt, sfa, sizeof *sfa, sizeof *sfa);
		if (error) {
			free(sfa, M_TEMP);
			return (error);
		}

		sfa->sfa_name[sizeof(sfa->sfa_name)-1] = '\0';
		sfa->sfa_arg[sizeof(sfa->sfa_arg)-1] = '\0';

		INP_WLOCK(inp);

		/* Must delete the old one before installing a new one. */
		if (NULL != inp->inp_synf) {
			error = EINVAL;
			goto out;
		}

		sfi = syn_filter_attach(sfa->sfa_name);

		if (NULL == sfi) {
			error = ENOENT;
			goto out;
		}
	
		sfinst->sfi = sfi;
		/* use memcpy, not strcpy, to support non-string uses of sfa_arg */
		memcpy(sfinst->ctor_arg, sfa->sfa_arg, sizeof(sfinst->ctor_arg));

		inp->inp_synf = sfinst;
		sfinst->instance_arg = syn_filter_run_constructor(inp);

		if (NULL == sfinst->instance_arg) {
			syn_filter_detach(sfi);
			inp->inp_synf = NULL;
			error = EINVAL;
			goto out;
		}

		inp->inp_flags2 |= INP_SYNFILTER;
		sfinst = NULL;
	out:
		INP_WUNLOCK(inp);

		if (NULL != sfinst)
			free(sfinst, M_SYNF);

		free(sfa, M_TEMP);
		break;
	}

	case IP_SYNFILTER_RESULT:
	{
		struct syn_filter_cbarg cbarg;

		error = sooptcopyin(sopt, &cbarg, sizeof cbarg, sizeof cbarg);
		if (error) {
			return (error);
		}

		switch (cbarg.decision) {
		case SYNF_REJECT_SILENT:
			m_freem(cbarg.m);
			break;
		case SYNF_REJECT_RST:
			INP_WLOCK(inp);
			/* The following is what tcp_dropwithreset() does
			 * when only TH_SYN is set and none of the addresses
			 * are broadcast or multicast, which is the case
			 * with anything that makes it to syncache_add(),
			 * which is on the only path to here.
			 */
			if (badport_bandlim(BANDLIM_RST_CLOSEDPORT) < 0)
				m_freem(cbarg.m);
			else {
				/* tcp_respond consumes the mbuf chain. */
				tcp_respond(sototcpcb(so), mtod(cbarg.m, void *), &cbarg.th, cbarg.m, cbarg.th.th_seq+1,
					    (tcp_seq)0, TH_RST|TH_ACK);
			}

			INP_WUNLOCK(inp);
			break;
		case SYNF_ACCEPT:
			INP_INFO_WLOCK(&V_tcbinfo);
			INP_WLOCK(inp);
			syncache_add(&cbarg.inc, &cbarg.to, &cbarg.th, inp, &so, cbarg.m, cbarg.initial_timeout);
		
			/* syncache_add performs the INP_WUNLOCK(inp) and INP_INFO_WUNLOCK(&V_tcbinfo) */
			break;
		default:
			error = EINVAL;
			break;
		}

		break;
	}

	}

	return (error);
}



/*
 * The following is adapted from Austin Appleby's MurmurHash3.[h,cpp],
 * http://smhasher.googlecode.com/svn, revision 150.  In this use we do not
 * care about the fact that different results will be obtained for the same
 * input on different endian platforms, as it is used for internal hashing
 * (we only care about overall hash quality).  Also, in this use we do not
 * care about the implementation assumption that unaligned 32-bit reads are
 * OK, since it will only be applied to 32-bit aligned data.
 */


#define	FORCE_INLINE static inline __attribute__((always_inline))

static inline uint32_t rotl32 ( uint32_t x, int8_t r )
{
  return (x << r) | (x >> (32 - r));
}

#define	ROTL32(x,y)	rotl32(x,y)


//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche

FORCE_INLINE uint32_t fmix32 ( uint32_t h )
{
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;

  return h;
}


//-----------------------------------------------------------------------------

/*
 * This is MurmurHash3_x86_32 with 32-bit aligned input that is a multiple
 * of 32-bits in length, so there are no unaligned accesses, nor is there
 * any need for a tail computation.  Note that all 32-bit blocks with a
 * corresponding mask of zero are ignored in the computation, including that
 * the effective block count incorporated into the hash does not include
 * them.
 */
uint32_t in_promisc_hash32 ( const uint32_t * key, const uint32_t *masks, int nblocks, uint32_t seed )
{
  uint32_t h1 = seed;

  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  //----------
  // body

  const uint32_t * blocks = key + nblocks;
  const uint32_t * block_masks = masks + nblocks;

  for(int i = -nblocks; i; i++)
  {
    if (block_masks[i]) {
      uint32_t k1 = blocks[i] & block_masks[i];

      k1 *= c1;
      k1 = ROTL32(k1,15);
      k1 *= c2;
    
      h1 ^= k1;
      h1 = ROTL32(h1,13); 
      h1 = h1*5+0xe6546b64;
    } else {
      nblocks--;
    }
  }

  //----------
  // finalization

  h1 ^= (nblocks << 2);

  h1 = fmix32(h1);

  return (h1);
} 

//-----------------------------------------------------------------------------




SYSINIT(in_promisc, SI_SUB_PROTO_DOMAIN, SI_ORDER_ANY, in_promisc_init, NULL);
