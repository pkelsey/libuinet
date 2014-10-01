/*-
 * Copyright (c) 2013-2014 Patrick Kelsey. All rights reserved.
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
#include <sys/mbuf.h>

#include <net/if_promiscinet.h>

#include <netinet/in_promisc.h>


uma_zone_t if_promiscinet_tag_zone;

static int if_promiscinet_tag_init(void *mem, int size, int flags);
static void if_promiscinet_tag_free(struct m_tag *tag);


static void
if_promiscinet_init(__unused void *arg)
{

	if_promiscinet_tag_zone = uma_zcreate("promiscinet_tags",
					      sizeof(struct ifl2info),
					      NULL, NULL,
					      if_promiscinet_tag_init, NULL,
					      UMA_ALIGN_PTR, 0);
}
SYSINIT(promiscinet, SI_SUB_INIT_IF, SI_ORDER_ANY, if_promiscinet_init, NULL);


static int
if_promiscinet_tag_init(void *mem, int size, int flags)
{
	struct m_tag *t = mem;
	m_tag_setup(t, MTAG_PROMISCINET, MTAG_PROMISCINET_L2INFO, MTAG_PROMISCINET_L2INFO_LEN);
	t->m_tag_free = if_promiscinet_tag_free;
	return (0);
}


static void
if_promiscinet_tag_free(struct m_tag *tag)
{

	uma_zfree(if_promiscinet_tag_zone, tag);
}


int
if_promiscinet_add_tag(struct mbuf *m, struct in_l2info *l2i)
{
	struct ifl2info *l2info_tag;

	l2info_tag = if_promiscinet_tag_alloc();
	if (NULL == l2info_tag) {
		return (ENOMEM);
	}

	in_promisc_l2info_copy(&l2info_tag->ifl2i_info, l2i);
	m_tag_prepend(m, &l2info_tag->ifl2i_mtag);

	return (0);
}
