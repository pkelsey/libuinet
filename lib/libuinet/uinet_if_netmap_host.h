/*
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

#ifndef _UINET_IF_NETMAP_HOST_H_
#define _UINET_IF_NETMAP_HOST_H_

struct if_netmap_host_context;

struct if_netmap_host_context *if_netmap_register_if(int nmfd, const char *ifname, unsigned int isvale, unsigned int qno, unsigned int *num_extra_bufs);
void if_netmap_deregister_if(struct if_netmap_host_context *ctx);
uint32_t if_netmap_get_bufshead(struct if_netmap_host_context *ctx);
void if_netmap_set_bufshead(struct if_netmap_host_context *ctx, uint32_t head);
uint32_t if_netmap_buffer_get_next(struct if_netmap_host_context *ctx, uint32_t index);
void if_netmap_buffer_set_next(struct if_netmap_host_context *ctx, uint32_t index, uint32_t next_index);
uint32_t *if_netmap_buffer_address(struct if_netmap_host_context *ctx, uint32_t index);
int if_netmap_rxsync(struct if_netmap_host_context *ctx, const uint32_t *avail, const uint32_t *cur, const uint32_t *reserved);
uint32_t if_netmap_rxavail(struct if_netmap_host_context *ctx);
uint32_t if_netmap_rxcur(struct if_netmap_host_context *ctx);
uint32_t if_netmap_rxreserved(struct if_netmap_host_context *ctx);
uint32_t if_netmap_rxslots(struct if_netmap_host_context *ctx);
uint32_t if_netmap_rxbufsize(struct if_netmap_host_context *ctx);
void *if_netmap_rxslot(struct if_netmap_host_context *ctx, uint32_t slotno, uint32_t *index, void **ptr, uint32_t *len);
uint32_t if_netmap_rxslotnext(struct if_netmap_host_context *ctx, uint32_t curslot);
uint32_t if_netmap_rxslotaddn(struct if_netmap_host_context *ctx, uint32_t curslot, uint32_t n);
void if_netmap_rxsetslot(struct if_netmap_host_context *ctx, uint32_t *slotno, uint32_t index, void *ptr);
void if_netmap_rxsetslotptr(struct if_netmap_host_context *ctx, uint32_t slotno, void *ptr);
void if_netmap_txupdate(struct if_netmap_host_context *ctx, const uint32_t *avail, const uint32_t *cur);
int if_netmap_txsync(struct if_netmap_host_context *ctx, const uint32_t *avail, const uint32_t *cur);
uint32_t if_netmap_txavail(struct if_netmap_host_context *ctx);
uint32_t if_netmap_txcur(struct if_netmap_host_context *ctx);
uint32_t if_netmap_txslots(struct if_netmap_host_context *ctx);
void *if_netmap_txslot(struct if_netmap_host_context *ctx, uint32_t slotno, uint32_t *index, void **ptr);
uint32_t if_netmap_txslotnext(struct if_netmap_host_context *ctx, uint32_t slotno);
void if_netmap_txsetslot(struct if_netmap_host_context *ctx, uint32_t *slotno, uint32_t index, void *ptr, uint32_t len, int report);
void if_netmap_txsetslotptr(struct if_netmap_host_context *ctx, uint32_t slotno, void *ptr);
int if_netmap_set_offload(struct if_netmap_host_context *ctx, int on);
int if_netmap_set_promisc(struct if_netmap_host_context *ctx, int on);


#endif /* _UINET_IF_NETMAP_HOST_H_ */
