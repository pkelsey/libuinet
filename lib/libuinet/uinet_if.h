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

#ifndef	_UINET_IF_H_
#define	_UINET_IF_H_

#include <sys/queue.h>

#include "uinet_pkt_desc.h"


#define uinet_iftouif(ifp) ((ifp)->if_pspare[1])
#define uinet_uifsts(uif) ((uif)->uinst->ui_sts.sts_enabled)

struct ifnet;
struct vnet;

struct uinet_instance;

struct uinet_if_type_info {
	uinet_iftype_t type;
	const char *type_name;
	void (*default_cfg)(union uinet_if_type_cfg *cfg);
};

#define UINET_IF_REGISTER_TYPE(type_name, type_info)			\
static __attribute__((constructor)) void				\
uinet_if_register_type_ ## type_name(void) {				\
	uinet_if_register_type(type_info);				\
}

struct uinet_if {
	TAILQ_ENTRY(uinet_if) link;
	struct uinet_instance *uinst;
	uinet_iftype_t type;
	char *configstr;
	char name[IF_NAMESIZE];		/* assigned by driver */
	char alias[IF_NAMESIZE];	/* assigned by user (optional) */
	int rx_cpu;
	int tx_cpu;
	uint32_t rx_batch_size;
	uint32_t tx_inject_queue_len;
	uinet_if_timestamp_mode_t timestamp_mode;
	uint64_t timestamp_counter;
	union uinet_if_type_cfg type_cfg;

	unsigned int ifindex;
	void *sts_evifctx;		/* event system context for sts mode*/
	void *ifdata;			/* softc */
	struct ifnet *ifp;		/* ifnet */

	/*
	 * Optional handler for batch-related events.  Can be used by an
	 * event system to reduce event activation overhead.
	 */
	void (*batch_event_handler)(void *arg, int event);
	void *batch_event_handler_arg;

	/* Application-installed handler that is passed received packets before they are sent to the stack. */
	void (*first_look_handler)(void *arg, struct uinet_pd_list *pkts);
	void *first_look_handler_arg;

	/* Invoked to allocate packet descriptors suitable for zero-copy transmit on this interface */
	void (*pd_alloc)(struct uinet_if *uif, struct uinet_pd_list *pkts);

	/* Invoked to send packets directly to the transmit interface. */
	void (*inject_tx_pkts)(struct uinet_if *uif, struct uinet_pd_list *pkts);

	/* Perform a non-blocking batch receive. */
	int (*batch_rx)(struct uinet_if *uif, int *fd, uint64_t *wait_ns);

	/* Perform a non-blocking batch transmit. */
	int (*batch_tx)(struct uinet_if *uif, int *fd, uint64_t *wait_ns);
};

#define UIF_BATCH_EVENT(uif_, e_) if ((uif_)->batch_event_handler) (uif_)->batch_event_handler((uif_)->batch_event_handler_arg, (e_))
#define UIF_FIRST_LOOK(uif_, p_) if ((uif_)->first_look_handler) (uif_)->first_look_handler((uif_)->first_look_handler_arg, (p_))
#define UIF_PD_ALLOC(uif_, p_) (uif_)->pd_alloc((uif_), (p_))
#define UIF_INJECT_TX(uif_, p_) (uif_)->inject_tx_pkts((uif_), (p_))
#define UIF_BATCH_RX(uif_, fd_, ns_) (uif_)->batch_rx((uif_), (fd_), (ns_))
#define UIF_BATCH_TX(uif_, fd_, ns_) (uif_)->batch_tx((uif_), (fd_), (ns_))
#define UIF_TIMESTAMP(uif_, p_) if ((uif_)->timestamp_mode != UINET_IF_TIMESTAMP_NONE) uinet_if_pd_timestamp((uif_), (p_))

int uinet_if_attach(struct uinet_if *uif, struct ifnet *ifp, void *sc);
const struct uinet_if_type_info *uinet_if_get_type_info(uinet_iftype_t type);
void uinet_if_pd_timestamp(struct uinet_if *uif, struct uinet_pd_list *pkts);

/* only used in SYSINIT via UINET_IF_REGISTER_TYPE() */
void uinet_if_register_type(const void *arg);

#endif /* _UINET_IF_H_ */

