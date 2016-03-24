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

#ifndef	_UINET_INTERNAL_H_
#define	_UINET_INTERNAL_H_

#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/vnet.h>

#include "uinet_api.h"
#include "uinet_if.h"

/* used by uinet_ifs in UINET_IF_TIMESTAMP_GLOBAL_COUNTER mode */
extern uint64_t global_timestamp_counter;

/* 32 bits is enough for more than one epoch per second for 100 years */
extern uint32_t epoch_number;

extern uint32_t instance_count;

struct uinet_instance {
	struct vnet *ui_vnet;
	struct uinet_sts_cfg ui_sts;
	void *ui_sts_evinstctx;
	void *ui_userdata;
	uint32_t ui_index;
};


extern struct uinet_instance uinst0;

void uinet_ifdestroy_all(struct uinet_instance *uinst);

void uinet_instance_init_vnet_sts(struct vnet_sts *sts, struct uinet_instance_cfg *cfg);
int uinet_instance_init(struct uinet_instance *uinst, struct vnet *vnet, struct uinet_instance_cfg *cfg);
void uinet_instance_shutdown(uinet_instance_t uinst);

int uinet_if_attach(uinet_if_t uif, struct ifnet *ifp, void *sc);

#endif /* _UINET_INTERNAL_H_ */

