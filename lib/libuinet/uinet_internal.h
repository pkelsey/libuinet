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

struct uinet_instance {
	struct vnet *ui_vnet;
	void *ui_userdata;
};

struct uinet_if {
	TAILQ_ENTRY(uinet_if) link;
	struct uinet_instance *uinst;
	uinet_iftype_t type;
	char *configstr;
	char name[IF_NAMESIZE];		/* assigned by driver */
	char alias[IF_NAMESIZE];	/* assigned by user (optional) */
	int cpu;
	unsigned int cdom;
	unsigned int ifindex;
	void *ifdata;			/* softc */
	void *ifp;			/* ifnet */
	void (*batch_event_handler)(void *arg, int event);
	void *batch_event_handler_arg;
};

extern struct uinet_instance uinst0;

void uinet_ifdestroy_all(struct uinet_instance *uinst);
struct uinet_if *uinet_iffind_byname(const char *ifname);

int uinet_instance_init(struct uinet_instance *uinst, struct vnet *vnet, struct uinet_instance_cfg *cfg);
void uinet_instance_shutdown(uinet_instance_t uinst);

#endif /* _UINET_INTERNAL_H_ */

