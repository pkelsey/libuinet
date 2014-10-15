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


#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include "uinet_internal.h"
#include "uinet_if_netmap.h"
#include "uinet_if_pcap.h"
#include "uinet_if_bridge.h"
#include "uinet_if_span.h"

static VNET_DEFINE(TAILQ_HEAD(config_head, uinet_if), uinet_if_list);
#define V_uinet_if_list VNET(uinet_if_list)


static void
vnet_if_list_init(const void *unused __unused)
{
	TAILQ_INIT(&V_uinet_if_list);
}
VNET_SYSINIT(vnet_if_list_init, SI_SUB_VNET, SI_ORDER_ANY, vnet_if_list_init, 0);

struct uinet_if *
uinet_iffind_byname(const char *ifname)
{
	struct uinet_if *uif;

	TAILQ_FOREACH(uif, &V_uinet_if_list, link) {
		if (0 == strcmp(ifname, uif->name)) {
			break;
		}

		if (('\0' != uif->alias[0]) && (0 == strcmp(ifname, uif->alias))) {
			break;
		}
	}

	return (uif);
}


static struct uinet_if *
uinet_iffind_bycdom(unsigned int cdom)
{
	struct uinet_if *uif;

	TAILQ_FOREACH(uif, &V_uinet_if_list, link) {
		if (cdom == uif->cdom) {
			return (uif);
		}
	}

	return (NULL);
}


int
uinet_ifcreate(uinet_instance_t uinst, uinet_iftype_t type, const char *configstr,
	       const char *alias, unsigned int cdom, int cpu, uinet_if_t *uif)
{
	struct uinet_if *new_uif;
	int alias_len;
	int error = 0;

	CURVNET_SET(uinst->ui_vnet);

	if (alias) {
		alias_len = strlen(alias);
		if (alias_len >= IF_NAMESIZE) {
			error = EINVAL;
			goto out;
		}
		
		if ((alias_len > 0) && (NULL != uinet_iffind_byname(alias))) {
			error = EEXIST;
			goto out;
		}
	}

	/*
	 * CDOM 0 is for non-promiscuous-inet interfaces and can contain
	 * multiple interfaces.  All other CDOMs are for promiscuous-inet
	 * interfaces and can only contain one interface.
	 */
	if ((cdom != 0) && (NULL != uinet_iffind_bycdom(cdom))) {
		error = EEXIST;
		goto out;
	}

	new_uif = malloc(sizeof(struct uinet_if), M_DEVBUF, M_WAITOK);
	if (NULL == new_uif) {
		error = ENOMEM;
		goto out;
	}

	new_uif->type = type;

	if (configstr) {
		new_uif->configstr = strdup(configstr, M_DEVBUF);
	} else {
		new_uif->configstr = NULL;
	}

	if (alias) {
		/* copy guaranteed not to overflow the destinations due to above
		 * checks against IF_NAMESIZE.
		 */
		strcpy(new_uif->alias, alias);
	} else {
		new_uif->alias[0] = '\0';
	}
	new_uif->cpu = cpu;
	new_uif->cdom = cdom;
	new_uif->ifdata = NULL;

	switch (new_uif->type) {
	case UINET_IFTYPE_NETMAP:
		error = if_netmap_attach(new_uif);
		break;
	case UINET_IFTYPE_PCAP:
		error = if_pcap_attach(new_uif);
		break;
	case UINET_IFTYPE_BRIDGE:
		error = if_bridge_attach(new_uif);
		break;
	case UINET_IFTYPE_SPAN:
		error = if_span_attach(new_uif);
		break;
	default:
		printf("Error attaching interface with config %s: unknown interface type %d\n", new_uif->configstr, new_uif->type);
		error = ENXIO;
		break;
	}

	if (0 == error) {
		TAILQ_INSERT_TAIL(&V_uinet_if_list, new_uif, link);
		if (uif)
			*uif = new_uif;
	}

out:
	CURVNET_RESTORE();
	if (error) {
		if (uif)
			*uif = NULL;

		if (new_uif) {
			if (new_uif->configstr)
				free(new_uif->configstr, M_DEVBUF);

			free(new_uif, M_DEVBUF);
		}
	}

	return (error);
}


static int
uinet_ifdestroy_internal(struct uinet_if *uif)
{
	int error;

	switch (uif->type) {
	case UINET_IFTYPE_NETMAP:
		error = if_netmap_detach(uif);
		break;
	case UINET_IFTYPE_PCAP:
		error = if_pcap_detach(uif);
		break;
	default:
		printf("Error detaching interface %s: unknown interface type %d\n", uif->name, uif->type);
		error = ENXIO;
		break;
	}

	TAILQ_REMOVE(&V_uinet_if_list, uif, link);
		
	if (uif->configstr)
		free(uif->configstr, M_DEVBUF);

	free(uif, M_DEVBUF);

	return (error);
}


int
uinet_ifdestroy(uinet_if_t uif)
{
	int error = EINVAL;

	CURVNET_SET(uif->uinst->ui_vnet);

	if (NULL != uif)
		error = uinet_ifdestroy_internal(uif);

	CURVNET_RESTORE();

	return (error);
}


void
uinet_ifdestroy_all(struct uinet_instance *uinst)
{
	struct uinet_if *uif, *tmp;

	CURVNET_SET(uinst->ui_vnet);
	TAILQ_FOREACH_SAFE(uif, &V_uinet_if_list, link, tmp) {
		uinet_ifdestroy_internal(uif);
	}
	CURVNET_RESTORE();
}


int
uinet_ifdestroy_byname(uinet_instance_t uinst, const char *ifname)
{
	struct uinet_if *uif;
	int error = EINVAL;

	CURVNET_SET(uinst->ui_vnet);
	uif = uinet_iffind_byname(ifname);
	if (uif)
		error = uinet_ifdestroy_internal(uif);
	CURVNET_RESTORE();

	return (error);
}


const char *
uinet_ifaliasname(uinet_if_t uif)
{
	return (uif ? uif->alias : "");
}


const char *
uinet_ifgenericname(uinet_if_t uif)
{
	return (uif ? uif->name : "");
}


int
uinet_if_set_batch_event_handler(uinet_if_t uif,
				 void (*handler)(void *arg, int event),
				 void *arg)
{
	int error = EINVAL;

	if (NULL != uif) {
		uif->batch_event_handler = handler;
		uif->batch_event_handler_arg = arg;
		error = 0;
	}

	return (error);
}
