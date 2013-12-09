/*
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


#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#include "uinet_config.h"
#include "uinet_config_internal.h"
#include "uinet_if_netmap.h"

static TAILQ_HEAD(config_head, uinet_config_if) if_conf = TAILQ_HEAD_INITIALIZER(if_conf);


static struct uinet_config_if *
uinet_iffind_byname(const char *ifname)
{
	struct uinet_config_if *cfg;

	TAILQ_FOREACH(cfg, &if_conf, link) {
		if (0 == strcmp(ifname, cfg->spec)) {
			return (cfg);
		}
	}

	return (NULL);
}


static struct uinet_config_if *
uinet_iffind_bycdom(unsigned int cdom)
{
	struct uinet_config_if *cfg;

	TAILQ_FOREACH(cfg, &if_conf, link) {
		if (cdom == cfg->cdom) {
			return (cfg);
		}
	}

	return (NULL);
}


int uinet_ifcreate(const char *ifname, uinet_iftype_t type, unsigned int cdom, int cpu)
{
	const char *colon, *p, *p_orig;
	unsigned int queue;
	unsigned int unit;
	struct uinet_config_if *cfg = NULL;
	int copylen;
	int error = 0;

	
	if (NULL == ifname) {
		error = EINVAL;
		goto out;
	}

	if (strlen(ifname) >= IF_NAMESIZE) {
		error = EINVAL;
		goto out;
	}

	if (NULL != uinet_iffind_byname(ifname)) {
		error = EEXIST;
		goto out;
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

	/* parse ifname into base, unit, and queue */
	colon = strchr(ifname, ':');
	if (colon) {
		if (colon == ifname) {
			/* no base or unit */
			error = EINVAL;
			goto out;
		}
		
		p = colon + 1;
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

		p = colon + 1;
		queue = strtoul(p, NULL, 10);
		
		p = colon - 1;
	} else {
		queue = 0;
		p = ifname + strlen(ifname) - 1;
	}

	/* p now points to what should be the last digit of the unit
	 * number.
	 */

	p_orig = p;
	while (isdigit(*p) && p != ifname)
		p--;
	
	if (p == p_orig) {
		/* no unit number */
		error = EINVAL;
		goto out;
	}

	if (p == ifname) {
		/* it's all numeric up to the colon */
		error = EINVAL;
		goto out;
	}

	/* p now points to last char of base name */

	unit = strtoul(p + 1, NULL, 10);

	cfg = malloc(sizeof(struct uinet_config_if), M_DEVBUF, M_WAITOK);
	if (NULL == cfg) {
		error = ENOMEM;
		goto out;
	}

	cfg->type = type;

	/* copies guaranteed not to overflow the destinations due to above
	 * checks against IF_NAMESIZE.
	 */
	strcpy(cfg->spec, ifname);

	copylen = p_orig - ifname + 1;
	memcpy(cfg->name, ifname, copylen);
	cfg->name[copylen] = '\0';

	copylen = p - ifname + 1;
	memcpy(cfg->basename, ifname, copylen);
	cfg->basename[copylen] = '\0';

	cfg->unit = unit;
	cfg->queue = queue;
	cfg->cpu = cpu;
	cfg->cdom = cdom;

	cfg->ifdata = NULL;

	switch (cfg->type) {
	case UINET_IFTYPE_NETMAP:
		error = if_netmap_attach(cfg);
		break;
	default:
		printf("Error attaching interface %s: unknown interface type %d\n", cfg->spec, cfg->type);
		error = ENXIO;
		break;
	}

	if (0 == error)
		TAILQ_INSERT_TAIL(&if_conf, cfg, link);

out:
	if (error && cfg)
		free(cfg, M_DEVBUF);

	return (error);
}


int uinet_ifdestroy(const char *ifname)
{
	struct uinet_config_if *cfg;
	int error = EINVAL;

	cfg = uinet_iffind_byname(ifname);
	if (NULL != cfg) {
		switch (cfg->type) {
		case UINET_IFTYPE_NETMAP:
			error = if_netmap_detach(cfg);
			break;
		default:
			printf("Error detaching interface %s: unknown interface type %d\n", cfg->spec, cfg->type);
			error = ENXIO;
			break;
		}

		TAILQ_REMOVE(&if_conf, cfg, link);
		free(cfg, M_DEVBUF);
	}

	return (error);
}
