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


struct uinet_config_if *
uinet_iffind_byname(const char *ifname)
{
	struct uinet_config_if *cfg;

	TAILQ_FOREACH(cfg, &if_conf, link) {
		if (0 == strcmp(ifname, cfg->name)) {
			return (cfg);
		}

		if (('\0' != cfg->alias[0]) && (0 == strcmp(ifname, cfg->alias))) {
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


int
uinet_ifcreate(uinet_iftype_t type, const char *configstr, const char *alias,
	       unsigned int cdom, int cpu, uinet_ifcookie_t *cookie)
{
	struct uinet_config_if *cfg = NULL;
	int alias_len;
	int error = 0;

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

	cfg = malloc(sizeof(struct uinet_config_if), M_DEVBUF, M_WAITOK);
	if (NULL == cfg) {
		error = ENOMEM;
		goto out;
	}

	cfg->type = type;

	if (configstr) {
		cfg->configstr = strdup(configstr, M_DEVBUF);
	} else {
		cfg->configstr = NULL;
	}

	if (alias) {
		/* copy guaranteed not to overflow the destinations due to above
		 * checks against IF_NAMESIZE.
		 */
		strcpy(cfg->alias, alias);
	} else {
		cfg->alias[0] = '\0';
	}
	cfg->cpu = cpu;
	cfg->cdom = cdom;
	cfg->ifdata = NULL;

	switch (cfg->type) {
	case UINET_IFTYPE_NETMAP:
		error = if_netmap_attach(cfg);
		break;
	default:
		printf("Error attaching interface with config %s: unknown interface type %d\n", cfg->configstr, cfg->type);
		error = ENXIO;
		break;
	}

	if (0 == error) {
		TAILQ_INSERT_TAIL(&if_conf, cfg, link);
		if (cookie)
			*cookie = cfg;
	}

out:
	if (error) {
		if (cookie)
			*cookie = UINET_IFCOOKIE_INVALID;

		if (cfg) {
			if (cfg->configstr)
				free(cfg->configstr, M_DEVBUF);

			free(cfg, M_DEVBUF);
		}
	}

	return (error);
}


int
uinet_ifdestroy(uinet_ifcookie_t cookie)
{
	struct uinet_config_if *cfg = cookie;
	int error = EINVAL;

	if (NULL != cfg) {
		switch (cfg->type) {
		case UINET_IFTYPE_NETMAP:
			error = if_netmap_detach(cfg);
			break;
		default:
			printf("Error detaching interface %s: unknown interface type %d\n", cfg->name, cfg->type);
			error = ENXIO;
			break;
		}

		TAILQ_REMOVE(&if_conf, cfg, link);
		
		if (cfg->configstr)
			free(cfg->configstr, M_DEVBUF);

		free(cfg, M_DEVBUF);
	}

	return (error);
}


int
uinet_ifdestroy_byname(const char *ifname)
{
	struct uinet_config_if *cfg;

	cfg = uinet_iffind_byname(ifname);

	return (uinet_ifdestroy(cfg));
}


const char *
uinet_ifaliasname(uinet_ifcookie_t cookie)
{
	struct uinet_config_if *cfg = cookie;

	return (cfg ? cfg->alias : "");
}


const char *
uinet_ifgenericname(uinet_ifcookie_t cookie)
{
	struct uinet_config_if *cfg = cookie;

	return (cfg ? cfg->name : "");
}
