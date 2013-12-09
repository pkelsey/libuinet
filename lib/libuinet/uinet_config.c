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


static TAILQ_HEAD(config_head, uinet_config_if) if_conf = TAILQ_HEAD_INITIALIZER(if_conf);


int uinet_config_if(const char *ifname, uinet_iftype_t type, unsigned int cdom, int cpu)
{
	const char *colon, *p, *p_orig;
	unsigned int queue;
	unsigned int unit;
	struct uinet_config_if *cfg;
	int copylen;

	
	if (NULL == ifname) {
		return (EINVAL);
	}

	if (strlen(ifname) >= IF_NAMESIZE) {
		return (EINVAL);
	}


	/* parse ifname into base, unit, and queue */
	colon = strchr(ifname, ':');
	if (colon) {
		if (colon == ifname) {
			/* no base or unit */
			return (EINVAL);
		}
		
		p = colon + 1;
		if ('\0' == *p) {
			/* colon at the end */
			return (EINVAL);
		}

		while (isdigit(*p) && ('\0' != *p))
			p++;

		if ('\0' != *p) {
			/* non-numeric chars after colon */
			return (EINVAL);
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
		return (EINVAL);
	}

	if (p == ifname) {
		/* it's all numeric up to the colon */
		return (EINVAL);
	}

	/* p now points to last char of base name */

	unit = strtoul(p + 1, NULL, 10);

	cfg = malloc(sizeof(struct uinet_config_if), M_DEVBUF, M_WAITOK);
	if (NULL == cfg) {
		return (ENOMEM);
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

	TAILQ_INSERT_TAIL(&if_conf, cfg, link);

	return (0);
}


struct uinet_config_if *
uinet_config_if_next(struct uinet_config_if *cur)
{
	if (NULL == cur) {
		return (TAILQ_FIRST(&if_conf));
	} else {
		return (TAILQ_NEXT(cur, link));
	}
}

