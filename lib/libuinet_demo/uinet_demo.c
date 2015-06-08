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

#include <getopt.h>
#include <stdio.h>

#include "uinet_demo.h"
#include "uinet_demo_internal.h"

static struct uinet_demo_info demo_db[UINET_NUM_DEMO_APPS];

const char *
uinet_demo_name(enum uinet_demo_id which)
{
	return ((which < UINET_NUM_DEMO_APPS)  && demo_db[which].name ?
		demo_db[which].name : "<invalid app id>");
}


void uinet_demo_print_usage(enum uinet_demo_id which)
{
	if ((which < UINET_NUM_DEMO_APPS)  && demo_db[which].print_usage)
		demo_db[which].print_usage();
	else
		printf("  <invalid app id>\n");
}


int
uinet_demo_init_cfg(struct uinet_demo_config *cfg, enum uinet_demo_id which, 
		    uint64_t instance_id, const char *name, int verbose)
{
	return ((which < UINET_NUM_DEMO_APPS) && demo_db[which].init_cfg ?
		demo_db[which].init_cfg(cfg, instance_id, name, verbose) : -1);
}


void
uinet_demo_print_cfg(struct uinet_demo_config *cfg)
{
	demo_db[cfg->which].print_cfg(cfg);
}


int
uinet_demo_process_args(struct uinet_demo_config *cfg, int argc, char **argv)
{
	int oldopterr;
	int rv;

	oldopterr = opterr;
	opterr = 0;
	rv = demo_db[cfg->which].process_args(cfg, argc, argv);
	opterr = oldopterr;

	/* missing required argument to known option */
	if (rv == ':') {
		printf("%s option `%s' requires an argument\n", uinet_demo_name(cfg->which), argv[optind-1]);
		return (-1);  /* caller should stop argument processing */
	}

	/* unknown option */
	if (rv == '?') {
		optind--;  /* move index back to point to option that was unknown */
		return (0);  /* caller should continue argument processing */
	}

	/* invalid argument to known option */
	if (rv > 0) {
		return (-1);  /* caller should stop argument processing */
	}

        /* rv is -1, caller should continue processing to notice end-of-arguments */
	return (0);
}


int
uinet_demo_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
		 struct ev_loop *loop)
{
	return (demo_db[cfg->which].start(cfg, uinst, loop));
}



int
uinet_demo_init(void)
{
	uinet_demo_util_init();

	UINET_DEMO_INIT(connscale);
	UINET_DEMO_INIT(echo);
	UINET_DEMO_INIT(passive);
	UINET_DEMO_INIT(passive_extract);

	return (0);
}


void
uinet_demo_shutdown(void)
{
	uinet_demo_util_shutdown();
}


/*
 * Internal methods
 */

void
uinet_demo_register(struct uinet_demo_info *info)
{
	demo_db[info->which] = *info;
}


void
uinet_demo_base_init_cfg(struct uinet_demo_config *cfg, enum uinet_demo_id which,
			 uint64_t instance_id, const char *name, int verbose)
{
	if (name)
		snprintf(cfg->name, sizeof(cfg->name), "%s", name);
	else
		snprintf(cfg->name, sizeof(cfg->name), "%s %llu",
			 uinet_demo_name(which), (unsigned long long)instance_id);

	cfg->id = instance_id;
	cfg->which = which;
	cfg->verbose = verbose;
}


void
uinet_demo_base_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
		      struct ev_loop *loop)
{
	cfg->uinst = uinst;
	cfg->loop = loop;
}

