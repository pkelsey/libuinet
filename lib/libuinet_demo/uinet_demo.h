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

#ifndef _UINET_DEMO_H_
#define _UINET_DEMO_H_

#include <stdint.h>

#include "uinet_ev.h"
#include "uinet_api.h"


enum uinet_demo_id {
	UINET_DEMO_CONNSCALE,
	UINET_DEMO_ECHO,
	UINET_DEMO_PASSIVE,
	UINET_DEMO_PASSIVE_EXTRACT,

	UINET_NUM_DEMO_APPS /* always last */
};


struct uinet_demo_config {
	char name[UINET_NAME_BUF_LEN];
	uint64_t id;
	enum uinet_demo_id which;
	unsigned int verbose;
	unsigned int copy_every;
	uint64_t copy_limit;
	const char *copy_to;

	uinet_if_t copy_uif;
	unsigned int copy_mode;
	uinet_instance_t uinst;
	struct ev_loop *loop;
};


int uinet_demo_init(void);
void uinet_demo_shutdown(void);

const char *uinet_demo_name(enum uinet_demo_id which);
void uinet_demo_print_usage(enum uinet_demo_id which);
int uinet_demo_init_cfg(struct uinet_demo_config *cfg, enum uinet_demo_id which,
			uint64_t instance_id, const char *name, int verbose);
int uinet_demo_process_args(struct uinet_demo_config *cfg, int argc, char **argv);
void uinet_demo_print_cfg(struct uinet_demo_config *cfg);
int uinet_demo_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
		     struct ev_loop *loop);

#endif /* _UINET_DEMO_H_ */
