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

#ifndef _UINET_DEMO_INTERNAL_H_
#define _UINET_DEMO_INTERNAL_H_


#include "uinet_demo.h"
#include "uinet_demo_util.h"

struct uinet_demo_info {
	enum uinet_demo_id which;
	const char *name;
	void (*print_usage)(void);
	int (*init_cfg)(struct uinet_demo_config *cfg, uint64_t id,
			const char *name, int verbose);
	int (*process_args)(struct uinet_demo_config *cfg, int argc, char **argv);
	void (*print_cfg)(struct uinet_demo_config *cfg);
	int (*start)(struct uinet_demo_config *cfg, uinet_instance_t uinst,
		     struct ev_loop *loop);
};

#define UINET_DEMO_REGISTER(which, demo_info)				\
void									\
uinet_demo_## which ##_init(void) {					\
	uinet_demo_register(demo_info);					\
}


void uinet_demo_register(struct uinet_demo_info *info);
void uinet_demo_base_init_cfg(struct uinet_demo_config *cfg, enum uinet_demo_id which,
			      uint64_t instance_id, const char *name, int verbose);
void uinet_demo_base_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
			   struct ev_loop *loop);


#endif /* _UINET_DEMO_INTERNAL_H_ */
