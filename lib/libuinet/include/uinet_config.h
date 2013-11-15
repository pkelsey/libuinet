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


#ifndef	_UINET_CONFIG_H_
#define	_UINET_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	UINET_BLACKHOLE_TCP_NONE,	/* disable TCP blackholing (default) */
	UINET_BLACKHOLE_TCP_SYN_ONLY,	/* only blackhole unwanted SYNs */
	UINET_BLACKHOLE_TCP_ALL,	/* blackhole all unwanted TCP segments */
	UINET_BLACKHOLE_UDP_NONE,	/* disable UDP blackholing (default) */
	UINET_BLACKHOLE_UDP_ALL,	/* blackhole all unwanted UDP datagrams */
} uinet_blackhole_t;


/*
 *  Add an interface to the config.  If called twice for the same interface,
 *  the second config replaces the first.
 *
 *  ifname	is of the form <base><unit>:<queue>, e.g. em0:1.
 *  		<base><unit> is a synonym for <base><unit>:0.
 *
 *  cpu		is the cpu number on which to perform stack processing on
 *		packets received on ifname.  -1 means leave it up to the
 *		scheduler.
 *
 *  cdom	is the connection domain for ifname.  When looking up an
 *		inbound connection on ifname, only control blocks in the
 *		same connection domain will be searched.
 *
 *  returns:
 *
 *  0		Configuration successfully added.
 *
 *  ENOMEM	Too many configs
 *
 *  EINVAL	Malformed ifname, or cpu not in range [-1, num_cpu-1]
 */
int uinet_config_if(const char *ifname, int cpu, unsigned int cdom);


/*
 *  Configure UDP and TCP blackholing.
 */
int uinet_config_blackhole(uinet_blackhole_t action);

#ifdef __cplusplus
}
#endif

#endif /* _UINET_CONFIG_H_ */
