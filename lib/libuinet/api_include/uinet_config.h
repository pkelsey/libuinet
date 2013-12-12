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


typedef enum {
	UINET_IFTYPE_LOOPBACK,
	UINET_IFTYPE_NETMAP
} uinet_iftype_t;


typedef void * uinet_ifcookie_t;
#define UINET_IFCOOKIE_INVALID	NULL


/*
 *  Create a network interface with the given name, of the given type, in
 *  the given connection domain, and bound to the given cpu.
 *
 *  type	is the type of interface to create.  This determines the
 *		interface driver that will attach to the given configstr.
 *
 *  configstr	is a driver-specific configuration string.
 *
 *  		UINET_IFTYPE_NETMAP - vale<n>:<m> or <hostifname> or
 *  		    <hostifname>:<qno>, where queue 0 is implied by
 *		    a configstr of <hostifname>
 *
 *  alias	is any user-supplied string, or NULL.  If a string is supplied,
 *	        it must be unique among all the other aliases and driver-assigned
 *		names.  Passing an empty string is the same as passing NULL.
 *
 *  cdom	is the connection domain for ifname.  When looking up an
 *		inbound packet on ifname, only protocol control blocks in
 *		the same connection domain will be searched.
 *
 *  cpu		is the cpu number on which to perform stack processing on
 *		packets received on ifname.  -1 means leave it up to the
 *		scheduler.
 *
 *  cookie	is a pointer to an opaque reference that, if not NULL,  will be
 *		set to something that corresponds to the interface that is
 *		created, or UINET_IFCOOKIE_INVALID if creation fails.
 *
 *
 *  Return values:
 *
 *  0			Interface created successfully
 *
 *  UINET_ENXIO		Unable to configure the inteface
 *
 *  UINET_ENOMEM	No memory available for interface creation
 *
 *  UINET_EEXIST	An interface with the given name or cdom already exists
 *
 *  UINET_EINVAL	Malformed ifname, or cpu not in range [-1, num_cpu-1]
 */
int uinet_ifcreate(uinet_iftype_t type, const char *configstr, const char *alias,
		   unsigned int cdom, int cpu, uinet_ifcookie_t *cookie);


/*
 *  Destroy the network interface specified by the cookie.
 *
 *
 *  Return values:
 *
 *  0			Interface destroyed successfully
 *
 *  UINET_ENXIO		Unable to destroy the interface
 *
 *  UINET_EINVAL	Invalid cookie
 */
int uinet_ifdestroy(uinet_ifcookie_t cookie);


/*
 *  Destroy the network interface with the given name.
 *
 *  name	can be either the user-specified alias, or the driver-assigned
 *		name returned by uinet_ifgenericname().
 *
 *  Return values:
 *
 *  0			Interface destroyed successfully
 *
 *  UINET_ENXIO		Unable to destroy the interface
 *
 *  UINET_EINVAL	No interface with the given name found
 */
int uinet_ifdestroy_byname(const char *ifname);


/*
 *  Retrieve the user-assigned alias or driver-assigned generic name for the
 *  interface specified by cookie.
 *
 *
 *  Return values:
 *
 *  ""			No alias was assigned or cookie was invalid.
 *
 *  <non-empty string>	The alias or driver-assigned name
 *
 */
const char *uinet_ifaliasname(uinet_ifcookie_t cookie);
const char *uinet_ifgenericname(uinet_ifcookie_t cookie);


/*
 *  Configure UDP and TCP blackholing.
 */
int uinet_config_blackhole(uinet_blackhole_t action);

#ifdef __cplusplus
}
#endif

#endif /* _UINET_CONFIG_H_ */
