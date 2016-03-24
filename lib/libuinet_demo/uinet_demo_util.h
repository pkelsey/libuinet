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

#ifndef _UINET_DEMO_UTIL_H_
#define _UINET_DEMO_UTIL_H_

#include <stdint.h>
#include <uinet_api.h>


struct uinet_demo_mac_addr_range {
	uint8_t first[6];
	uint8_t last[6];
	uint64_t size;
};

struct uinet_demo_ipv4_addr_range {
	uint32_t first; /* host byte order */
	uint32_t last;  /* host byte order */
	uint64_t size;
};

struct uinet_demo_port_range {
	uint16_t first; /* host byte order */
	uint16_t last;  /* host byte order */
	uint32_t size;
};

struct uinet_demo_vlan_range {
	uint16_t first[UINET_IN_L2INFO_MAX_TAGS];
	uint16_t last[UINET_IN_L2INFO_MAX_TAGS];
	uint16_t num_tags;
	uint64_t size;
};


int uinet_demo_util_init(void);
void uinet_demo_util_shutdown(void);

int uinet_demo_break_ipaddr_port_string(const char *instr, char *ipstr,
					unsigned int ipstrlen, unsigned int *port);

int uinet_demo_get_mac_addr_range(const char *input, struct uinet_demo_mac_addr_range *range);
int uinet_demo_get_ipv4_addr_range(const char *input, struct uinet_demo_ipv4_addr_range *range, unsigned int cidr_skip_bcast);
int uinet_demo_get_port_range(const char *input, struct uinet_demo_port_range *range);
int uinet_demo_get_vlan_range(const char *input, struct uinet_demo_vlan_range *range);

char *uinet_demo_mac_addr_str(char *buf, unsigned int size, const uint8_t *mac);
char *uinet_demo_vlan_str(char *buf, unsigned int size, const uint16_t *vlan, unsigned int num_tags);

char *uinet_demo_mac_addr_range_str(char *buf, unsigned int size, const struct uinet_demo_mac_addr_range *range);
char *uinet_demo_ipv4_addr_range_str(char *buf, unsigned int size, const struct uinet_demo_ipv4_addr_range *range);
char *uinet_demo_port_range_str(char *buf, unsigned int size, const struct uinet_demo_port_range *range);
char *uinet_demo_vlan_range_str(char *buf, unsigned int size, const struct uinet_demo_vlan_range *range);

void uinet_demo_get_mac_addr_n(const struct uinet_demo_mac_addr_range *range, uint64_t n, uint8_t *mac);
void uinet_demo_get_ipv4_addr_n(const struct uinet_demo_ipv4_addr_range *range, uint64_t n, uint32_t *addr);
void uinet_demo_get_port_n(const struct uinet_demo_port_range *range, uint32_t n, uint16_t *port);
void uinet_demo_get_vlan_n(const struct uinet_demo_vlan_range *range, uint64_t n, uint16_t *vlan);

#endif /* _UINET_DEMO_UTIL_H_ */
