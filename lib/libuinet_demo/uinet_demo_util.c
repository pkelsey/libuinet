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


#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "uinet_demo_util.h"


/*
 * These regular expressions are not intended to reject all invalid input,
 * but to be used in conjunction with additional post-match checks where
 * required.
 */
#define MAC_ADDR_REGEX	"([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}"
#define IPV4_ADDR_REGEX	"([0-9]{1,3}\\.){3}[0-9]{1,3}"
#define IPV4_CIDR_REGEX IPV4_ADDR_REGEX "/[0-9]+"
#define PORT_REGEX	"[0-9]{1,5}"
#define VLAN_REGEX	"[0-9]{1,4}(:[0-9]{1,4})*"


static regex_t mac_addr_regex;
static regex_t ipv4_addr_regex;
static regex_t ipv4_cidr_regex;
static regex_t port_regex;
static regex_t vlan_regex;


int
uinet_demo_util_init(void)
{
	int init_count = 0;

	if (regcomp(&mac_addr_regex, MAC_ADDR_REGEX, REG_EXTENDED) != 0)
		goto error;
	init_count++;

	if (regcomp(&ipv4_addr_regex, IPV4_ADDR_REGEX, REG_EXTENDED) != 0)
		goto error;
	init_count++;

	if (regcomp(&ipv4_cidr_regex, IPV4_CIDR_REGEX, REG_EXTENDED) != 0)
		goto error;
	init_count++;

	if (regcomp(&port_regex, PORT_REGEX, REG_EXTENDED) != 0)
		goto error;
	init_count++;

	if (regcomp(&vlan_regex, VLAN_REGEX, REG_EXTENDED) != 0)
		goto error;
	init_count++;
	    
	return (0);

error:
	switch (init_count) {
	case 5: regfree(&vlan_regex);		/* FALLTHROUGH */
	case 4: regfree(&port_regex);		/* FALLTHROUGH */
	case 3: regfree(&ipv4_cidr_regex);	/* FALLTHROUGH */
	case 2: regfree(&ipv4_addr_regex);	/* FALLTHROUGH */
	case 1: regfree(&mac_addr_regex);	/* FALLTHROUGH */
	}

	return (-1);
}


void
uinet_demo_util_shutdown(void)
{
	regfree(&vlan_regex);
	regfree(&port_regex);
	regfree(&ipv4_cidr_regex);
	regfree(&ipv4_addr_regex);
	regfree(&mac_addr_regex);
}


/*
 * From the input, extract the IP address string and port number if
 * possible.
 *
 * Formats are:
 *
 *     ipv4:port
 *     [ipv6]:port
 *
 * If there is no ':', a zero port number is returned.  Full IP address
 * format verification is not performed, although this routine will reject
 * empty strings, a '[' that isn't followed at some point by a ']', and a
 * handful of other conditions.
 */
int
uinet_demo_break_ipaddr_port_string(const char *instr, char *ipstr,
				    unsigned int ipstrlen, unsigned int *port)
{
	char *p1, *p2;

	if (!instr || (instr[0] == '\0'))
		return (-1);
	
	p1 = strchr(instr, '[');
	if (p1) { 		
		/* '[' present */

		if (p1 != instr)
			return (-1); /* '[' not first character */

		p2 = strchr(p1 + 1, ']');
		if (!p2)
			return (-1); /* no ']' */

		if (p2 - p1 - 1 < 2)
			return (-1); /* too short */

		snprintf(ipstr, p2 - p1 > ipstrlen ? ipstrlen : p2 - p1, "%s", p1 + 1);  
		p1 = strchr(p2 + 1, ':');
	} else {
		p1 = strchr(instr, ':');
		if (p1 == instr)
			return (-1); /* too short */

		if (p1)
			snprintf(ipstr, p1 - instr + 1 > ipstrlen ? ipstrlen : p1 - instr + 1, "%s", instr);
		else
			snprintf(ipstr, ipstrlen, "%s", instr);
	}


	if (!p1)
		*port = 0;
	else
		*port = strtoul(p1 + 1, NULL, 10);

	return (0);
}


static void
extract_mac(const char *macstr, uint8_t *mac)
{
	mac[0] = strtoul(macstr, NULL, 16);
	mac[1] = strtoul(macstr + 3, NULL, 16);
	mac[2] = strtoul(macstr + 6, NULL, 16);
	mac[3] = strtoul(macstr + 9, NULL, 16);
	mac[4] = strtoul(macstr + 12, NULL, 16);
	mac[5] = strtoul(macstr + 15, NULL, 16);
}


static uint64_t
mac_to_u64(const uint8_t *mac)
{
	return ((((uint64_t)mac[0]) << 40) |
		(((uint64_t)mac[1]) << 32) |
		(((uint64_t)mac[2]) << 24) |
		(((uint64_t)mac[3]) << 16) |
		(((uint64_t)mac[4]) <<  8) |
		(uint64_t)mac[5]);
}


/*
 * Valid input (where all x are hex digits):
 *     xx:xx:xx:xx:xx:xx
 *     xx:xx:xx:xx:xx:xx-xx:xx:xx:xx:xx:xx
 *
 */
int
uinet_demo_get_mac_addr_range(const char *input, struct uinet_demo_mac_addr_range *range)
{
	regmatch_t match;
	const char *p;
	uint64_t mac_first, mac_last;

	if (regexec(&mac_addr_regex, input, 1, &match, 0) != 0)
		return (-1);

	extract_mac(input, range->first);
	
	p = input + match.rm_eo;
	if (*p == '\0') {
		memcpy(range->last, range->first, 6);
		range->size = 1;
		return (0);
	} else if (*p != '-')
		return (-1);

	p++;
	if (regexec(&mac_addr_regex, p, 1, &match, 0) != 0)
		return (-1);
	
	p += match.rm_eo;
	if (*p != '\0')
		return (-1);
	
	extract_mac(input, range->last);

	mac_first = mac_to_u64(range->first);
	mac_last = mac_to_u64(range->last);
	if (mac_first < mac_last) {
		uint64_t temp;
		
		temp = mac_last;
		mac_last = mac_first;
		mac_first = temp;
	}
	
	range->size = mac_last - mac_first + 1;

	return (0);
}


static int
ipv4_to_u32(const char *start, const char *end, uint32_t *ipv4)
{
	struct uinet_in_addr ina;
	char *p;

	p = strndup(start, end - start);
	if (p == NULL)
		return (-1);
	
	if (inet_pton(UINET_AF_INET, p, &ina) != 1) {
		free(p);
		return (-1);
	}
	free(p);
	
	*ipv4 = ntohl(ina.s_addr);
	return (0);
}


/*
 * Valid input (all numbers interpreted as decimal, a thru h [0,255], m [0,32]):
 *     a.b.c.d/m
 *     a.b.c.d
 *     a.b.c.d-e.f.g.h
 *
 */
int
uinet_demo_get_ipv4_addr_range(const char *input, struct uinet_demo_ipv4_addr_range *range, unsigned int cidr_skip_bcast)
{
	regmatch_t match;
	const char *p;
	const char *p2;
	uint32_t ipv4_first;
	uint32_t ipv4_last;

	if (regexec(&ipv4_cidr_regex, input, 1, &match, 0) == 0) {
		unsigned int mask_bits;
		uint32_t mask;
		uint32_t offset;
		uint64_t range_size;
		char *slash;

		p = input + match.rm_eo;
		if (*p != '\0')
			return (-1);
		
		slash = strchr(input ,'/');
		mask_bits = strtoul(slash + 1, NULL, 10);
		if (mask_bits > 32)
			return (-1);

		if (mask_bits == 0)
			mask = 0;
		else
			mask = 0xffffffff << (32 - mask_bits);

		if (ipv4_to_u32(input, slash, &ipv4_first) != 0)
			return (-1);

		ipv4_last = ipv4_first | ~mask;
		range_size = (uint64_t)(~mask) + 1;
		offset = ipv4_first & ~mask;

		/*
		 * cidr_skip_bcast will have no impact on /32, /31 will be
		 * left empty, and all others will will have the last
		 * adddress removed from the set, along with the first
		 * address if it is offset 0 from the beginning of the block
		 */
		if (cidr_skip_bcast && (range_size > 1)) {
			ipv4_last--;
			if (!offset)
				ipv4_first++;
		}

	} else if (regexec(&ipv4_addr_regex, input, 1, &match, 0) == 0) {
		p = input + match.rm_eo;
		if (ipv4_to_u32(input, p, &ipv4_first) != 0)
			return (-1);

		if (*p == '\0') 
			ipv4_last = ipv4_first;
		else if (*p == '-') {
			p++;
			if (regexec(&ipv4_addr_regex, p, 1, &match, 0) != 0)
				return (-1);

			p2 = p + match.rm_eo;
			if (*p2 != '\0')
				return (-1);

			if (ipv4_to_u32(p, p2, &ipv4_last) != 0)
				return (-1);
		} else
			return (-1);

		if (ipv4_first > ipv4_last) {
			uint32_t temp;

			temp = ipv4_last;
			ipv4_last = ipv4_first;
			ipv4_first = temp;
		}
	} else
		return (-1);

	range->first = ipv4_first;
	range->last = ipv4_last;
	range->size = (uint64_t)ipv4_last - (uint64_t)ipv4_first + 1;

	return (0);
}


/*
 * Valid input (where n and m [0,65535]):
 *     n
 *     n-m
 *
 */
int
uinet_demo_get_port_range(const char *input, struct uinet_demo_port_range *range)
{
	regmatch_t match;
	const char *p;
	unsigned long value;

	if (regexec(&port_regex, input, 1, &match, 0) != 0)
		return (-1);
	
	value = strtoul(input, NULL, 10);
	if (value > 65535)
		return (-1);
	range->first = value;

	p = input + match.rm_eo;
	if (*p == '\0') {
		range->last = range->first;
		range->size = 1;
		return (0);
	} else if (*p != '-')
		return (-1);

	p++;
	if (regexec(&port_regex, p, 1, &match, 0) != 0)
		return (-1);
	
	value = strtoul(p, NULL, 10);
	if (value > 65535)
		return (-1);

	p += match.rm_eo;
	if (*p != '\0')
		return (-1);

	range->last = value;
	if (range->first > range->last) {
		uint16_t temp;
		
		temp = range->last;
		range->last = range->first;
		range->first = temp;
	}
	
	range->size = (uint32_t)range->last - (uint32_t)range->first + 1;

	return (0);
}


static int
extract_vlan(const char *vlanstr, uint16_t *vlan, unsigned int *num_tags)
{
	unsigned int i;
	unsigned long value;
	char *endp;

	for (i = 0; i < UINET_IN_L2INFO_MAX_TAGS; i++) {
		value = strtoul(vlanstr, &endp, 10);
		if (endp == vlanstr)
			return (-1);
		if (value > 4094)
			return (-1);
		vlan[i] = value;
		if ((*endp == '\0') || (*endp == '-')) {
			*num_tags = i + 1;
			return (0);
		}
		if (*endp != ':')
			return (-1);
		vlanstr = endp + 1;
	}

	return (-1);  /* too many tags */
}


static int
compare_vlans(const uint16_t *vlan1, const uint16_t *vlan2, unsigned int num_tags)
{
	unsigned int i;

	for (i = 0; i < num_tags; i++) {
		if (vlan1[i] > vlan2[i])
			return (1);
		else if (vlan1[i] < vlan2[i])
			return (-1);
	}

	return (0);
}


/*
 * Valid input (where n thru s [0,4094]):
 *     n
 *     n-m
 *     n:m
 *     n:m-p:q
 *     n:m:p-q:r:s
 *     .
 *     .
 *     .
 *
 */
int
uinet_demo_get_vlan_range(const char *input, struct uinet_demo_vlan_range *range)
{
	regmatch_t match;
	const char *p;
	unsigned int num_tags_first, num_tags_last;
	int i;
	unsigned int max_vlans_per_level;
	uint64_t total_vlans;
	uint64_t scale;
	int adjust;
	int minuend;

	if (regexec(&vlan_regex, input, 1, &match, 0) != 0)
		return (-1);

	if (extract_vlan(input, range->first, &num_tags_first) != 0)
		return (-1);

	p = input + match.rm_eo;
	if (*p == '\0') {
		memcpy(range->last, range->first, num_tags_first * sizeof(range->first[0]));
		range->num_tags = num_tags_first;
		range->size = 1;
		return (0);
	} else if (*p != '-')
		return (-1);

	p++;
	if (extract_vlan(p, range->last, &num_tags_last) != 0)
		return (-1);
	
	if (num_tags_first != num_tags_last)
		return (-1);

	range->num_tags = num_tags_first;

	if (compare_vlans(range->first, range->last, range->num_tags) > 0)
		for (i = 0; i < range->num_tags; i++) {
			uint16_t temp;
			
			temp = range->first[i];
			range->first[i] = range->last[i];
			range->last[i] = temp;
		}

	max_vlans_per_level = 4095;
	scale = 1;
	adjust = 0;
	total_vlans = 1;
	for (i = range->num_tags - 1; i >= 0; i--) {
		minuend = (int)range->last[i] + adjust;
		if (minuend < (int)range->first[i]) {
			minuend += max_vlans_per_level;
			adjust = -1;
		} else
			adjust = 0;

		total_vlans += (minuend - range->first[i]) * scale;
		scale *= max_vlans_per_level;
	}
	range->size = total_vlans;

	return (0);
}


char *
uinet_demo_mac_addr_str(char *buf, unsigned int size, const uint8_t *mac)
{
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	
	return (buf);
}


char *
uinet_demo_mac_addr_range_str(char *buf, unsigned int size, const struct uinet_demo_mac_addr_range *range)
{
	int result;

	uinet_demo_mac_addr_str(buf, size, range->first);
	
	if ((range->size > 1) && (size > 7))
		uinet_demo_mac_addr_str(buf + 6, size - 6, range->last);

	return (buf);
}


char *
uinet_demo_ipv4_addr_range_str(char *buf, unsigned int size, const struct uinet_demo_ipv4_addr_range *range)
{
	int result;

	result = snprintf(buf, size, "%u.%u.%u.%u",
			  (range->first >> 24) & 0xff,
			  (range->first >> 16) & 0xff,
			  (range->first >>  8) & 0xff,
			   range->first        & 0xff);
	if (result < 0) {
		if (size > 0)
			buf[0] = '\0';
	} else if ((range->size > 1) && (result < size - 1))
		snprintf(buf + result, size - result, "-%u.%u.%u.%u",
			 (range->last >> 24) & 0xff,
			 (range->last >> 16) & 0xff,
			 (range->last >>  8) & 0xff,
			  range->last        & 0xff);

	return (buf);
}


char *
uinet_demo_port_range_str(char *buf, unsigned int size, const struct uinet_demo_port_range *range)
{
	int result;

	result = snprintf(buf, size, "%u", range->first);
	if (result < 0) {
		if (size > 0)
			buf[0] = '\0';
	} else if ((range->size > 1) && (result < size - 1))
		snprintf(buf + result, size - result, "-%u", range->last);

	return (buf);
}


char *
uinet_demo_vlan_str(char *buf, unsigned int size, const uint16_t *vlan, unsigned int num_tags)
{
	unsigned int i;
	unsigned int remaining;
	int result;
	char *p;

	if (num_tags == 0) {
		snprintf(buf, size, "none");
		goto out;
	}

	p = buf;
	remaining = size;
	for (i = 0; i < num_tags; i++) {
		result = snprintf(p, remaining, "%s%u", i ? ":" : "", vlan[i]);
		if (result < 0)
			goto out;
		if (result >= remaining)
			goto out;
		remaining -= result;
		p += result;
	}

out:
	return (buf);
}


char *
uinet_demo_vlan_range_str(char *buf, unsigned int size, const struct uinet_demo_vlan_range *range)
{
	int result;
	char tmp[UINET_IN_L2INFO_MAX_TAGS * 5];
	
	if ((range->num_tags > UINET_IN_L2INFO_MAX_TAGS) || (size == 0)) {
		if (size > 0)
			buf[0] = '\0';
		return (buf);
	}

	result = snprintf(buf, size, "%s%s",
			  uinet_demo_vlan_str(tmp, sizeof(tmp), range->first, range->num_tags),
			  range->size > 1 ? "-" : "");
	if (result < 0) {
		if (size > 0)
			buf[0] = '\0';
	} else if ((range->size > 1) && (result < size - 1))
		uinet_demo_vlan_str(buf + result, size - result, range->last, range->num_tags);

	return (buf);
}


void
uinet_demo_get_mac_addr_n(const struct uinet_demo_mac_addr_range *range, uint64_t n, uint8_t *mac)
{
	uint64_t sum;
	int i;

	if (range->size == 0)
		return;

	n = n % range->size;
	sum = n;
	for (i = 5; i >= 0; i--) {
		sum = range->first[i] + sum;
		mac[i] = sum & 0xff;
		sum >>= 8;
	}
}


void
uinet_demo_get_ipv4_addr_n(const struct uinet_demo_ipv4_addr_range *range, uint64_t n, uint32_t *addr)
{
	if (range->size == 0)
		return;

	n = n % range->size;
	*addr = range->first + n;
}


void
uinet_demo_get_port_n(const struct uinet_demo_port_range *range, uint32_t n, uint16_t *port)
{
	if (range->size == 0)
		return;

	n = n % range->size;
	*port = range->first + n;
}


void
uinet_demo_get_vlan_n(const struct uinet_demo_vlan_range *range, uint64_t n, uint16_t *vlan)
{
	uint64_t sum;
	unsigned int max_vlans_per_level;
	int i;

	if (range->size == 0)
		return;

	n = n % range->size;
	sum = n;
	max_vlans_per_level = 4095;
	for (i = range->num_tags - 1; i >= 0; i--) {
		sum = range->first[i] + sum;
		vlan[i] = sum % max_vlans_per_level;
		sum /= max_vlans_per_level;
	}
}


