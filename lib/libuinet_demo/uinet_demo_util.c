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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uinet_demo_util.h"


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

