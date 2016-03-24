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

#ifndef _UINET_DEMO_CONNSCALE_H_
#define _UINET_DEMO_CONNSCALE_H_

#include "uinet_demo.h"
#include "uinet_demo_util.h"

struct uinet_demo_connscale {
	struct uinet_demo_config cfg;

	struct uinet_demo_mac_addr_range local_mac_addrs;
	struct uinet_demo_mac_addr_range foreign_mac_addrs;
	struct uinet_demo_ipv4_addr_range local_ipv4_addrs;
	struct uinet_demo_ipv4_addr_range foreign_ipv4_addrs;
	struct uinet_demo_port_range local_ports;
	struct uinet_demo_port_range foreign_ports;
	struct uinet_demo_vlan_range vlans;
	unsigned int server;
	unsigned int read_size;
	unsigned int read_remaining;
	unsigned int write_size;
	unsigned int write_remaining;

	uint64_t num_tuples;
	uint64_t next_tuple;
	uint64_t num_listens;
	uint64_t num_connections;
	uinet_pool_t connection_pool;
	uinet_if_t next_client_conn_if;

	uint64_t client_current_period;
	uint64_t client_connections_launched;
	uint64_t client_connections_max;
	ev_timer connection_launch_watcher;
	unsigned int connection_launch_rate;
	ev_tstamp connection_launch_period;
	double client_connections_per_period;
	int client_rst_close;
};


void uinet_demo_connscale_init(void);


#endif /* _UINET_DEMO_CONNSCALE_H_ */
