/*
 * Copyright (c) 2013-2015 Patrick Kelsey. All rights reserved.
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

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#include "uinet_demo_connscale.h"
#include "uinet_demo_internal.h"

static void connscale_print_usage(void);
static int connscale_init_cfg(struct uinet_demo_config *cfg);
static int connscale_process_args(struct uinet_demo_config *cfg, int argc, char **argv);
static void connscale_print_cfg(struct uinet_demo_config *cfg);
static int connscale_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
		      struct ev_loop *loop);
static int connscale_connect(struct uinet_demo_connscale *connscale, uint64_t index);

struct uinet_demo_info connscale_info = {
	.which = UINET_DEMO_CONNSCALE,
	.name = "connscale client/server",
	.cfg_size = sizeof(struct uinet_demo_connscale),
	.print_usage = connscale_print_usage,
	.init_cfg = connscale_init_cfg,
	.process_args = connscale_process_args,
	.print_cfg = connscale_print_cfg,
	.start = connscale_start
};

enum connscale_option_id {
	CONNSCALE_OPT_FOREIGN_IP = 1000,
	CONNSCALE_OPT_FOREIGN_MAC,
	CONNSCALE_OPT_FOREIGN_PORT,
	CONNSCALE_OPT_LOCAL_IP,
	CONNSCALE_OPT_LOCAL_MAC,
	CONNSCALE_OPT_LOCAL_PORT,
	CONNSCALE_OPT_MAX_CONN,
	CONNSCALE_OPT_RATE,
	CONNSCALE_OPT_RST_CLOSE,
	CONNSCALE_OPT_RX_SIZE,
	CONNSCALE_OPT_SERVER,
	CONNSCALE_OPT_TX_SIZE,
	CONNSCALE_OPT_VLAN
};

static const struct option connscale_long_options[] = {
	UINET_DEMO_BASE_LONG_OPTS,
	{ "foreign-ip",		required_argument,	NULL,	CONNSCALE_OPT_FOREIGN_IP },
	{ "foreign-mac",	required_argument,	NULL,	CONNSCALE_OPT_FOREIGN_MAC },
	{ "foreign-port",	required_argument,	NULL,	CONNSCALE_OPT_FOREIGN_PORT },
	{ "local-ip",		required_argument,	NULL,	CONNSCALE_OPT_LOCAL_IP },
	{ "local-mac",		required_argument,	NULL,	CONNSCALE_OPT_LOCAL_MAC },
	{ "local-port",		required_argument,	NULL,	CONNSCALE_OPT_LOCAL_PORT },
	{ "max-conn",		required_argument,	NULL,	CONNSCALE_OPT_MAX_CONN },
	{ "rate",		required_argument,	NULL,	CONNSCALE_OPT_RATE },
	{ "rst-close",		no_argument,		NULL,	CONNSCALE_OPT_RST_CLOSE },
	{ "rx-size",		required_argument,	NULL,	CONNSCALE_OPT_RX_SIZE },
	{ "server",		no_argument,		NULL,	CONNSCALE_OPT_SERVER },
	{ "tx-size",		required_argument,	NULL,	CONNSCALE_OPT_TX_SIZE },
	{ "vlan",		required_argument,	NULL,	CONNSCALE_OPT_VLAN},
	{ 0, 0, 0, 0 }
};



struct connscale_connection {
	struct uinet_demo_connscale *connscale;
	ev_uinet watcher;
	uint64_t id;
	int verbose;
};


static void
connscale_print_usage(void)
{
	printf("  --foreign-ip <ip>|<ip1>-<ip2>\n");
	printf("                          Specify the foreign IP address or range to use (default is 192.0.2.2)\n");
	printf("  --foreign-mac <mac>|<mac1>-<mac2>\n");
	printf("                          Specify the foreign mac address or range to use (default is 02:00:00:00:00:02)\n");
	printf("  --foreign-port <port>|<port1>-<port2>\n");
	printf("                          Specify the foreign port or range to use (default is 22222)\n");
	printf("  --local-ip <ip>|<ip1>-<ip2>\n");
	printf("                          Specify the local IP address or range to use (default is 192.0.2.1)\n");
	printf("  --local-mac <mac>|<mac1>-<mac2>\n");
	printf("                          Specify the local mac address or range to use (default is 02:00:00:00:00:01)\n");
	printf("  --local-port <port>|<port1>-<port2>\n");
	printf("                          Specify the local port or range to use (default is 22221)\n");
	printf("  --max-conn <value>      Maximum number of client connections to attempt, 0 means unlimited (default is 0)\n");
	printf("  --rate <value>          Number of client connections to attempt per second, 0 means serially (default is 0)\n");
	printf("  --rst-close             Send RST when closing client connections (default is normal TCP close)\n");
	printf("  --rx-size               Server receive size before transmitting or client receive size after transmitting (default is 0)\n");
	printf("  --server                Function as a server instead of a client\n");
	printf("  --tx-size               Server transmit size after receiving or client transmit size before receiving (default is 0)\n");
	printf("  --vlan <vlan>|<vlan1>-<vlan2>\n");
	printf("                          Specify the VLAN tag stack or range to use (default is none)\n");
}


static int
connscale_init_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_connscale *connscale = (struct uinet_demo_connscale *)cfg;

	uinet_demo_get_mac_addr_range("02:00:00:00:00:01", &connscale->local_mac_addrs);
	uinet_demo_get_mac_addr_range("02:00:00:00:00:02", &connscale->foreign_mac_addrs);
	uinet_demo_get_ipv4_addr_range("192.0.2.1", &connscale->local_ipv4_addrs, 1);
	uinet_demo_get_ipv4_addr_range("192.0.2.2", &connscale->foreign_ipv4_addrs, 1);
	uinet_demo_get_port_range("22221", &connscale->local_ports);
	uinet_demo_get_port_range("22222", &connscale->foreign_ports);

	return (0);
}


static int
connscale_process_args(struct uinet_demo_config *cfg, int argc, char **argv)
{
	struct uinet_demo_connscale *connscale = (struct uinet_demo_connscale *)cfg;
	int opt;

	while ((opt = getopt_long(argc, argv, ":" UINET_DEMO_BASE_OPT_STRING,
				  connscale_long_options, NULL)) != -1) {
		switch (opt) {
		case CONNSCALE_OPT_FOREIGN_IP:
			if (uinet_demo_get_ipv4_addr_range(optarg,
							   &connscale->foreign_ipv4_addrs, 1) != 0) {
				printf("%s: Invalid foreign IP address specification %s\n",
				       connscale->cfg.name, optarg);
				return (1);
			}
			break;
		case CONNSCALE_OPT_FOREIGN_MAC:
			if (uinet_demo_get_mac_addr_range(optarg,
							  &connscale->foreign_mac_addrs) != 0) {
				printf("%s: Invalid foreign MAC address specification %s\n",
				       connscale->cfg.name, optarg);
				return (1);
			}
			break;
		case CONNSCALE_OPT_FOREIGN_PORT:
			if (uinet_demo_get_port_range(optarg,
						      &connscale->foreign_ports) != 0) {
				printf("%s: Invalid foreign port specification %s\n",
				       connscale->cfg.name, optarg);
				return (1);
			}
			break;
		case CONNSCALE_OPT_LOCAL_IP:
			if (uinet_demo_get_ipv4_addr_range(optarg,
							   &connscale->local_ipv4_addrs, 1) != 0) {
				printf("%s: Invalid local IP address specification %s\n",
				       connscale->cfg.name, optarg);
				return (1);
			}
			break;
		case CONNSCALE_OPT_LOCAL_MAC:
			if (uinet_demo_get_mac_addr_range(optarg,
							  &connscale->local_mac_addrs) != 0) {
				printf("%s: Invalid local MAC address specification %s\n",
				       connscale->cfg.name, optarg);
				return (1);
			}
			break;
		case CONNSCALE_OPT_LOCAL_PORT:
			if (uinet_demo_get_port_range(optarg,
						      &connscale->local_ports) != 0) {
				printf("%s: Invalid local port specification %s\n",
				       connscale->cfg.name, optarg);
				return (1);
			}
			break;
		case CONNSCALE_OPT_MAX_CONN:
			connscale->client_connections_max = strtoul(optarg, NULL, 10);
			break;
		case CONNSCALE_OPT_RATE:
			connscale->connection_launch_rate = strtoul(optarg, NULL, 10);
			break;
		case CONNSCALE_OPT_RST_CLOSE:
			connscale->client_rst_close = 1;
			break;
		case CONNSCALE_OPT_RX_SIZE:
			connscale->read_size = strtoul(optarg, NULL, 10);
			break;
		case CONNSCALE_OPT_SERVER:
			connscale->server = 1;
			break;
		case CONNSCALE_OPT_TX_SIZE:
			connscale->write_size = strtoul(optarg, NULL, 10);
			break;
		case CONNSCALE_OPT_VLAN:
			if (uinet_demo_get_vlan_range(optarg,
						      &connscale->vlans) != 0) {
				printf("%s: Invalid vlan specification %s\n",
				       connscale->cfg.name, optarg);
				return (1);
			}
			break;
		case ':':
		case '?':
			return (opt);
		default:
			if (uinet_demo_base_process_arg(cfg, opt, optarg))
				return (opt);
			break;
		}
	}

	return (opt);
}


static void
connscale_print_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_connscale *connscale = (struct uinet_demo_connscale *)cfg;
	char buf[64];

	printf("mode=%s",
	       connscale->server ? "server" : "client");
	if (!connscale->server) {
		if (connscale->connection_launch_rate)
			printf(" rate=%u", connscale->connection_launch_rate);
		else
			printf(" rate=serial");

		if (connscale->client_connections_max)
			printf(" max-conn=%llu", (unsigned long long)connscale->client_connections_max);
		else
			printf(" max-conn=unlimited");
	}
	printf(" vlan=%s", uinet_demo_vlan_range_str(buf, sizeof(buf), &connscale->vlans));
	if (!connscale->server)
		printf(" l_mac=%s", uinet_demo_mac_addr_range_str(buf, sizeof(buf), &connscale->local_mac_addrs));
	printf(" l_ip=%s", uinet_demo_ipv4_addr_range_str(buf, sizeof(buf), &connscale->local_ipv4_addrs));
	printf(" l_port=%s", uinet_demo_port_range_str(buf, sizeof(buf), &connscale->local_ports));
	if (!connscale->server) {
		printf(" f_mac=%s", uinet_demo_mac_addr_range_str(buf, sizeof(buf), &connscale->foreign_mac_addrs));
		printf(" f_ip=%s", uinet_demo_ipv4_addr_range_str(buf, sizeof(buf), &connscale->foreign_ipv4_addrs));
		printf(" f_port=%s", uinet_demo_port_range_str(buf, sizeof(buf), &connscale->foreign_ports));
	}
}


static void
get_server_tuple(struct uinet_demo_connscale *connscale, uint64_t index,
		 uint16_t *vlan, struct uinet_in_addr *addr, uint16_t *port)
{
	uint64_t vlan_index;
	uint64_t ip_index;
	uint32_t ip_addr;
	uint32_t port_index;

	if (connscale->vlans.size > 0) {
		vlan_index = index % connscale->vlans.size;
		index /= connscale->vlans.size;
		uinet_demo_get_vlan_n(&connscale->vlans, vlan_index, vlan);
	}

	ip_index = index % connscale->local_ipv4_addrs.size;
	index /= connscale->local_ipv4_addrs.size;
	uinet_demo_get_ipv4_addr_n(&connscale->local_ipv4_addrs, ip_index, &ip_addr);
	addr->s_addr = htonl(ip_addr);

	port_index = index % connscale->local_ports.size;
	uinet_demo_get_port_n(&connscale->local_ports, port_index, port);
}


static void
decompose_client_tuple_index(const struct uinet_demo_connscale *connscale, uint64_t index,
			     uint64_t *vlan_index,
			     uint64_t *local_mac_index, uint64_t *foreign_mac_index,
			     uint64_t *local_ip_index, uint32_t *local_port_index,
			     uint64_t *foreign_ip_index, uint32_t *foreign_port_index)
{
	

	if (connscale->vlans.size > 0) {
		*vlan_index = index % connscale->vlans.size;
		index /= connscale->vlans.size;
	}

	*local_ip_index = index % connscale->local_ipv4_addrs.size;
	index /= connscale->local_ipv4_addrs.size;

	*local_port_index = index % connscale->local_ports.size;
	index /= connscale->local_ports.size;

	*foreign_ip_index = index % connscale->foreign_ipv4_addrs.size;
	index /= connscale->foreign_ipv4_addrs.size;
	
	*foreign_port_index = index % connscale->foreign_ports.size;
	index /= connscale->foreign_ports.size;

	*local_mac_index = *local_ip_index;
	*foreign_mac_index = *foreign_ip_index;

	if (connscale->vlans.size > 0) {
		*local_mac_index *= connscale->vlans.size;
		*local_mac_index += *vlan_index;

		*foreign_mac_index *= connscale->vlans.size;
		*foreign_mac_index += *vlan_index;
	}

	*local_mac_index %= connscale->local_mac_addrs.size;
	*foreign_mac_index %= connscale->foreign_mac_addrs.size;
}


static void
get_client_tuple(const struct uinet_demo_connscale *connscale, uint64_t index,
		 uint8_t *local_mac, uint8_t *foreign_mac, uint16_t *vlan,
		 struct uinet_in_addr *local_addr, uint16_t *local_port,
		 struct uinet_in_addr *foreign_addr, uint16_t *foreign_port)
{
	uint64_t vlan_index;
	uint64_t local_mac_index;
	uint64_t local_ip_index;
	uint32_t local_ip_addr;
	uint32_t local_port_index;
	uint64_t foreign_mac_index;
	uint64_t foreign_ip_index;
	uint32_t foreign_ip_addr;
	uint32_t foreign_port_index;

	decompose_client_tuple_index(connscale, index, &vlan_index,
				     &local_mac_index, &foreign_mac_index,
				     &local_ip_index, &local_port_index,
				     &foreign_ip_index, &foreign_port_index);

	if (connscale->vlans.size > 0)
		uinet_demo_get_vlan_n(&connscale->vlans, vlan_index, vlan);

	uinet_demo_get_ipv4_addr_n(&connscale->local_ipv4_addrs, local_ip_index,
				   &local_ip_addr);
	local_addr->s_addr = htonl(local_ip_addr);

	uinet_demo_get_port_n(&connscale->local_ports, local_port_index, local_port);

	uinet_demo_get_ipv4_addr_n(&connscale->foreign_ipv4_addrs, foreign_ip_index,
				   &foreign_ip_addr);
	foreign_addr->s_addr = htonl(foreign_ip_addr);

	uinet_demo_get_port_n(&connscale->foreign_ports, foreign_port_index, foreign_port);

	uinet_demo_get_mac_addr_n(&connscale->local_mac_addrs, local_mac_index, local_mac);
	uinet_demo_get_mac_addr_n(&connscale->foreign_mac_addrs, foreign_mac_index, foreign_mac);
}


static void
connscale_server_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct connscale_connection *conn = w->data;
	struct uinet_demo_connscale *connscale = conn->connscale;
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int read_size;
	int write_size;
	int error;
#define BUFFER_SIZE (64*1024)
	char buffer[BUFFER_SIZE];

	if (connscale->read_remaining > 0) {
		read_size = connscale->read_remaining > BUFFER_SIZE ? BUFFER_SIZE : connscale->read_remaining;

		uio.uio_iov = &iov;
		iov.iov_base = buffer;
		iov.iov_len = read_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = read_size;

		error = uinet_soreceive(w->so, NULL, &uio, NULL);
		if (0 != error) {
			if (conn->verbose)
				printf("%s: connection %llu: read error (%d), closing\n",
				       connscale->cfg.name, (unsigned long long)conn->id, error);
			goto err;
		}

		connscale->read_remaining -= read_size - uio.uio_resid;
	}

	if ((connscale->read_remaining == 0) && (connscale->write_remaining > 0)) {
		write_size = connscale->write_remaining > BUFFER_SIZE ? BUFFER_SIZE : connscale->write_remaining;

		uio.uio_iov = &iov;
		iov.iov_base = buffer;
		iov.iov_len = write_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = write_size;
		error = uinet_sosend(w->so, NULL, &uio, 0);
		if (0 != error) {
			if (conn->verbose)
				printf("%s: connection %llu: write error (%d), closing\n",
				       connscale->cfg.name, (unsigned long long)conn->id, error);
			goto err;
		}

		connscale->write_remaining -= write_size - uio.uio_resid;
		if ((connscale->write_remaining > 0) && (w->events == EV_READ)) {
			ev_uinet_stop(loop, w);
			w->events = EV_WRITE;
			ev_uinet_start(loop, w);
		}
	}

	if ((connscale->read_remaining > 0) || (connscale->write_remaining > 0))
		return;

 err:
	ev_uinet_stop(loop, w);
	ev_uinet_detach(w->ctx);
	uinet_soclose(w->so);
	uinet_pool_free(connscale->connection_pool, conn);
}


static void
connscale_connected_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct connscale_connection *conn = w->data;
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];

	uinet_sogetsockaddr(w->so, (struct uinet_sockaddr **)&sin1);
	uinet_sogetpeeraddr(w->so, (struct uinet_sockaddr **)&sin2);
	printf("%s: connection %llu: established (local=%s:%u foreign=%s:%u)\n",
	       conn->connscale->cfg.name, (unsigned long long)conn->id,
	       uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
	       uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
	uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
	uinet_free_sockaddr((struct uinet_sockaddr *)sin2);

	ev_uinet_stop(loop, w);
	uinet_pool_free(conn->connscale->connection_pool, conn);
}


static void
connscale_accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct connscale_connection *listen_conn = w->data;
	struct uinet_demo_connscale *connscale = listen_conn->connscale;
	struct uinet_socket *newso = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct connscale_connection *connected_conn = NULL;
	struct connscale_connection *conn = NULL;
	unsigned int batch_limit = 32;
	unsigned int processed = 0;
	int error;

	while ((processed < batch_limit) &&
	       (UINET_EWOULDBLOCK != (error = uinet_soaccept(w->so, NULL, &newso)))) {
		processed++;

		if (0 == error) {
			if (listen_conn->verbose)
				printf("%s: Accept succeeded\n", connscale->cfg.name);
		
			soctx = ev_uinet_attach(newso);
			if (NULL == soctx) {
				printf("%s: Failed to alloc libev context for new connection\n",
				       connscale->cfg.name);
				goto fail;
			}

			conn = uinet_pool_alloc(connscale->connection_pool, UINET_POOL_ALLOC_WAITOK);
			if (conn == NULL) {
				printf("%s: Connection context allocation failed (%d)\n", connscale->cfg.name, error);
				goto fail;
			}
			conn->connscale = connscale;
			conn->id = connscale->num_connections++;
			conn->verbose = connscale->cfg.verbose;

			if (conn->verbose) {
				/* just need a watcher here, use a connection context for convenience */
				connected_conn = uinet_pool_alloc(connscale->connection_pool, UINET_POOL_ALLOC_WAITOK);
				if (connected_conn == NULL) {
					printf("%s: Connection complete context allocation failed (%d)\n", connscale->cfg.name, error);
					goto fail;
				}
				connected_conn->connscale = conn->connscale;
				connected_conn->id = conn->id;
				connected_conn->verbose = conn->verbose;

				ev_init(&connected_conn->watcher, connscale_connected_cb);
				ev_uinet_set(&connected_conn->watcher, soctx, EV_WRITE);
				connected_conn->watcher.data = connected_conn;
				ev_uinet_start(loop, &connected_conn->watcher);
			}

			connscale->read_remaining = connscale->read_size;
			connscale->write_remaining = connscale->write_size;

			ev_init(&conn->watcher, connscale_server_cb);
			ev_uinet_set(&conn->watcher, soctx, 
				     ((connscale->read_remaining > 0) || (connscale->write_remaining == 0)) ? EV_READ : EV_WRITE);
			conn->watcher.data = conn;
			ev_uinet_start(loop, &conn->watcher);
			
			continue;
		fail:
			if (conn) uinet_pool_free(connscale->connection_pool, conn);
			if (connected_conn) uinet_pool_free(connscale->connection_pool, connected_conn);
			if (soctx) ev_uinet_detach(soctx);
			if (newso) uinet_soclose(newso);
		} else if (error != UINET_ECONNABORTED)
			printf("%s: Accept failed (%d)\n", connscale->cfg.name, error);
	}


	return;
}


static int
connscale_start_server(struct uinet_demo_connscale *connscale)
{
	uint64_t num_listens;
	uint64_t i;
	uint16_t vlan[UINET_IN_L2INFO_MAX_TAGS];
	struct uinet_in_addr ip;
	uint16_t port;
	char tmp[64];
	struct uinet_in_l2tagstack tagstack;
	struct connscale_connection *listen_conn = NULL;
	struct uinet_socket *listen_socket = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;


	num_listens =
	    (connscale->vlans.size ? connscale->vlans.size : 1ULL) *
	    connscale->local_ipv4_addrs.size *
	    connscale->local_ports.size;
	for (i = 0; i < num_listens; i++) {
		get_server_tuple(connscale, i, vlan, &ip, &port);
		
		listen_conn = uinet_pool_alloc(connscale->connection_pool, UINET_POOL_ALLOC_WAITOK);
		if (listen_conn == NULL) {
			printf("%s: Listen connection allocation failed (%d)\n", connscale->cfg.name, error);
			goto fail;
		}
		listen_conn->connscale = connscale;
		listen_conn->verbose = connscale->cfg.verbose;

		error = uinet_socreate(connscale->cfg.uinst, UINET_PF_INET, &listen_socket, UINET_SOCK_STREAM, 0);
		if (0 != error) {
			printf("%s: Listen socket creation failed (%d)\n", connscale->cfg.name, error);
			goto fail;
		}

		soctx = ev_uinet_attach(listen_socket);
		if (NULL == soctx) {
			printf("%s: Failed to alloc libev socket context\n", connscale->cfg.name);
			error = UINET_ENOMEM;
			goto fail;
		}

		if ((error = uinet_make_socket_promiscuous(listen_socket, NULL))) {
			printf("%s: Failed to make listen socket promiscuous (%d)\n",
			       connscale->cfg.name, error);
			goto fail;
		}


		/*
		 * Socket needs to be non-blocking to work with the event system
		 */
		uinet_sosetnonblocking(listen_socket, 1);
		
		/* 
		 * Set NODELAY on the listen socket so it will be set on all
		 * accepted sockets via inheritance.
		 */
		optlen = sizeof(optval);
		optval = 1;
		if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_NODELAY,
						&optval, optlen))) {
			printf("%s: Failed to set TCP_NODELAY (%d)\n", connscale->cfg.name, error);
			goto fail;
		}

		/* 
		 * Set NOTIMEWAIT on the listen socket so it will be set on all
		 * accepted sockets via inheritance.
		 */
		optlen = sizeof(optval);
		optval = 1;
		if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_NOTIMEWAIT,
						&optval, optlen))) {
			printf("%s: Failed to set TCP_NOTIMEWAIT (%d)\n", connscale->cfg.name, error);
			goto fail;
		}

		if (connscale->vlans.size > 0) {
			unsigned int vindex;
			uint32_t ethertype;
			
			tagstack.inl2t_cnt = connscale->vlans.size;
			for (vindex = 0; vindex < connscale->vlans.size; vindex++) {
				ethertype = (vindex == (connscale->vlans.size - 1)) ? 0x8100 : 0x88a8;
				tagstack.inl2t_tags[vindex] = htonl((ethertype << 16) | vlan[vindex]);
				tagstack.inl2t_masks[vindex] = (vlan[vindex] == 0) ? 0 : htonl(0x00000fff);
			}
		}
		if ((error = uinet_setl2info2(listen_socket, NULL, NULL,
					      connscale->vlans.size ? 0 : UINET_INL2I_TAG_ANY,
					      connscale->vlans.size ? &tagstack : NULL))) {
			printf("%s: Listen socket L2 info set failed (%d)\n",
			       connscale->cfg.name, error);
			goto fail;
		}

		memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
		sin.sin_len = sizeof(struct uinet_sockaddr_in);
		sin.sin_family = UINET_AF_INET;
		sin.sin_addr = ip;
		sin.sin_port = htons(port);
		error = uinet_sobind(listen_socket, (struct uinet_sockaddr *)&sin);
		if (0 != error) {
			printf("%s: Bind to %s:%u failed\n", connscale->cfg.name,
			       uinet_inet_ntop(UINET_AF_INET, &ip, tmp, sizeof(tmp)), port);
			goto fail;
		}
	
		error = uinet_solisten(listen_socket, -1);
		if (0 != error) {
			printf("%s: Listen on %s:%u failed\n", connscale->cfg.name,
			       uinet_inet_ntop(UINET_AF_INET, &ip, tmp, sizeof(tmp)), port);
			goto fail;
		}


		/* If listening on 0.0.0.0:0, make this socket the
		 * catchall listen so that all wildcard inpcb lookups
		 * will resolve to this socket.
		 */
		if ((ip.s_addr == INADDR_ANY) && (port == 0))
			uinet_sosetcatchall(listen_socket);
		
		if (connscale->cfg.verbose) {
			printf("%s: Listening on vlan=%s", connscale->cfg.name,
			       uinet_demo_vlan_str(tmp, sizeof(tmp), vlan, connscale->vlans.num_tags));
			printf(" ip=%s port=%u\n",
			       uinet_inet_ntop(UINET_AF_INET, &ip, tmp, sizeof(tmp)), port);
		}

		listen_conn->id = connscale->num_listens++;

		/*
		 * Set up a read watcher to accept new connections
		 */
		ev_init(&listen_conn->watcher, connscale_accept_cb);
		ev_uinet_set(&listen_conn->watcher, soctx, EV_READ);
		listen_conn->watcher.data = listen_conn;
		ev_uinet_start(connscale->cfg.loop, &listen_conn->watcher);
	}
	
	return (0);

fail:
	if (listen_conn) uinet_pool_free(connscale->connection_pool, listen_conn);
	if (soctx) ev_uinet_detach(soctx);
	if (listen_socket) uinet_soclose(listen_socket);

	return (-1);
}



static void
connscale_client_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct connscale_connection *conn = w->data;
	struct uinet_demo_connscale *connscale = conn->connscale;
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int read_size;
	int write_size;
	int error;
#define BUFFER_SIZE (64*1024)
	char buffer[BUFFER_SIZE];
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];

	if (conn->verbose) {
		uinet_sogetsockaddr(w->so, (struct uinet_sockaddr **)&sin1);
		uinet_sogetpeeraddr(w->so, (struct uinet_sockaddr **)&sin2);
		printf("%s: connection %llu: established, closing (local=%s:%u foreign=%s:%u)\n",
		       conn->connscale->cfg.name, (unsigned long long)conn->id,
		       uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
		       uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
		uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
		uinet_free_sockaddr((struct uinet_sockaddr *)sin2);
	}

	if (connscale->write_remaining > 0) {
		write_size = connscale->write_remaining > BUFFER_SIZE ? BUFFER_SIZE : connscale->write_remaining;

		uio.uio_iov = &iov;
		iov.iov_base = buffer;
		iov.iov_len = write_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = write_size;
		error = uinet_sosend(w->so, NULL, &uio, 0);
		if (0 != error) {
			if (conn->verbose)
				printf("%s: connection %llu: write error (%d), closing\n",
				       connscale->cfg.name, (unsigned long long)conn->id, error);
			goto err;
		}

		connscale->write_remaining -= write_size - uio.uio_resid;
	}

	if ((connscale->write_remaining == 0)  && (connscale->read_remaining > 0)) {
		read_size = connscale->read_remaining > BUFFER_SIZE ? BUFFER_SIZE : connscale->read_remaining;

		uio.uio_iov = &iov;
		iov.iov_base = buffer;
		iov.iov_len = read_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = read_size;

		error = uinet_soreceive(w->so, NULL, &uio, NULL);
		if (0 != error) {
			if (conn->verbose)
				printf("%s: connection %llu: read error (%d), closing\n",
				       connscale->cfg.name, (unsigned long long)conn->id, error);
			goto err;
		}

		connscale->read_remaining -= read_size - uio.uio_resid;
		if ((connscale->read_remaining > 0) && (w->events == EV_WRITE)) {
			ev_uinet_stop(loop, w);
			w->events = EV_READ;
			ev_uinet_start(loop, w);
		}
	}

	if ((connscale->read_remaining > 0) || (connscale->write_remaining > 0))
		return;

 err:
	ev_uinet_stop(loop, w);
	ev_uinet_detach(w->ctx);
	uinet_soclose(w->so);
	uinet_pool_free(connscale->connection_pool, conn);

	if ((connscale->connection_launch_rate == 0) &&
	    !((connscale->client_connections_max > 0) &&
	      (connscale->client_connections_launched == connscale->client_connections_max))) {
		if (++connscale->next_tuple == connscale->num_tuples)
			connscale->next_tuple = 0;
		connscale_connect(connscale,  connscale->next_tuple);
	}
}


static int
connscale_connect(struct uinet_demo_connscale *connscale, uint64_t index)
{
	uint16_t vlan[UINET_IN_L2INFO_MAX_TAGS];
	uint8_t local_mac[6];
	uint8_t foreign_mac[6];
	struct uinet_in_addr local_ip;
	struct uinet_in_addr foreign_ip;
	uint16_t local_port;
	uint16_t foreign_port;
	char tmp[64];
	struct uinet_in_l2tagstack tagstack;
	struct connscale_connection *conn = NULL;
	struct uinet_socket *so = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;
	struct uinet_linger linger;

	get_client_tuple(connscale, index, local_mac, foreign_mac, vlan,
			 &local_ip, &local_port, &foreign_ip, &foreign_port);
		
	conn = uinet_pool_alloc(connscale->connection_pool, UINET_POOL_ALLOC_WAITOK);
	if (conn == NULL) {
		printf("%s: Connection allocation failed\n", connscale->cfg.name);
		goto fail;
	}
	conn->connscale = connscale;
	conn->verbose = connscale->cfg.verbose;

	error = uinet_socreate(connscale->cfg.uinst, UINET_PF_INET, &so, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("%s: Socket creation failed (%d)\n", connscale->cfg.name, error);
		goto fail;
	}

	soctx = ev_uinet_attach(so);
	if (NULL == soctx) {
		printf("%s: Failed to alloc libev socket context\n", connscale->cfg.name);
		error = UINET_ENOMEM;
		goto fail;
	}


	/* XXX for now, if there are multiple interfaces attached to this
	 * stack, transmit on the first one instead of selecting them
	 * round-robin as performance is better using one transmit queue
	 * instead of N
	 */
#if 0
	connscale->next_client_conn_if = uinet_ifnext(connscale->cfg.uinst,
						      connscale->next_client_conn_if);
#else
	if (connscale->next_client_conn_if == NULL)
		connscale->next_client_conn_if = uinet_ifnext(connscale->cfg.uinst,
							      connscale->next_client_conn_if);
#endif
	if ((error = uinet_make_socket_promiscuous(so, connscale->next_client_conn_if))) {
		printf("%s: Failed to make socket promiscuous (%d)\n",
		       connscale->cfg.name, error);
		goto fail;
	}

	/* Use fast ISN generation */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(so, UINET_IPPROTO_TCP, UINET_TCP_TRIVIAL_ISN, &optval, optlen))) {
		printf("%s: Failed to set TCP_TRIVIAL_ISN (%d)\n", connscale->cfg.name, error);
		goto fail;
	}

	/* Skip TIMEWAIT state on close */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(so, UINET_IPPROTO_TCP, UINET_TCP_NOTIMEWAIT, &optval, optlen))) {
		printf("%s: Failed to set TCP_NOTIMEWAIT (%d)\n", connscale->cfg.name, error);
		goto fail;
	}

	if (connscale->client_rst_close) {
		/* Drop connection on close */
		optlen = sizeof(linger);
		linger.l_onoff = 1;
		linger.l_linger = 0;
		if ((error = uinet_sosetsockopt(so, UINET_SOL_SOCKET, UINET_SO_LINGER, &linger, optlen))) {
			printf("%s: Failed to set SO_LINGER (%d)\n", connscale->cfg.name, error);
			goto fail;
		}
	}

	/*
	 * Socket needs to be non-blocking to work with the event system
	 */
	uinet_sosetnonblocking(so, 1);
		
	/* Set NODELAY on the socket
	 */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(so, UINET_IPPROTO_TCP, UINET_TCP_NODELAY,
					&optval, optlen))) {
		printf("%s: Failed to set TCP_NODELAY (%d)\n", connscale->cfg.name, error);
		goto fail;
	}

	if (connscale->vlans.size > 0) {
		unsigned int vindex;
		uint32_t ethertype;
			
		tagstack.inl2t_cnt = connscale->vlans.size;
		for (vindex = 0; vindex < connscale->vlans.size; vindex++) {
			ethertype = (vindex == (connscale->vlans.size - 1)) ? 0x8100 : 0x88a8;
			tagstack.inl2t_tags[vindex] = htonl((ethertype << 16) | vlan[vindex]);
			tagstack.inl2t_masks[vindex] = (vlan[vindex] == 0) ? 0 : htonl(0x00000fff);
		}
	}
	if ((error = uinet_setl2info2(so, local_mac, foreign_mac,
				      connscale->vlans.size ? 0 : UINET_INL2I_TAG_ANY,
				      connscale->vlans.size ? &tagstack : NULL))) {
		printf("%s: Socket L2 info set failed (%d)\n",
		       connscale->cfg.name, error);
		goto fail;
	}

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = local_ip;
	sin.sin_port = htons(local_port);
	error = uinet_sobind(so, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("%s: Bind to %s:%u failed\n", connscale->cfg.name,
		       uinet_inet_ntop(UINET_AF_INET, &local_ip, tmp, sizeof(tmp)), local_port);
		goto fail;
	}
	
	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = foreign_ip;
	sin.sin_port = htons(foreign_port);
	error = uinet_soconnect(so, (struct uinet_sockaddr *)&sin);
	if (error) {
		if (UINET_EINPROGRESS == error) {
			error = 0;
		} else {
			printf("%s: Connect from %s:%u", connscale->cfg.name,
			       uinet_inet_ntop(UINET_AF_INET, &local_ip, tmp, sizeof(tmp)),
			       local_port);
			printf(" to %s:%u failed (%d)\n", 
			       uinet_inet_ntop(UINET_AF_INET, &foreign_ip, tmp, sizeof(tmp)),
			       foreign_port, error);
			goto fail;
		}
	}

	if (connscale->cfg.verbose) {
		printf("%s: Connecting on vlan=%s", connscale->cfg.name,
		       uinet_demo_vlan_str(tmp, sizeof(tmp), vlan, connscale->vlans.num_tags));
		printf(" from ip=%s port=%u",
		       uinet_inet_ntop(UINET_AF_INET, &local_ip, tmp, sizeof(tmp)), local_port);
		printf(" to ip=%s port=%u\n",
		       uinet_inet_ntop(UINET_AF_INET, &foreign_ip, tmp, sizeof(tmp)), foreign_port);
	}

	conn->id = connscale->client_connections_launched++;

	connscale->write_remaining = connscale->write_size;
	connscale->read_remaining = connscale->read_size;

	/*
	 * Set up a write watcher to continue when the connection is complete
	 */
	ev_init(&conn->watcher, connscale_client_cb);
	ev_uinet_set(&conn->watcher, soctx, 
		     ((connscale->write_remaining > 0) || (connscale->read_remaining == 0)) ? EV_WRITE : EV_READ);
	conn->watcher.data = conn;
	ev_uinet_start(connscale->cfg.loop, &conn->watcher);

	return (0);

fail:
	if (conn) uinet_pool_free(connscale->connection_pool, conn);
	if (soctx) ev_uinet_detach(soctx);
	if (so) uinet_soclose(so);

	return (-1);
}


static unsigned int
connscale_launch_periodic_connections(struct uinet_demo_connscale *connscale)
{
	uint64_t num_to_launch;
	uint64_t i;

	connscale->client_current_period++;
	num_to_launch =
	    connscale->client_connections_per_period * connscale->client_current_period
	    - connscale->client_connections_launched;

	for (i = 0; i < num_to_launch; i++) {
	    if ((connscale->client_connections_max > 0) &&
		(connscale->client_connections_launched == connscale->client_connections_max))
		    return (1);

		connscale_connect(connscale, connscale->next_tuple);
		if (++connscale->next_tuple == connscale->num_tuples)
			connscale->next_tuple = 0;
	}

	return (0);
}


static void
connection_launch_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct uinet_demo_connscale *connscale = w->data;
	unsigned int done;

	done = connscale_launch_periodic_connections(connscale);

	if (done)
		ev_timer_stop(loop, w);
}


static int
connscale_start_client(struct uinet_demo_connscale *connscale)
{
	double min_period;
	unsigned int done;

	connscale->num_tuples =
	    (connscale->vlans.size ? connscale->vlans.size : 1ULL) *
	    connscale->local_ipv4_addrs.size *
	    connscale->local_ports.size *
	    connscale->foreign_ipv4_addrs.size *
	    connscale->foreign_ports.size;

	if (connscale->connection_launch_rate == 0)
		connscale_connect(connscale,  connscale->next_tuple);
	else {
		min_period = 0.001;
		connscale->connection_launch_period = min_period;
		connscale->client_connections_per_period =
		    connscale->connection_launch_rate * connscale->connection_launch_period;

		/*
		 * If the rate is less than one per min_period, recompute
		 * the period so the rate is one per period.
		 */
		if (connscale->client_connections_per_period < 1.0) {
			connscale->connection_launch_period = 1.0 / connscale->connection_launch_rate;
			connscale->client_connections_per_period = 1;
		}

		if (connscale->cfg.verbose)
			printf("%s: launch_period=%fs conns_per_period=%f\n",
			       connscale->cfg.name,
			       connscale->connection_launch_period, connscale->client_connections_per_period);

		done = connscale_launch_periodic_connections(connscale);

		if (!done) {
			ev_timer_init(&connscale->connection_launch_watcher, connection_launch_cb,
				      connscale->connection_launch_period,
				      connscale->connection_launch_period);
			connscale->connection_launch_watcher.data = connscale;
			ev_timer_start(connscale->cfg.loop, &connscale->connection_launch_watcher);
		}
	}

	return (0);
}


static int
connscale_start(struct uinet_demo_config *cfg, uinet_instance_t uinst, struct ev_loop *loop)
{
	struct uinet_demo_connscale *connscale = (struct uinet_demo_connscale *)cfg;

	connscale->connection_pool =
	    uinet_pool_create("connscale connections", sizeof(struct connscale_connection),
			      NULL, NULL, NULL, NULL, UINET_POOL_ALIGN_PTR, 0);

	if (connscale->connection_pool == NULL) {
		printf("%s: Failed to create connection pool\n", cfg->name);
		return (-1);
	}

	if (connscale->server) {
		if (connscale_start_server(connscale) != 0)
			return (-1);
	} else {
		if (connscale_start_client(connscale) != 0)
			return (-1);
	}

	return (0);
}




