/*
 * Copyright (c) 2016 Patrick Kelsey. All rights reserved.
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

/*
 * nproxy is a non-transparent TCP proxy demo
 *
 * 'Non-transparent' could mean a lot of things.  In this case, it means
 * that the proxy establishes the inbound connection before it establishes
 * the outbound (proxied) connection.  With this approach, the proxy alters
 * (i.e., is non-transparent regarding) some connection failure behaviors.
 * Consider what happens when the outbound connection cannot be established
 * because the server isn't there - the client will see a connection
 * established, then closed when the proxy determines it can't reach that
 * server.
 *
 * That being said, unlike with a fully transparent proxy, this kind of
 * proxy doesn't defeat the functionality of the syncache and syncookies.
 *
 * This version of nproxy is transparent at the addressing level - the same
 * L2, L3, and L4 addressing (VLAN tag stack, MAC addresses, IP addresses,
 * and TCP ports) are used on both sides of the proxy.
 *
 */

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include "uinet_demo_nproxy.h"
#include "uinet_demo_internal.h"

static void nproxy_print_usage(void);
static int nproxy_init_cfg(struct uinet_demo_config *cfg);
static int nproxy_process_args(struct uinet_demo_config *cfg, int argc, char **argv);
static void nproxy_print_cfg(struct uinet_demo_config *cfg);
static int nproxy_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
		      struct ev_loop *loop);

struct uinet_demo_info nproxy_info = {
	.which = UINET_DEMO_NPROXY,
	.name = "nproxy server",
	.cfg_size = sizeof(struct uinet_demo_nproxy),
	.print_usage = nproxy_print_usage,
	.init_cfg = nproxy_init_cfg,
	.process_args = nproxy_process_args,
	.print_cfg = nproxy_print_cfg,
	.start = nproxy_start
};


enum nproxy_option_id {
	NPROXY_OPT_LISTEN = 1000,
	NPROXY_OPT_OUTBOUND_IF
};

static const struct option nproxy_long_options[] = {
	UINET_DEMO_BASE_LONG_OPTS,
	{ "listen",	required_argument,	NULL,	NPROXY_OPT_LISTEN },
	{ "outbound-if", required_argument,	NULL,	NPROXY_OPT_OUTBOUND_IF },
	{ 0, 0, 0, 0 }
};


struct nproxy_splice;

struct nproxy_connection {
	struct nproxy_splice *splice;
	const char *name;
	ev_uinet copy_watcher; /* used for the data copy callback */
	ev_uinet connected_watcher; /* used for the connection-complete callback */
	ev_uinet writable_watcher; /* used by the other connection's data copy callback to wait for writability */
	struct nproxy_connection *other_side;
};

struct nproxy_splice {
	struct uinet_demo_nproxy *nproxy;
	struct nproxy_connection inbound; /* accepted connection */
	struct nproxy_connection outbound; /* originated connection */
	uint64_t id;
	int verbose;
};

static inline int imin(int a, int b) { return (a < b ? a : b); }


static void
nproxy_conn_destroy(struct ev_loop *loop, struct nproxy_connection *conn)
{
	struct ev_uinet_ctx *ctx;

	ctx = conn->copy_watcher.ctx;
	ev_uinet_stop(loop, &conn->copy_watcher);
	ev_uinet_stop(loop, &conn->connected_watcher);
	ev_uinet_stop(loop, &conn->writable_watcher);
	uinet_soclose(ev_uinet_so(ctx));
	ev_uinet_detach(ctx);
}


static void
nproxy_splice_destroy(struct ev_loop *loop, struct nproxy_splice *splice)
{
	nproxy_conn_destroy(loop, &splice->inbound);
	nproxy_conn_destroy(loop, &splice->outbound);
	free(splice);
}


static void
nproxy_copy_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct nproxy_connection *conn = w->data;
	struct nproxy_connection *other_side_conn = conn->other_side;
	struct nproxy_splice *splice = conn->splice;
	struct uinet_demo_nproxy *nproxy = splice->nproxy;
	struct uinet_socket *other_side_so = conn->other_side->copy_watcher.so;
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int max_read;
	int max_write;
	int read_size;
	int error;
#define BUFFER_SIZE (64*1024)
	char buffer[BUFFER_SIZE];

	max_read = uinet_soreadable(w->so, 0);
	if (max_read <= 0) {
		/* the watcher should never be invoked if there is no error and there no bytes to be read */
		assert(max_read != 0);
		if (splice->verbose)
			printf("%s: splice %llu: %s: can't read, closing splice\n",
			       nproxy->cfg.name, (unsigned long long)splice->id, conn->name);
		goto err;
	} else {
		max_write = uinet_sowritable(other_side_so, 0);
		if (-1 == max_write) {
			if (splice->verbose)
				printf("%s: splice %llu: %s: can't write, closing splice\n",
				       nproxy->cfg.name, (unsigned long long)splice->id, other_side_conn->name);
			goto err;
		} else {
			read_size = imin(imin(max_read, max_write), BUFFER_SIZE);

			/* read_size == 0 should only happen when max_write is 0 */
			if (read_size > 0) {
				uio.uio_iov = &iov;
				iov.iov_base = buffer;
				iov.iov_len = read_size;
				uio.uio_iovcnt = 1;
				uio.uio_offset = 0;
				uio.uio_resid = read_size;
	
				error = uinet_soreceive(w->so, NULL, &uio, NULL);
				if (0 != error) {
					printf("%s: splice %llu: %s: read error (%d), closing splice\n",
					       nproxy->cfg.name, (unsigned long long)splice->id, conn->name, error);
					goto err;
				}

				assert(uio.uio_resid == 0);

				uio.uio_iov = &iov;
				iov.iov_base = buffer;
				iov.iov_len = read_size;
				uio.uio_iovcnt = 1;
				uio.uio_offset = 0;
				uio.uio_resid = read_size;
				error = uinet_sosend(other_side_so, NULL, &uio, 0);
				if (0 != error) {
					printf("%s: splice %llu: %s: write error (%d), closing splice\n",
					       nproxy->cfg.name, (unsigned long long)splice->id, other_side_conn->name, error);
					goto err;
				}
			}

			if (max_write < max_read) {
				/* 
				 * Limited by write space, so deactivate us
				 * and activate the write watcher for the
				 * other side, which will reactivate us when
				 * it fires.
				 */
				ev_uinet_stop(loop, w);
				ev_uinet_start(loop, &other_side_conn->writable_watcher);
			}
		}
	}

	return;

 err:
	nproxy_splice_destroy(loop, splice);
}


static void
nproxy_writable_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct nproxy_connection *conn = w->data;
	struct nproxy_connection *other_side_conn = conn->other_side;

	/* restart the other side's copy watcher */
	ev_uinet_start(loop, &other_side_conn->copy_watcher);

	/* stop this watcher until the other side's copy watcher needs it again */
	ev_uinet_stop(loop, w);
}


static void
nproxy_outbound_connected_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct nproxy_splice *splice = w->data;
	struct uinet_demo_nproxy *nproxy = splice->nproxy;
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];

	ev_uinet_stop(loop, w);

	if (splice->verbose) {
		uinet_sogetsockaddr(w->so, (struct uinet_sockaddr **)&sin1);
		uinet_sogetpeeraddr(w->so, (struct uinet_sockaddr **)&sin2);
		printf("%s: splice %llu: outbound connection established (local=%s:%u foreign=%s:%u)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id,
		       uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
		       uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
		uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
		uinet_free_sockaddr((struct uinet_sockaddr *)sin2);
	}

	ev_uinet_start(loop, &splice->inbound.copy_watcher);
	ev_uinet_start(loop, &splice->outbound.copy_watcher);
}


static void
nproxy_inbound_connected_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct nproxy_splice *splice = w->data;
	struct uinet_demo_nproxy *nproxy = splice->nproxy;
	struct uinet_sockaddr_in *sin_local, *sin_foreign;
	struct uinet_socket *outbound_socket = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_in_l2info l2i;
	char buf1[32], buf2[32];
	int optlen, optval;
	int error;
	
	uinet_sogetsockaddr(w->so, (struct uinet_sockaddr **)&sin_local);
	uinet_sogetpeeraddr(w->so, (struct uinet_sockaddr **)&sin_foreign);
	if (splice->verbose)
		printf("%s: splice %llu: inbound connection established (local=%s:%u foreign=%s:%u)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id,
		       uinet_inet_ntoa(sin_local->sin_addr, buf1, sizeof(buf1)), ntohs(sin_local->sin_port),
		       uinet_inet_ntoa(sin_foreign->sin_addr, buf2, sizeof(buf2)), ntohs(sin_foreign->sin_port));

	if ((nproxy->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE) &&
	    ((uinet_sogetserialno(w->so) % nproxy->cfg.copy_every) == 0)){
		if ((error =
		     uinet_sosetcopymode(w->so, UINET_IP_COPY_MODE_RX|UINET_IP_COPY_MODE_ON,
					 nproxy->cfg.copy_limit, nproxy->cfg.copy_uif)))
			printf("%s: splice %llu: Failed to set copy mode (%d)\n",
			       nproxy->cfg.name, (unsigned long long)splice->id, error);	
	}

	/* don't need this watcher anymore */
	ev_uinet_stop(loop, w);
	
	/* Create the outbound connection */
	error = uinet_socreate(nproxy->cfg.uinst, UINET_PF_INET, &outbound_socket, UINET_SOCK_STREAM, 0);
	if (error != 0) {
		printf("%s: splice %llu: outbound socket creation failed (%d)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id, error);
		goto fail;
	}

	if ((error = uinet_make_socket_promiscuous(outbound_socket, nproxy->outbound_if))) {
		printf("%s: splice %llu: failed to make outbound socket promiscuous (%d)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id, error);
		goto fail;
	}
	
	/*
	 * Socket needs to be non-blocking to work with the event system
	 */
	uinet_sosetnonblocking(outbound_socket, 1);

	optlen = sizeof(optval);
	optval = 1;
	error = uinet_sosetsockopt(outbound_socket, UINET_IPPROTO_TCP, UINET_TCP_NODELAY,
				   &optval, optlen);
	if (error != 0) {
		printf("%s: splice %llu: failed to set TCP_NODELAY on outbound socket (%d)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id, error);
		goto fail;
	}

	/* Bind to the foreign address of the inbound connection */
	error = uinet_sobind(outbound_socket, (struct uinet_sockaddr *)sin_foreign);
	if (error != 0) {
		printf("%s: splice %llu: outbound socket bind failed (%d)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id, error);
		goto fail;
	}

	/*
	 * Use the same MAC addrs and VLAN tag stack as the inbound
	 * connection, which requires swapping the local and foreign MAC
	 * addrs.
	 */
	error = uinet_getl2info(w->so, &l2i);
	if (error != 0) {
		printf("%s: splice %llu: unable to get l2info from inbound socket (%d)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id, error);
		goto fail;
	}

	error = uinet_setl2info2(outbound_socket,
				 l2i.inl2i_foreign_addr, l2i.inl2i_local_addr,
				 l2i.inl2i_flags, &l2i.inl2i_tagstack);
	if (error != 0) {
		printf("%s: splice %llu: unable to set l2info for outbound socket (%d)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id, error);
		goto fail;
	}

	soctx = ev_uinet_attach(outbound_socket);
	if (NULL == soctx) {
		printf("%s: splice %llu: failed to alloc libev context for outbound socket\n",
		       nproxy->cfg.name, (unsigned long long)splice->id);
		goto fail;
	}

	/* The connection target is the local address of the inbound connection */
	error = uinet_soconnect(outbound_socket, (struct uinet_sockaddr *)sin_local);
	if ((error != 0) && (error != UINET_EINPROGRESS)) {
		printf("%s: splice %llu: outbound socket connect failed (%d)\n",
		       nproxy->cfg.name, (unsigned long long)splice->id, error);
		goto fail;
	}
	
	uinet_free_sockaddr((struct uinet_sockaddr *)sin_local);
	uinet_free_sockaddr((struct uinet_sockaddr *)sin_foreign);

	ev_init(&splice->outbound.connected_watcher, nproxy_outbound_connected_cb);
	ev_uinet_set(&splice->outbound.connected_watcher, soctx, EV_WRITE);
	splice->outbound.connected_watcher.data = splice;
	ev_uinet_start(loop, &splice->outbound.connected_watcher);

	ev_init(&splice->outbound.writable_watcher, nproxy_writable_cb);
	ev_uinet_set(&splice->outbound.writable_watcher, soctx, EV_WRITE);
	splice->outbound.writable_watcher.data = &splice->outbound;
	/* will be started as necessary by the inbound copy watcher */
	
	ev_init(&splice->outbound.copy_watcher, nproxy_copy_cb);
	ev_uinet_set(&splice->outbound.copy_watcher, soctx, EV_READ);
	splice->outbound.copy_watcher.data = &splice->outbound;
	/* will be started when the outbound connection is established */
	
	return;

 fail:
	uinet_free_sockaddr((struct uinet_sockaddr *)sin_local);
	uinet_free_sockaddr((struct uinet_sockaddr *)sin_foreign);
	if (soctx) ev_uinet_detach(soctx);
	if (outbound_socket) uinet_soclose(outbound_socket);
	free(splice);
}


static void
nproxy_accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct uinet_demo_nproxy *nproxy = w->data;
	struct uinet_socket *newso = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct nproxy_splice *splice = NULL;
	int error;

	if (0 != (error = uinet_soaccept(w->so, NULL, &newso))) {
		printf("%s: Accept failed (%d)\n", nproxy->cfg.name, error);
	} else {
		if (nproxy->cfg.verbose)
			printf("%s: Accept succeeded\n", nproxy->cfg.name);
		
		soctx = ev_uinet_attach(newso);
		if (NULL == soctx) {
			printf("%s: Failed to alloc libev context for new splice\n",
			       nproxy->cfg.name);
			goto fail;
		}

		splice = malloc(sizeof(*splice));
		if (NULL == splice) {
			printf("%s: Failed to alloc new splice context\n",
			       nproxy->cfg.name);
			goto fail;
		}
		splice->nproxy = nproxy;
		splice->id = nproxy->next_id++;
		splice->verbose = nproxy->cfg.verbose;
		splice->inbound.name = "inbound";
		splice->inbound.splice = splice;
		splice->inbound.other_side = &splice->outbound;
		splice->outbound.name = "outbound";
		splice->outbound.splice = splice;
		splice->outbound.other_side = &splice->inbound;
		
		ev_init(&splice->inbound.connected_watcher, nproxy_inbound_connected_cb);
		ev_uinet_set(&splice->inbound.connected_watcher, soctx, EV_WRITE);
		splice->inbound.connected_watcher.data = splice;
		ev_uinet_start(loop, &splice->inbound.connected_watcher);

		ev_init(&splice->inbound.writable_watcher, nproxy_writable_cb);
		ev_uinet_set(&splice->inbound.writable_watcher, soctx, EV_WRITE);
		splice->inbound.writable_watcher.data = &splice->inbound;
		/* will be started as necessary by the outbound copy watcher */

		ev_init(&splice->inbound.copy_watcher, nproxy_copy_cb);
		ev_uinet_set(&splice->inbound.copy_watcher, soctx, EV_READ);
		splice->inbound.copy_watcher.data = &splice->inbound;
		/* will be started when the outbound connection is established */
	}

	return;

fail:
	if (splice) free(splice);
	if (soctx) ev_uinet_detach(soctx);
	if (newso) uinet_soclose(newso);
}


static void
nproxy_print_usage(void)
{
	printf("  --listen <ip:port>      Specify the listen address and port (default is 0.0.0.0:0 - promiscuous listen on all ip:port pairs)\n");
	printf("  --outbound-if <ifname>  Name of the interface to use for outbound connections\n");
}


static int
nproxy_init_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_nproxy *nproxy = (struct uinet_demo_nproxy *)cfg;

	snprintf(nproxy->listen_addr, sizeof(nproxy->listen_addr), "%s", "0.0.0.0");
	nproxy->next_id = 1;
	nproxy->promisc = 1;

	return (0);
}


static int
nproxy_process_args(struct uinet_demo_config *cfg, int argc, char **argv)
{
	struct uinet_demo_nproxy *nproxy = (struct uinet_demo_nproxy *)cfg;
	int opt;

	while ((opt = getopt_long(argc, argv, ":" UINET_DEMO_BASE_OPT_STRING,
				 nproxy_long_options, NULL)) != -1) {
		switch (opt) {
		case NPROXY_OPT_LISTEN:
			if (0 != uinet_demo_break_ipaddr_port_string(optarg, nproxy->listen_addr,
								     sizeof(nproxy->listen_addr),
								     &nproxy->listen_port)) {
				printf("%s: Invalid listen address and port specification %s\n",
				       nproxy->cfg.name, optarg);
				return (1);
			}
			break;
		case NPROXY_OPT_OUTBOUND_IF:
			nproxy->outbound_if_name = optarg;
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
nproxy_print_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_nproxy *nproxy = (struct uinet_demo_nproxy *)cfg;

	printf("listen=%s:%u promisc=%s outbound-if=%s",
	       nproxy->listen_addr, nproxy->listen_port, nproxy->promisc ? "yes" : "no",
	       nproxy->outbound_if_name);
}


static int
nproxy_start(struct uinet_demo_config *cfg, uinet_instance_t uinst, struct ev_loop *loop)
{
	struct uinet_demo_nproxy *nproxy = (struct uinet_demo_nproxy *)cfg;
	struct uinet_socket *listen_socket = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_in_addr addr;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;

	if (uinet_inet_pton(UINET_AF_INET, nproxy->listen_addr, &addr) <= 0) {
		printf("%s: Malformed address %s\n", nproxy->cfg.name, nproxy->listen_addr);
		error = UINET_EINVAL;
		goto fail;
	}

	nproxy->outbound_if = uinet_iffind_byname(nproxy->cfg.uinst, nproxy->outbound_if_name);
	if (nproxy->outbound_if == NULL) {
		printf("%s: Unknown outbound interface %s\n", nproxy->cfg.name,
		       nproxy->outbound_if_name);
		error = UINET_EINVAL;
		goto fail;
	}
	
	error = uinet_socreate(nproxy->cfg.uinst, UINET_PF_INET, &listen_socket, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("%s: Listen socket creation failed (%d)\n", nproxy->cfg.name, error);
		goto fail;
	}

	soctx = ev_uinet_attach(listen_socket);
	if (NULL == soctx) {
		printf("%s: Failed to alloc libev socket context\n", nproxy->cfg.name);
		error = UINET_ENOMEM;
		goto fail;
	}

	if (nproxy->promisc) {
		if ((error = uinet_make_socket_promiscuous(listen_socket, NULL))) {
			printf("%s: Failed to make listen socket promiscuous (%d)\n",
			       nproxy->cfg.name, error);
			goto fail;
		}
	}

	if (cfg->copy_mode) {
		if ((error = uinet_sosetcopymode(listen_socket, cfg->copy_mode,
						 cfg->copy_limit, cfg->copy_uif))) {
			printf("%s: Failed to set copy mode (%d)\n",
			       nproxy->cfg.name, error);
			goto fail;
		}
	}
	
	/*
	 * Socket needs to be non-blocking to work with the event system
	 */
	uinet_sosetnonblocking(listen_socket, 1);

	/* Set NODELAY on the listen socket so it will be set on all
	 * accepted sockets via inheritance.
	 */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_NODELAY,
					&optval, optlen))) {
		printf("%s: Failed to set TCP_NODELAY (%d)\n", nproxy->cfg.name, error);
		goto fail;
	}

	/* Listen on all VLANs */
	if ((error = uinet_setl2info2(listen_socket, NULL, NULL,
				      UINET_INL2I_TAG_ANY, NULL))) {
		printf("%s: Listen socket L2 info set failed (%d)\n",
		       nproxy->cfg.name, error);
		goto fail;
	}

	nproxy->listen_socket = listen_socket;

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = addr;
	sin.sin_port = htons(nproxy->listen_port);
	error = uinet_sobind(listen_socket, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("%s: Bind to %s:%u failed\n", nproxy->cfg.name,
		       nproxy->listen_addr, nproxy->listen_port);
		goto fail;
	}
	
	error = uinet_solisten(nproxy->listen_socket, -1);
	if (0 != error) {
		printf("%s: Listen on %s:%u failed\n", nproxy->cfg.name,
		       nproxy->listen_addr, nproxy->listen_port);
		goto fail;
	}

	if (nproxy->cfg.verbose)
		printf("%s: Listening on %s:%u\n", nproxy->cfg.name,
		       nproxy->listen_addr, nproxy->listen_port);

	/*
	 * Set up a read watcher to accept new connections
	 */
	ev_init(&nproxy->listen_watcher, nproxy_accept_cb);
	ev_uinet_set(&nproxy->listen_watcher, soctx, EV_READ);
	nproxy->listen_watcher.data = nproxy;
	ev_uinet_start(nproxy->cfg.loop, &nproxy->listen_watcher);

	return (0);

fail:
	if (soctx) ev_uinet_detach(soctx);
	if (listen_socket) uinet_soclose(listen_socket);

	return (error);
}




