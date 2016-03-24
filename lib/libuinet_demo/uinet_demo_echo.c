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

#include <netinet/in.h>

#include "uinet_demo_echo.h"
#include "uinet_demo_internal.h"

static void echo_print_usage(void);
static int echo_init_cfg(struct uinet_demo_config *cfg);
static int echo_process_args(struct uinet_demo_config *cfg, int argc, char **argv);
static void echo_print_cfg(struct uinet_demo_config *cfg);
static int echo_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
		      struct ev_loop *loop);

struct uinet_demo_info echo_info = {
	.which = UINET_DEMO_ECHO,
	.name = "echo server",
	.cfg_size = sizeof(struct uinet_demo_echo),
	.print_usage = echo_print_usage,
	.init_cfg = echo_init_cfg,
	.process_args = echo_process_args,
	.print_cfg = echo_print_cfg,
	.start = echo_start
};


enum echo_option_id {
	ECHO_OPT_LISTEN = 1000,
	ECHO_OPT_SINK
};

static const struct option echo_long_options[] = {
	UINET_DEMO_BASE_LONG_OPTS,
	{ "listen",	required_argument,	NULL,	ECHO_OPT_LISTEN },
	{ "sink",	no_argument,		NULL,	ECHO_OPT_SINK },
	{ 0, 0, 0, 0 }
};



struct echo_connection {
	struct uinet_demo_echo *echo;
	ev_uinet watcher;
	ev_uinet connected_watcher;
	uint64_t id;
	int verbose;
};

static inline int imin(int a, int b) { return (a < b ? a : b); }

static void
echo_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct echo_connection *conn = w->data;
	struct uinet_demo_echo *echo = conn->echo;
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
		if (conn->verbose)
			printf("%s: connection %llu: can't read, closing\n",
			       echo->cfg.name, (unsigned long long)conn->id);
		goto err;
	} else {
		max_write = echo->sink ? max_read : uinet_sowritable(w->so, 0);
		if (-1 == max_write) {
			if (conn->verbose)
				printf("%s: connection %llu: can't write, closing\n",
				       echo->cfg.name, (unsigned long long)conn->id);
			goto err;
		} else {
			read_size = imin(imin(max_read, max_write), BUFFER_SIZE);

			uio.uio_iov = &iov;
			iov.iov_base = buffer;
			iov.iov_len = read_size;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = read_size;
	
			error = uinet_soreceive(w->so, NULL, &uio, NULL);
			if (0 != error) {
				printf("%s: connection %llu: read error (%d), closing\n",
				       echo->cfg.name, (unsigned long long)conn->id, error);
				goto err;
			}

			assert(uio.uio_resid == 0);

			if (!echo->sink) {
				uio.uio_iov = &iov;
				iov.iov_base = buffer;
				iov.iov_len = read_size;
				uio.uio_iovcnt = 1;
				uio.uio_offset = 0;
				uio.uio_resid = read_size;
				error = uinet_sosend(w->so, NULL, &uio, 0);
				if (0 != error) {
					printf("%s: connection %llu: write error (%d), closing\n",
					       echo->cfg.name, (unsigned long long)conn->id, error);
					goto err;
				}
			}

			if (max_write < max_read) {
				/* limited by write space, so change to a
				 * write watch on the socket, if we aren't
				 * already one.
				 */
				if (w->events & EV_READ) {
					ev_uinet_stop(loop, w);
					w->events = EV_WRITE;
					ev_uinet_start(loop, w);
				}
				/* else, continue as a write watch */
			} else if (!(w->events & EV_READ)) {
				/* write space wasn't a limitation this
				 * time, so switch back to waiting on
				 * EV_READ
				 */
				ev_uinet_stop(loop, w);
				w->events = EV_READ;
				ev_uinet_start(loop, w);
			}
			/* else, continue as a read watcher */
		}
	}

	return;

err:
	ev_uinet_stop(loop, w);
	ev_uinet_detach(w->ctx);
	uinet_soclose(w->so);
	free(conn);
}


static void
echo_connected_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct echo_connection *conn = w->data;
	struct uinet_demo_echo *echo = conn->echo;
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];
	int error;
	
	if (conn->verbose) {
		uinet_sogetsockaddr(w->so, (struct uinet_sockaddr **)&sin1);
		uinet_sogetpeeraddr(w->so, (struct uinet_sockaddr **)&sin2);
		printf("%s: connection %llu: established (local=%s:%u foreign=%s:%u)\n",
		       echo->cfg.name, (unsigned long long)conn->id,
		       uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
		       uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
		uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
		uinet_free_sockaddr((struct uinet_sockaddr *)sin2);
	}

	if ((echo->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE) &&
	    ((uinet_sogetserialno(w->so) % echo->cfg.copy_every) == 0)){
		if ((error =
		     uinet_sosetcopymode(w->so, UINET_IP_COPY_MODE_RX|UINET_IP_COPY_MODE_ON,
					 echo->cfg.copy_limit, echo->cfg.copy_uif)))
			printf("%s: Failed to set copy mode (%d)\n",
			       echo->cfg.name, error);	
	}
	ev_uinet_stop(loop, w);
}


static void
echo_accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct uinet_demo_echo *echo = w->data;
	struct uinet_socket *newso = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct echo_connection *conn = NULL;
	int error;

	if (0 != (error = uinet_soaccept(w->so, NULL, &newso))) {
		printf("%s: Accept failed (%d)\n", echo->cfg.name, error);
	} else {
		if (echo->cfg.verbose)
			printf("%s: Accept succeeded\n", echo->cfg.name);
		
		soctx = ev_uinet_attach(newso);
		if (NULL == soctx) {
			printf("%s: Failed to alloc libev context for new connection\n",
			       echo->cfg.name);
			goto fail;
		}

		conn = malloc(sizeof(*conn));
		if (NULL == conn) {
			printf("%s: Failed to alloc new connection context\n",
			       echo->cfg.name);
			goto fail;
		}
		conn->echo = echo;
		conn->id = echo->next_id++;
		conn->verbose = echo->cfg.verbose;

		ev_init(&conn->connected_watcher, echo_connected_cb);
		ev_uinet_set(&conn->connected_watcher, soctx, EV_WRITE);
		conn->connected_watcher.data = conn;
		if (conn->verbose || (echo->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE))
			ev_uinet_start(loop, &conn->connected_watcher);

		ev_init(&conn->watcher, echo_cb);
		ev_uinet_set(&conn->watcher, soctx, EV_READ);
		conn->watcher.data = conn;
		ev_uinet_start(loop, &conn->watcher);
	}

	return;

fail:
	if (conn) free(conn);
	if (soctx) ev_uinet_detach(soctx);
	if (newso) uinet_soclose(newso);
}


static void
echo_print_usage(void)
{
	printf("  --listen <ip:port>      Specify the listen address and port (default is 0.0.0.0:0 - promiscuous listen on all ip:port pairs)\n");
	printf("  --sink                  Discard received data without echoing\n");
}


static int
echo_init_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_echo *echo = (struct uinet_demo_echo *)cfg;

	snprintf(echo->listen_addr, sizeof(echo->listen_addr), "%s", "0.0.0.0");
	echo->next_id = 1;
	echo->promisc = 1;

	return (0);
}


static int
echo_process_args(struct uinet_demo_config *cfg, int argc, char **argv)
{
	struct uinet_demo_echo *echo = (struct uinet_demo_echo *)cfg;
	int opt;

	while ((opt = getopt_long(argc, argv, ":" UINET_DEMO_BASE_OPT_STRING,
				 echo_long_options, NULL)) != -1) {
		switch (opt) {
		case ECHO_OPT_LISTEN:
			if (0 != uinet_demo_break_ipaddr_port_string(optarg, echo->listen_addr,
								     sizeof(echo->listen_addr),
								     &echo->listen_port)) {
				printf("%s: Invalid listen address and port specification %s\n",
				       echo->cfg.name, optarg);
				return (1);
			}
			break;
		case ECHO_OPT_SINK:
			echo->sink = 1;
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
echo_print_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_echo *echo = (struct uinet_demo_echo *)cfg;

	printf("listen=%s:%u promisc=%s", echo->listen_addr, echo->listen_port, echo->promisc ? "yes" : "no");
}


static int
echo_start(struct uinet_demo_config *cfg, uinet_instance_t uinst, struct ev_loop *loop)
{
	struct uinet_demo_echo *echo = (struct uinet_demo_echo *)cfg;
	struct uinet_socket *listen_socket = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_in_addr addr;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;

	if (uinet_inet_pton(UINET_AF_INET, echo->listen_addr, &addr) <= 0) {
		printf("%s: Malformed address %s\n", echo->cfg.name, echo->listen_addr);
		error = UINET_EINVAL;
		goto fail;
	}

	error = uinet_socreate(echo->cfg.uinst, UINET_PF_INET, &listen_socket, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("%s: Listen socket creation failed (%d)\n", echo->cfg.name, error);
		goto fail;
	}

	soctx = ev_uinet_attach(listen_socket);
	if (NULL == soctx) {
		printf("%s: Failed to alloc libev socket context\n", echo->cfg.name);
		error = UINET_ENOMEM;
		goto fail;
	}

	if (echo->promisc) {
		if ((error = uinet_make_socket_promiscuous(listen_socket, NULL))) {
			printf("%s: Failed to make listen socket promiscuous (%d)\n",
			       echo->cfg.name, error);
			goto fail;
		}
	}

	if (cfg->copy_mode) {
		if ((error = uinet_sosetcopymode(listen_socket, cfg->copy_mode,
						 cfg->copy_limit, cfg->copy_uif))) {
			printf("%s: Failed to set copy mode (%d)\n",
			       echo->cfg.name, error);
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
		printf("%s: Failed to set TCP_NODELAY (%d)\n", echo->cfg.name, error);
		goto fail;
	}

	/* Listen on all VLANs */
	if ((error = uinet_setl2info2(listen_socket, NULL, NULL,
				      UINET_INL2I_TAG_ANY, NULL))) {
		printf("%s: Listen socket L2 info set failed (%d)\n",
		       echo->cfg.name, error);
		goto fail;
	}

	echo->listen_socket = listen_socket;

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = addr;
	sin.sin_port = htons(echo->listen_port);
	error = uinet_sobind(listen_socket, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("%s: Bind to %s:%u failed\n", echo->cfg.name,
		       echo->listen_addr, echo->listen_port);
		goto fail;
	}
	
	error = uinet_solisten(echo->listen_socket, -1);
	if (0 != error) {
		printf("%s: Listen on %s:%u failed\n", echo->cfg.name,
		       echo->listen_addr, echo->listen_port);
		goto fail;
	}

	if (echo->cfg.verbose)
		printf("%s: Listening on %s:%u\n", echo->cfg.name,
		       echo->listen_addr, echo->listen_port);

	/*
	 * Set up a read watcher to accept new connections
	 */
	ev_init(&echo->listen_watcher, echo_accept_cb);
	ev_uinet_set(&echo->listen_watcher, soctx, EV_READ);
	echo->listen_watcher.data = echo;
	ev_uinet_start(echo->cfg.loop, &echo->listen_watcher);

	return (0);

fail:
	if (soctx) ev_uinet_detach(soctx);
	if (listen_socket) uinet_soclose(listen_socket);

	return (error);
}




