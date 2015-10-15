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

#include "uinet_demo_passive.h"
#include "uinet_demo_internal.h"


static void passive_print_usage(void);
static int passive_init_cfg(struct uinet_demo_config *cfg);
static int passive_process_args(struct uinet_demo_config *cfg, int argc, char **argv);
static void passive_print_cfg(struct uinet_demo_config *cfg);
static int passive_start(struct uinet_demo_config *cfg, uinet_instance_t uinst,
			 struct ev_loop *loop);

struct uinet_demo_info passive_info = {
	.which = UINET_DEMO_PASSIVE,
	.name = "passive server",
	.cfg_size = sizeof(struct uinet_demo_passive),
	.print_usage = passive_print_usage,
	.init_cfg = passive_init_cfg,
	.process_args = passive_process_args,
	.print_cfg = passive_print_cfg,
	.start = passive_start
};


enum passive_option_id {
	PASSIVE_OPT_LISTEN = 1000
};

static const struct option passive_long_options[] = {
	UINET_DEMO_BASE_LONG_OPTS,
	{ "listen",	required_argument,	NULL, PASSIVE_OPT_LISTEN },
	{ 0, 0, 0, 0 }
};


struct passive_connection {
	char label[64];
	ev_uinet watcher;
	ev_uinet connected_watcher;
	struct uinet_demo_passive *server;
	uint64_t bytes_read;
	int verbose;
	struct passive_connection *peer;
};



static inline int imin(int a, int b) { return (a < b ? a : b); }


static void
destroy_conn(struct passive_connection *conn)
{
	ev_uinet *w  = &conn->watcher;

	ev_uinet_stop(conn->server->cfg.loop, &conn->connected_watcher);
	ev_uinet_stop(conn->server->cfg.loop, w);
	ev_uinet_detach(w->ctx);
	uinet_soclose(ev_uinet_so(w->ctx));
	conn->server->num_sockets--;
	free(conn);
}


static void
passive_receive_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct passive_connection *conn = w->data;
	struct uinet_demo_passive *passive = conn->server;
#define BUFFER_SIZE (64*1024)
	uint8_t buffer[BUFFER_SIZE];
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int max_read;
	int read_size;
	int bytes_read;
	int error;
	int flags;
	int i;
	int print_threshold = 10;
	int printable;
	int skipped;

	max_read = uinet_soreadable(w->so, 0);
	if (max_read <= 0) {
		/* the watcher should never be invoked if there is no error and there no bytes to be read */
		assert(max_read != 0);
		if (conn->verbose)
			printf("%s: %s: can't read, closing\n", passive->cfg.name, conn->label);
		goto err;
	} else {
		read_size = imin(max_read, BUFFER_SIZE - 1);

		uio.uio_iov = &iov;
		iov.iov_base = buffer;
		iov.iov_len = read_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = read_size;
		flags = UINET_MSG_HOLE_BREAK;

		error = uinet_soreceive(w->so, NULL, &uio, &flags);
		if (0 != error) {
			printf("%s: %s: read error (%d), closing\n", passive->cfg.name, conn->label, error);
			goto err;
		}

		bytes_read = read_size - uio.uio_resid;

		conn->bytes_read += bytes_read;

		if (conn->verbose > 2)
			printf("========================================================================================\n");

		if (conn->verbose > 1)
			printf("%s: To %s (%u bytes, %llu total, %s)\n", passive->cfg.name, conn->label, bytes_read,
			       (unsigned long long)conn->bytes_read, flags & UINET_MSG_HOLE_BREAK ? "HOLE" : "normal");
		
		if (conn->verbose > 2) {
			buffer[bytes_read] = '\0';
			printf("----------------------------------------------------------------------------------------\n");
			skipped = 0;
			printable = 0;
			for (i = 0; i < bytes_read; i++) {
				if ((buffer[i] >= 0x20 && buffer[i] <= 0x7e) || buffer[i] == 0x0a || buffer[i] == 0x0d || buffer[i] == 0x09) {
					printable++;
				} else {
					/*
					 * Print on printable-to-unprintable
					 * transition if enough consecutive
					 * printable chars were seen.
					 */
					if (printable >= print_threshold) {
						if (skipped) {
							printf("<%u>", skipped);
						}
						buffer[i] = '\0';
						printf("%s", &buffer[i - printable]);
					} else {
						skipped += printable;
					}
					printable = 0;
					skipped++;
				}
			}
			if (skipped) {
				printf("<%u>", skipped);
			}
			buffer[i] = '\0';
			printf("%s", &buffer[i - printable]);
			printf("\n");
			printf("========================================================================================\n");
		}
	}

	return;

err:
	destroy_conn(conn);
}


static void
passive_connected_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct passive_connection *conn = w->data;
	struct uinet_demo_passive *passive = conn->server;
	int error;

	if (passive->cfg.verbose)
		printf("%s: %s: connection established\n", passive->cfg.name, conn->label);

	if ((passive->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE) &&
	    ((uinet_sogetserialno(w->so) % passive->cfg.copy_every) == 0)){
		if ((error =
		     uinet_sosetcopymode(w->so, UINET_IP_COPY_MODE_RX|UINET_IP_COPY_MODE_ON,
					 passive->cfg.copy_limit, passive->cfg.copy_uif)))
			printf("%s: Failed to set copy mode (%d)\n",
			       passive->cfg.name, error);
	}
	ev_uinet_stop(loop, w);
}


static struct passive_connection *
create_conn(struct uinet_demo_passive *passive, struct uinet_socket *so, int server)
{
	struct passive_connection *conn = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];

	conn = calloc(1, sizeof(*conn));
	if (NULL == conn) {
		printf("%s: Failed to alloc connection context for new connection\n",
			passive->cfg.name);
		goto fail;
	}

	soctx = ev_uinet_attach(so);
	if (NULL == soctx) {
		printf("%s: Failed to alloc libev context for new connection socket\n",
			passive->cfg.name);
		goto fail;
	}

	uinet_sogetsockaddr(so, (struct uinet_sockaddr **)&sin1);
	uinet_sogetpeeraddr(so, (struct uinet_sockaddr **)&sin2);
	snprintf(conn->label, sizeof(conn->label), "%s (%s:%u <- %s:%u)",
		 server ? "SERVER" : "CLIENT",
		 uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
		 uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
	uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
	uinet_free_sockaddr((struct uinet_sockaddr *)sin2);

	conn->verbose = passive->cfg.verbose;
	conn->server = passive;

	ev_init(&conn->watcher, passive_receive_cb);
	ev_uinet_set(&conn->watcher, soctx, EV_READ);
	conn->watcher.data = conn;

	ev_init(&conn->connected_watcher, passive_connected_cb);
	ev_uinet_set(&conn->connected_watcher, soctx, EV_WRITE);
	conn->connected_watcher.data = conn;

	return (conn);

fail:
	if (conn) free(conn);
	if (soctx) ev_uinet_detach(soctx);

	return (NULL);
}


static void
passive_accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct uinet_demo_passive *passive = w->data;
	struct uinet_socket *newso = NULL;
	struct uinet_socket *newpeerso = NULL;
	struct passive_connection *conn = NULL;
	struct passive_connection *peerconn = NULL;
	int error;
	unsigned int batch_limit = 32;
	unsigned int processed = 0;

	while ((processed < batch_limit) &&
	       (UINET_EWOULDBLOCK != (error = uinet_soaccept(w->so, NULL, &newso)))) {
		processed++;

		if (0 == error) {
			newpeerso = NULL;
			conn = NULL;
			peerconn = NULL;

			if (passive->cfg.verbose)
				printf("%s: Accept succeeded\n", passive->cfg.name);

			conn = create_conn(passive, newso, 1);
			if (NULL == conn) {
				printf("%s: Failed to alloc new connection context\n",
				       passive->cfg.name);
				goto fail;
			}

			newpeerso = uinet_sogetpassivepeer(newso);
			peerconn = create_conn(passive, newpeerso, 0);
			if (NULL == peerconn) {
				printf("%s: Failed to alloc new peer connection context\n",
				       passive->cfg.name);
				goto fail;
			}

			conn->peer = peerconn;
			peerconn->peer = conn;
			
			ev_uinet_start(loop, &conn->watcher);
			ev_uinet_start(loop, &peerconn->watcher);

			if (conn->verbose || (passive->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE))
				ev_uinet_start(loop, &conn->connected_watcher);

			if (peerconn->verbose || (passive->cfg.copy_mode & UINET_IP_COPY_MODE_MAYBE))
				ev_uinet_start(loop, &peerconn->connected_watcher);

			passive->num_sockets += 2;

			continue;
		fail:
			if (conn) destroy_conn(conn);
			if (newso) uinet_soclose(newso);
			if (newpeerso) uinet_soclose(newpeerso);
		}
	}

	if (processed > passive->max_accept_batch)
		passive->max_accept_batch = processed;
}


static void
passive_print_usage(void)
{
	printf("  --listen <ip:port>      Specify the listen address and port (default is 0.0.0.0:0 - promiscuous listen on all ip:port pairs)\n");
}


static int
passive_init_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_passive *passive = (struct uinet_demo_passive *)cfg;

	snprintf(passive->listen_addr, sizeof(passive->listen_addr), "%s", "0.0.0.0");
	passive->promisc = 1;

	return (0);
}


static int
passive_process_args(struct uinet_demo_config *cfg, int argc, char **argv)
{
	struct uinet_demo_passive *passive = (struct uinet_demo_passive *)cfg;
	int opt;

	while ((opt = getopt_long(argc, argv, ":" UINET_DEMO_BASE_OPT_STRING,
				 passive_long_options, NULL)) != -1) {
		switch (opt) {
		case PASSIVE_OPT_LISTEN:
			if (0 != uinet_demo_break_ipaddr_port_string(optarg, passive->listen_addr,
								     sizeof(passive->listen_addr),
								     &passive->listen_port)) {
				printf("%s: Invalid listen address and port specification %s\n",
				       passive->cfg.name, optarg);
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
passive_print_cfg(struct uinet_demo_config *cfg)
{
	struct uinet_demo_passive *passive = (struct uinet_demo_passive *)cfg;

	printf("listen=%s:%u", passive->listen_addr, passive->listen_port);
}


static int
passive_start(struct uinet_demo_config *cfg, uinet_instance_t uinst, struct ev_loop *loop)
{
	struct uinet_demo_passive *passive = (struct uinet_demo_passive *)cfg;
	struct uinet_socket *listen_socket = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_in_addr addr;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;

	if (uinet_inet_pton(UINET_AF_INET, passive->listen_addr, &addr) <= 0) {
		printf("%s: Malformed address %s\n", passive->cfg.name, passive->listen_addr);
		error = UINET_EINVAL;
		goto fail;
	}

	error = uinet_socreate(passive->cfg.uinst, UINET_PF_INET, &listen_socket, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("%s: Listen socket creation failed (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	soctx = ev_uinet_attach(listen_socket);
	if (NULL == soctx) {
		printf("%s: Failed to alloc libev socket context\n", passive->cfg.name);
		error = UINET_ENOMEM;
		goto fail;
	}
	
	if ((error = uinet_make_socket_passive(listen_socket))) {
		printf("%s: Failed to make listen socket passive (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	if (passive->promisc) {
		if ((error = uinet_make_socket_promiscuous(listen_socket, NULL))) {
			printf("%s: Failed to make listen socket promiscuous (%d)\n", passive->cfg.name, error);
			goto fail;
		}
	}

	/* 
	 * The following settings will be inherited by all sockets created
	 * by this listen socket.
	 */

	/*
	 * Need to be non-blocking to work with the event system.
	 */
	uinet_sosetnonblocking(listen_socket, 1);

	/* Wait 5 seconds for connections to complete */
	optlen = sizeof(optval);
	optval = 5;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPINIT, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPINIT (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Begin counting down to close after 10 seconds of idle */
	optlen = sizeof(optval);
	optval = 10;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPIDLE, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPIDLE (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Count down to close once per second */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPINTVL, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPINTVL (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Close after idle for 3 counts */
	optlen = sizeof(optval);
	optval = 3;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_KEEPCNT, &optval, optlen))) {
		printf("%s: Failed to set TCP_KEEPCNT (%d)\n", passive->cfg.name, error);
		goto fail;
	}

	/* Wait 100 milliseconds for missing TCP segments */
	optlen = sizeof(optval);
	optval = 100;
	if ((error = uinet_sosetsockopt(listen_socket, UINET_IPPROTO_TCP, UINET_TCP_REASSDL, &optval, optlen))) {
		printf("%s: Failed to set TCP_REASSDL (%d)\n", passive->cfg.name, error);
		goto fail;
	}


	passive->listen_socket = listen_socket;

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = addr;
	sin.sin_port = htons(passive->listen_port);
	error = uinet_sobind(listen_socket, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("%s: Bind to %s:%u failed\n", passive->cfg.name,
		       passive->listen_addr, passive->listen_port);
		goto fail;
	}
	
	error = uinet_solisten(passive->listen_socket, -1);
	if (0 != error) {
		printf("%s: Listen on %s:%u failed\n", passive->cfg.name,
		       passive->listen_addr, passive->listen_port);
		goto fail;
	}

	if (passive->cfg.verbose)
		printf("%s: Listening on %s:%u\n", passive->cfg.name,
		       passive->listen_addr, passive->listen_port);

	ev_init(&passive->listen_watcher, passive_accept_cb);
	ev_uinet_set(&passive->listen_watcher, soctx, EV_READ);
	passive->listen_watcher.data = passive;
	ev_uinet_start(loop, &passive->listen_watcher);

	return (0);

fail:
	if (soctx) ev_uinet_detach(soctx);
	if (listen_socket) uinet_soclose(listen_socket);

	return (error);
}
