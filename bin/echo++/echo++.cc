/*
 * Copyright (c) 2014 Patrick Kelsey. All rights reserved.
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
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#include "uinet_api.h"

#define EV_STANDALONE 1
#define EV_UINET_ENABLE 1
#include <ev++.h>



class EchoServer {
private:
	ev::dynamic_loop &loop_;
	unsigned int cdom_;
	struct uinet_socket *listener_;
	struct ev_uinet_ctx *soctx_;
	ev::uinet watcher_;
	int verbose_;

public:
	EchoServer(ev::dynamic_loop &loop, struct server_config *cfg);
	~EchoServer();

	void accept(ev::uinet &w, int revents);
};


class EchoResponder {
private:
	ev::dynamic_loop &loop_;
	struct uinet_socket *so_;
	struct ev_uinet_ctx *soctx_;
	ev::uinet watcher_;
	bool is_running_;

public:
	EchoResponder(ev::dynamic_loop &loop, struct uinet_socket *so);
	~EchoResponder();

	void respond(ev::uinet &w, int revents);

	bool is_running() const { return is_running_; }
};


struct interface_config {
	char *ifname;
	unsigned int cdom;
	int thread_create_result;
	pthread_t thread;
	ev::dynamic_loop *loop;
};

struct server_config {
	char *listen_addr;
	int listen_port;
	struct interface_config *interface;
	int verbose;
	EchoServer *echo;
};


static __inline int imin(int a, int b) { return (a < b ? a : b); }


EchoResponder::EchoResponder(ev::dynamic_loop &loop, struct uinet_socket *so)
	: loop_(loop), 
	  so_(so),
	  soctx_(NULL),
	  watcher_(loop),
	  is_running_(false)
{
	soctx_ = ev_uinet_attach(so_);
	if (NULL == soctx_) {
		printf("Failed to alloc libev context for new connection socket\n");
	} else {
		watcher_.set<EchoResponder, &EchoResponder::respond>(this);
		watcher_.start(soctx_, EV_READ);

		is_running_ = true;
	}
}


EchoResponder::~EchoResponder()
{
	if (watcher_.is_active())
		watcher_.stop();

	if (soctx_)
		ev_uinet_detach(soctx_);

	if (so_)
		uinet_soclose(so_);
}


void
EchoResponder::respond(ev::uinet &w, int revents)
{
#define BUFFER_SIZE (64*1024)
	char buffer[BUFFER_SIZE];
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int max_read;
	int max_write;
	int read_size;
	int error;

	max_read = uinet_soreadable(w.so, 0);
	if (max_read <= 0) {
		/* the watcher should never be invoked if there is no error and there no bytes to be read */
		assert(max_read != 0);
		printf("can't read, closing\n");
		goto err;
	} else {
		max_write = uinet_sowritable(w.so, 0);
		if (-1 == max_write) {
			printf("can't write, closing\n");
			goto err;
		} else {
			read_size = imin(imin(max_read, max_write), BUFFER_SIZE);

			uio.uio_iov = &iov;
			iov.iov_base = buffer;
			iov.iov_len = read_size;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = read_size;
	
			error = uinet_soreceive(w.so, NULL, &uio, NULL);
			if (0 != error) {
				printf("read error (%d), closing\n", error);
				goto err;
			}

			assert(uio.uio_resid == 0);

			uio.uio_iov = &iov;
			iov.iov_base = buffer;
			iov.iov_len = read_size;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = read_size;
			error = uinet_sosend(w.so, NULL, &uio, 0);
			if (0 != error) {
				printf("write error (%d), closing\n", error);
				goto err;
			}

			if (max_write < max_read) {
				/* limited by write space, so change to a
				 * write watch on the socket, if we aren't
				 * already one.
				 */
				if (w.events & EV_READ) {
					w.set(EV_WRITE);
				}
				/* else, continue as a write watch */
			} else if (!(w.events & EV_READ)) {
				/* write space wasn't a limitation this
				 * time, so switch back to waiting on
				 * EV_READ
				 */
				w.set(EV_READ);
			}
			/* else, continue as a read watcher */
		}
	}

	return;

err:
	w.stop();
	uinet_soclose(w.so);
	so_ = NULL;
}


EchoServer::EchoServer(ev::dynamic_loop &loop, struct server_config *cfg)
	: loop_(loop),
	  listener_(NULL),
	  cdom_(cfg->interface->cdom),
	  soctx_(NULL),
	  watcher_(loop),
	  verbose_(cfg->verbose)
{

	struct uinet_in_addr addr;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;

	if (uinet_inet_pton(UINET_AF_INET, cfg->listen_addr, &addr) <= 0) {
		printf("Malformed address %s\n", cfg->listen_addr);
		goto done;
	}

	error = uinet_socreate(UINET_PF_INET, &listener_, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("Listen socket creation failed (%d)\n", error);
		goto done;
	}

	soctx_ = ev_uinet_attach(listener_);
	if (NULL == soctx_) {
		printf("Failed to alloc libev socket context\n");
		goto done;
	}
	
	if ((error = uinet_make_socket_promiscuous(listener_, cdom_))) {
		printf("Failed to make listen socket promiscuous (%d)\n", error);
		goto done;
	}

	uinet_sosetnonblocking(listener_, 1);

	/* Set NODELAY on the listen socket so it will be set on all
	 * accepted sockets via inheritance.
	 */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listener_, UINET_IPPROTO_TCP, UINET_TCP_NODELAY, &optval, optlen)))
		goto done;


	/* Listen on all VLANs */
	if ((error = uinet_setl2info2(listener_, NULL, NULL, UINET_INL2I_TAG_ANY, NULL))) {
		printf("Listen socket L2 info set failed (%d)\n", error);
		goto done;
	}

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = addr;
	sin.sin_port = htons(cfg->listen_port);
	error = uinet_sobind(listener_, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("bind failed\n");
		goto done;
	}
	
	error = uinet_solisten(listener_, -1);
	if (0 != error)
		goto done;

	if (verbose_) {
		char buf[32];

		printf("Listening on %s:%u\n", uinet_inet_ntoa(addr, buf, sizeof(buf)), cfg->listen_port);
	}
	
	watcher_.set<EchoServer, &EchoServer::accept>(this);
	watcher_.start(soctx_, EV_READ);

done:
	return;
}


EchoServer::~EchoServer()
{
	if (watcher_.is_active())
		watcher_.stop();

	if (soctx_)
		ev_uinet_detach(soctx_);

	if (listener_)
		uinet_soclose(listener_);
}


void
EchoServer::accept(ev::uinet &w, int revents)
{
	struct uinet_socket *newso = NULL;
	int error;

	if (0 != (error = uinet_soaccept(w.so, NULL, &newso))) {
		printf("accept failed (%d)\n", error);
	} else {
		printf("accept succeeded\n");
		
		EchoResponder *responder = new EchoResponder(loop_, newso);

		if (!responder->is_running())
			delete responder;
	}
}


void *interface_thread_start(void *arg)
{
	struct interface_config *cfg = (struct interface_config *)arg;

	uinet_initialize_thread();

	cfg->loop->run();

	uinet_finalize_thread();

	return (NULL);
}


static void
usage(const char *progname)
{

	printf("Usage: %s [options]\n", progname);
	printf("    -h                   show usage\n");
	printf("    -i ifname            specify network interface\n");
	printf("    -l inaddr            listen address\n");
	printf("    -p port              listen port [0, 65535]\n");
	printf("    -v                   be verbose\n");
}


int main (int argc, char **argv)
{
	int ch;
	char *progname = argv[0];
#define MIN_INTERFACES 1
#define MAX_INTERFACES 64
	struct interface_config interfaces[MAX_INTERFACES];
#define MIN_SERVERS 1
#define MAX_SERVERS 64	
	struct server_config servers[MAX_SERVERS];
	int num_interfaces = 0;
	int num_servers = 0;
	int interface_server_count = 0;
	int verbose = 0;
	unsigned int i;
	int error;

	for (i = 0; i < MAX_INTERFACES; i++) {
		interfaces[i].loop = NULL;
	}

	for (i = 0; i < MAX_SERVERS; i++) {
		servers[i].listen_addr = NULL;
		servers[i].listen_port = -1;
		servers[i].echo = NULL;
	}

	while ((ch = getopt(argc, argv, "hi:l:p:v")) != -1) {
		switch (ch) {
		case 'h':
			usage(progname);
			return (0);
		case 'i':
			if (MAX_INTERFACES == num_interfaces) {
				printf("Maximum number of interfaces is %u\n", MAX_INTERFACES);
				return (1);
			} else {
				interfaces[num_interfaces].ifname = optarg;
				interfaces[num_interfaces].cdom = num_interfaces + 1;
				num_interfaces++;
				interface_server_count = 0;
			}
			break;
		case 'l':
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else if (MAX_INTERFACES == num_interfaces) {
				printf("Maximum number of interfaces is %u\n", MAX_INTERFACES);
				return (1);
			} else {
				servers[num_servers].listen_addr = optarg;
				servers[num_servers].interface = &interfaces[num_interfaces - 1];
				num_servers++;
				interface_server_count++;
			}
			break;
		case 'p':
			if (0 == interface_server_count) {
				printf("No listen address specified\n");
				return (1);
			} else {
				servers[num_servers - 1].listen_port = strtoul(optarg, NULL, 10);
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
			printf("Unknown option \"%c\"\n", ch);
		case '?':
			usage(progname);
			return (1);
		}
	}
	argc -= optind;
	argv += optind;

	if (num_interfaces < MIN_INTERFACES) {
		printf("Specify at least %u interface%s\n", MIN_INTERFACES, MIN_INTERFACES == 1 ? "" : "s");
		return (1);
	}

	if (num_servers < MIN_SERVERS) {
		printf("Specify at least %u listen address%s\n", MIN_SERVERS, MIN_SERVERS == 1 ? "" : "es");
		return (1);
	}

	for (i = 0; i < num_servers; i++) {
		if (-1 == servers[i].listen_port) {
			printf("No listen port specified for interface %s, listen address %s\n",
			       servers[i].interface->ifname, servers[i].listen_addr);
			return (1);
		}

		if (servers[i].listen_port < 0 || servers[i].listen_port > 65535) {
			printf("Listen port for interface %s, listen address %s is out of range [0, 65535]\n",
			       servers[i].interface->ifname, servers[i].listen_addr);
			return (1);
		}
	}
	
	
	uinet_init(1, 128*1024, 0);
	uinet_install_sighandlers();

	for (i = 0; i < num_interfaces; i++) {
		error = uinet_ifcreate(UINET_IFTYPE_NETMAP, interfaces[i].ifname, interfaces[i].ifname, interfaces[i].cdom, 0, NULL);
		if (0 != error) {
			printf("Failed to create interface %s (%d)\n", interfaces[i].ifname, error);
		} else {
			error = uinet_interface_up(interfaces[i].ifname, 1, 1);
			if (0 != error) {
				printf("Failed to bring up interface %s (%d)\n", interfaces[i].ifname, error);
			}
		}

		interfaces[i].loop = new ev::dynamic_loop(EVFLAG_AUTO);
		if (NULL == interfaces[i].loop) {
			printf("Failed to create event loop interface %s\n", interfaces[i].ifname);
			break;
		}
		
	}
	
		
	for (i = 0; i < num_servers; i++) {
		servers[i].verbose = verbose;

		servers[i].echo = new EchoServer(*servers[i].interface->loop, &servers[i]);
		if (NULL == servers[i].echo) {
			printf("Failed to create echo server at %s:%d on interface %s\n",
			       servers[i].listen_addr, servers[i].listen_port,
			       servers[i].interface->ifname);
			break;
		}
	}

	for (i = 0; i < num_interfaces; i++) {
		if (verbose)
			printf("Creating interface thread for interface %s\n", interfaces[i].ifname);

		interfaces[i].thread_create_result = pthread_create(&interfaces[i].thread, NULL,
								    interface_thread_start, &interfaces[i]);
	}

	for (i = 0; i < num_interfaces; i++) {
		if (0 == interfaces[i].thread_create_result)
			pthread_join(interfaces[i].thread, NULL);
	}

	uinet_shutdown(0);

	return (0);
}
