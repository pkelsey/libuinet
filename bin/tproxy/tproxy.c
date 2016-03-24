/*
 * Copyright (c) 2013-2014 Patrick Kelsey. All rights reserved.
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
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "uinet_api.h"

#define EV_STANDALONE 1
#define EV_UINET_ENABLE 1
#include <ev.h>


struct connection_context {
	struct uinet_socket *so;
	struct ev_uinet_ctx *soctx;
	unsigned int write_shut;
};


struct pipe_context {
	const char *name;
	struct splice_context *splice;
	struct connection_context *from;
	struct connection_context *to;
	ev_uinet from_watcher;
	ev_uinet to_watcher;
};


struct splice_context {
	UINET_TAILQ_ENTRY(splice_context) splice_table;
	struct proxy_context *proxy;
	ev_uinet outbound_connect_watcher;
	uinet_synf_deferral_t synf_deferral;
	struct uinet_in_l2tagstack l2tags;
	struct uinet_sockaddr_in client_addr;
	struct uinet_sockaddr_in server_addr;
	struct connection_context client;
	struct connection_context server;
	struct pipe_context client_to_server;
	struct pipe_context server_to_client;
};


struct splice_table {
	pthread_mutex_t lock;
	UINET_TAILQ_HEAD(splice_table_bucket, splice_context) *buckets;
	uint32_t mask;
};


struct synf_queue_entry {
	UINET_STAILQ_ENTRY(synf_queue_entry) synf_queue;
	struct splice_context *splice;
};


struct interface_config {
	uinet_instance_t uinst;
	uinet_if_t uif;
};

struct proxy_context {
	struct ev_loop *loop;
	pthread_t thread;
	struct uinet_socket *listener;
	ev_uinet listen_watcher;
	ev_async synf_watcher;
	pthread_mutex_t synf_queue_lock;
	UINET_STAILQ_HEAD(, synf_queue_entry) synf_queue;
	struct splice_table splicetab;
	int verbose;
	struct interface_config client_ifcfg;
	struct interface_config server_ifcfg;
};


static __inline int imin(int a, int b) { return (a < b ? a : b); }


static void
print_inc(struct uinet_in_conninfo *inc, int local)
{
	char buf[32];

	if (local)
		printf("%s:%u", uinet_inet_ntoa(inc->inc_ie.ie_laddr, buf, sizeof(buf)), ntohs(inc->inc_ie.ie_lport));
	else
		printf("%s:%u", uinet_inet_ntoa(inc->inc_ie.ie_faddr, buf, sizeof(buf)), ntohs(inc->inc_ie.ie_fport));
}


static void
print_sin_port(struct uinet_sockaddr_in *sin, uint16_t port)
{
	char buf[32];
	printf("%s:%u", uinet_inet_ntoa(sin->sin_addr, buf, sizeof(buf)), ntohs(port));
}


static void
conn_init(struct connection_context *conn, struct uinet_socket *so, struct ev_uinet_ctx *soctx)
{
	conn->so = so;
	conn->soctx = soctx;
	conn->write_shut = 0;
}


static void
conn_fini(struct connection_context *conn)
{
	if (conn->so)
		uinet_soclose(conn->so);

	if (conn->soctx)
		ev_uinet_detach(conn->soctx);
}


static struct splice_context *
splice_alloc(struct uinet_in_l2info *l2i, struct uinet_in_conninfo *inc)
{
	struct splice_context *s;
	struct uinet_sockaddr_in *sin;

	s = calloc(1, sizeof(struct splice_context));
	if (NULL != s) {
		s->proxy = NULL;
		s->synf_deferral = NULL;

		s->l2tags = l2i->inl2i_tagstack;

		/* XXX assuming IPV4 */

		s->client_addr.sin_len = sizeof(struct uinet_sockaddr_in);
		s->client_addr.sin_family = UINET_AF_INET;
		s->client_addr.sin_port = inc->inc_ie.ie_fport;
		s->client_addr.sin_addr = inc->inc_ie.ie_faddr;

		s->server_addr.sin_len = sizeof(struct uinet_sockaddr_in);
		s->server_addr.sin_family = UINET_AF_INET;
		s->server_addr.sin_port = inc->inc_ie.ie_lport;
		s->server_addr.sin_addr = inc->inc_ie.ie_laddr;
	}

	return (s);
}


static int
splice_table_init(struct splice_table *t, unsigned int nbuckets)
{
	unsigned int actual_buckets = 1;
	unsigned int max_buckets = ((unsigned int)-1 >> 1) + 1;
	unsigned int i;

	pthread_mutex_init(&t->lock, NULL);

	if (nbuckets > max_buckets)
		nbuckets = max_buckets;

	while (actual_buckets < nbuckets)
		actual_buckets <<= 1;

	t->buckets = malloc(sizeof(struct splice_table_bucket) * actual_buckets);
	if (NULL == t->buckets)
		return (ENOMEM);

	for (i = 0; i < actual_buckets; i++) {
		UINET_TAILQ_INIT(&t->buckets[i]);
	}

	t->mask = actual_buckets - 1;

	return (0);
}


static uint32_t
splice_table_hash(struct splice_table *t, struct uinet_in_l2tagstack *l2tags,
		  uinet_in_addr_t laddr, uinet_in_port_t lport, uinet_in_addr_t faddr, uinet_in_port_t fport)
{
	uint32_t hash;

	hash = uinet_l2tagstack_hash(l2tags);
	hash ^= laddr ^ lport ^ faddr ^ fport;
	hash ^= hash >> 16;

	return (hash & t->mask);
}


static void
splice_table_lock(struct splice_table *t)
{
	pthread_mutex_lock(&t->lock);
}


static void
splice_table_unlock(struct splice_table *t)
{
	pthread_mutex_unlock(&t->lock);
}


static void
splice_table_insert(struct splice_table *t, struct splice_context *splice)
{
	struct splice_table_bucket *bucket;
	struct uinet_sockaddr_in *client_sin = &splice->client_addr;
	struct uinet_sockaddr_in *server_sin = &splice->server_addr;

	bucket = &t->buckets[splice_table_hash(t,
					       &splice->l2tags,
					       server_sin->sin_addr.s_addr, server_sin->sin_port,
					       client_sin->sin_addr.s_addr, client_sin->sin_port)];
	
	UINET_TAILQ_INSERT_HEAD(bucket, splice, splice_table);
}


static void
splice_table_remove(struct splice_table *t, struct splice_context *splice)
{
	struct splice_table_bucket *bucket;
	struct uinet_sockaddr_in *client_sin = &splice->client_addr;
	struct uinet_sockaddr_in *server_sin = &splice->server_addr;
	
	bucket = &t->buckets[splice_table_hash(t,
					       &splice->l2tags,
					       server_sin->sin_addr.s_addr, server_sin->sin_port,
					       client_sin->sin_addr.s_addr, client_sin->sin_port)];
	
	UINET_TAILQ_REMOVE(bucket, splice, splice_table);
}


static struct splice_context *
splice_table_lookup(struct splice_table *t, struct uinet_in_l2info *l2i, struct uinet_in_conninfo *inc)
{
	struct splice_table_bucket *bucket;
	struct splice_context *splice;

	bucket = &t->buckets[splice_table_hash(t,
					       &l2i->inl2i_tagstack,
					       inc->inc_ie.ie_laddr.s_addr, inc->inc_ie.ie_lport,
					       inc->inc_ie.ie_faddr.s_addr, inc->inc_ie.ie_fport)];
					       
	
	UINET_TAILQ_FOREACH(splice, bucket, splice_table) {
		struct uinet_sockaddr_in *client_sin = &splice->client_addr;
		struct uinet_sockaddr_in *server_sin = &splice->server_addr;

		/*
		 * The connection info in inc is from the incoming SYN from
		 * the client, so the client's address is in the foreign part.
		 */
		if ((0 == uinet_l2tagstack_cmp(&splice->l2tags, &l2i->inl2i_tagstack)) &&
		    (client_sin->sin_addr.s_addr == inc->inc_ie.ie_faddr.s_addr) &&
		    (client_sin->sin_port == inc->inc_ie.ie_fport) &&
		    (server_sin->sin_addr.s_addr == inc->inc_ie.ie_laddr.s_addr) &&
		    (server_sin->sin_port == inc->inc_ie.ie_lport)) {
			return (splice);
		}
	}

	return (NULL);
}


static void
splice_free(struct splice_context *splice)
{
	struct proxy_context *proxy = splice->proxy;

	if (splice->synf_deferral)
		uinet_synfilter_deferral_free(splice->synf_deferral);

	if (proxy) {
		splice_table_lock(&proxy->splicetab);
		splice_table_remove(&proxy->splicetab, splice);
		splice_table_unlock(&proxy->splicetab);
	}

	conn_fini(&splice->client);
	conn_fini(&splice->server);
	
	free(splice);
}


static void
splice_pipe_shut(struct splice_context *splice, struct pipe_context *pipe)
{
	struct proxy_context *proxy = splice->proxy;

	printf("shutting pipe\n");

	if (splice->client.write_shut && splice->server.write_shut) {
		splice_free(splice);
	}
}


static struct proxy_context *
proxy_alloc(unsigned int num_splices)
{
	struct proxy_context *p;

	p = malloc(sizeof(struct proxy_context));
	if (NULL != p) {
		p->listener = NULL;
		splice_table_init(&p->splicetab, num_splices);
		p->verbose = 0;
	}

	return (p);
}


static int
dobind(struct uinet_socket *so, uinet_in_addr_t addr, uinet_in_port_t port)
{
	struct uinet_sockaddr_in sin;
	int error;

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr.s_addr = addr;
	sin.sin_port = port;
	error = uinet_sobind(so, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("Bind to "); print_sin_port(&sin, port); printf(" (%d)\n", error);
	}

	return (error);
}


static void
outbound_connect_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct splice_context *splice = w->data;
	struct proxy_context *proxy = splice->proxy;
	struct uinet_socket *so = splice->server.so;
	struct uinet_in_conninfo inc;
	int error;

	ev_uinet_stop(loop, &splice->outbound_connect_watcher);

	if (uinet_sowritable(so, 0) >= 0) {
		if (proxy->verbose) {
			uinet_sogetconninfo(so, &inc);
			printf("Connection from "); print_inc(&inc, 0); printf(" to "); print_inc(&inc, 1); printf(" complete\n");
		}

		uinet_synfilter_deferral_deliver(proxy->listener, splice->synf_deferral, UINET_SYNF_ACCEPT);
		splice->synf_deferral = NULL;
	} else {
		/* failed to connect */
		error = uinet_sogeterror(so);

		if (proxy->verbose) {
			uinet_sogetconninfo(so, &inc);
			printf("Connection from "); print_inc(&inc, 0); printf(" to "); print_inc(&inc, 1); printf(" failed (%d)\n", error);
		}

		uinet_synfilter_deferral_deliver(proxy->listener, splice->synf_deferral,
						 (UINET_ECONNREFUSED == error) ?
						 UINET_SYNF_REJECT_RST : UINET_SYNF_REJECT_SILENT);

		splice->synf_deferral = NULL;
		splice_free(splice);
	}
}


static void
process_synf_queue(struct ev_loop *loop, ev_async *w, int revents)
{
	struct proxy_context *proxy = w->data;
	struct synf_queue_entry *qentry;
	struct splice_context *splice;
	struct uinet_socket *so;
	int error;
	unsigned int optval, optlen;
	uinet_api_synfilter_cookie_t cookie;
	struct uinet_in_conninfo inc;
	struct uinet_in_l2info l2i;
	struct uinet_sockaddr_in sin;

	if (proxy->verbose > 1)
		printf("Processing synf queue\n");

	pthread_mutex_lock(&proxy->synf_queue_lock);

	while (NULL != (qentry = UINET_STAILQ_FIRST(&proxy->synf_queue))) {
		UINET_STAILQ_REMOVE_HEAD(&proxy->synf_queue, synf_queue);
		pthread_mutex_unlock(&proxy->synf_queue_lock);
		
		splice = qentry->splice;
		so = splice->server.so;
		cookie = uinet_synfilter_deferral_get_cookie(splice->synf_deferral);

		uinet_synfilter_getconninfo(cookie, &inc);

		if ((error = uinet_make_socket_promiscuous(so, proxy->server_ifcfg.uif))) {
			printf("Failed to make socket promiscuous (%d)\n", error);
			goto err;
		}

		uinet_sosetnonblocking(so, 1);

		optlen = sizeof(optval);
		optval = 1;
		if ((error = uinet_sosetsockopt(so, UINET_IPPROTO_TCP, UINET_TCP_NODELAY, &optval, optlen))) {
			printf("Failed to set TCP_NODELAY on socket (%d)\n", error);
			goto err;
		}

		if ((error = dobind(so, inc.inc_ie.ie_faddr.s_addr, inc.inc_ie.ie_fport))) {
			printf("Bind to "); print_inc(&inc, 0); printf(" failed (%d)\n", error);
			goto err;
		}

		uinet_synfilter_getl2info(cookie, &l2i);
		if ((error = uinet_setl2info2(so, l2i.inl2i_foreign_addr, l2i.inl2i_local_addr,
					      l2i.inl2i_flags, &l2i.inl2i_tagstack))) {
			printf("Failed to set l2info on socket (%d)\n", error);
			goto err;
		}

		if (proxy->verbose) {
			printf("Connecting from "); print_inc(&inc, 0); printf(" to "); print_inc(&inc, 1); printf("\n");
		}
	
		memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
		sin.sin_len = sizeof(struct uinet_sockaddr_in);
		sin.sin_family = UINET_AF_INET;
		sin.sin_addr.s_addr = inc.inc_ie.ie_laddr.s_addr;
		sin.sin_port = inc.inc_ie.ie_lport;
		error = uinet_soconnect(so, (struct uinet_sockaddr *)&sin);
		if (error) {
			if (UINET_EINPROGRESS == error) {
				error = 0;
			} else {
				printf("Connect to "); print_inc(&inc, 1); printf(" failed (%d)\n", error);
				goto err;
			}
		}

		ev_init(&splice->outbound_connect_watcher, outbound_connect_cb);
		ev_uinet_set(&splice->outbound_connect_watcher, splice->server.soctx, EV_WRITE);
		splice->outbound_connect_watcher.data = splice;
		ev_uinet_start(loop, &splice->outbound_connect_watcher);

	err:
		if (error) {
			uinet_synfilter_deferral_deliver(so, splice->synf_deferral,
							 (UINET_ECONNREFUSED == error) ?
							 UINET_SYNF_REJECT_RST : UINET_SYNF_REJECT_SILENT);

			splice->synf_deferral = NULL;
			splice_free(splice);
		}

		free(qentry);
		
		pthread_mutex_lock(&proxy->synf_queue_lock);
	}
	pthread_mutex_unlock(&proxy->synf_queue_lock);


	return;
}


static int
proxy_syn_filter(struct uinet_socket *lso, void *arg, uinet_api_synfilter_cookie_t cookie)
{
	struct proxy_context *proxy = arg;
	struct uinet_socket *so = NULL;
	struct ev_uinet_ctx *soctx;
	struct splice_context *splice = NULL;
	struct synf_queue_entry *qentry = NULL;
	uinet_synf_deferral_t deferral = NULL;
	struct uinet_in_l2info l2i;
	struct uinet_in_conninfo inc;
	unsigned int optval, optlen;
	int error;

	uinet_synfilter_getl2info(cookie, &l2i);
	uinet_synfilter_getconninfo(cookie, &inc);

	if (proxy->verbose > 1) {
		printf("SYN arrived from "); print_inc(&inc, 0); printf(" to "); print_inc(&inc, 1); printf(" ");
	}

	splice_table_lock(&proxy->splicetab);
	if (NULL == splice_table_lookup(&proxy->splicetab, &l2i, &inc)) {

		splice = splice_alloc(&l2i, &inc);
		if (NULL == splice) {
			printf("Failed to allocate splice context\n");
			goto err;
		}

		deferral = uinet_synfilter_deferral_alloc(lso, cookie);
		if (NULL == deferral) {
			printf("Failed to allocate SYN filter deferral\n");
			goto err;
		}

		splice->synf_deferral = deferral;

		/* Create outbound socket here to avoid need to grab splice
		 * table lock when processing the syn filter queue in the
		 * event loop.
		 */
		error = uinet_socreate(proxy->server_ifcfg.uinst, UINET_PF_INET, &so, UINET_SOCK_STREAM, 0);
		if (0 != error) {
			printf("Outbound socket creation failed (%d)\n", error);
			goto err;
		}

		soctx = ev_uinet_attach(so);
		if (NULL == soctx) {
			printf("Failed to alloc libev context for connection to server\n");
			goto err;
		}

		conn_init(&splice->server, so, soctx);

		splice_table_insert(&proxy->splicetab, splice);
		splice->proxy = proxy;

		splice_table_unlock(&proxy->splicetab);

		if (proxy->verbose > 1) {
			printf("...queueing to event loop\n");
		}

		qentry = malloc(sizeof(*qentry));
		if (NULL == qentry) {
			printf("Failed to allocate synf queue entry\n");
			goto err;
		}

		qentry->splice = splice;

		pthread_mutex_lock(&proxy->synf_queue_lock);
		UINET_STAILQ_INSERT_TAIL(&proxy->synf_queue, qentry, synf_queue);
		pthread_mutex_unlock(&proxy->synf_queue_lock);

		ev_async_send(proxy->loop, &proxy->synf_watcher);

		return (UINET_SYNF_DEFER);
	}

	if (proxy->verbose > 1) {
		printf("...DUPLICATE\n");
	}

err:
	splice_table_unlock(&proxy->splicetab);
	splice_free(splice);
	if (qentry) free(qentry);

	return (UINET_SYNF_REJECT_SILENT);
}


static void
pipe_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
#define BUFFER_SIZE (64*1024)
	struct pipe_context *pipe = w->data;
	char buffer[BUFFER_SIZE];
	struct uinet_iovec iov;
	struct uinet_uio uio;
	int max_read;
	int max_write;
	int read_size;
	int error;

	max_read = uinet_soreadable(pipe->from->so, 0);
	if (max_read <= 0) {
		/* the watcher should never be invoked if there is no error and there no bytes to be read */
		assert(max_read != 0);
		goto err;
	} else {
		max_write = uinet_sowritable(pipe->to->so, 0);
		if (-1 == max_write) {
			printf("%s: max_write == -1 (%d)\n", pipe->name, max_write);
			goto err;
		} else {
			read_size = imin(imin(max_read, max_write), BUFFER_SIZE);

			uio.uio_iov = &iov;
			iov.iov_base = buffer;
			iov.iov_len = read_size;
			uio.uio_iovcnt = 1;
			uio.uio_offset = 0;
			uio.uio_resid = read_size;
	
			error = uinet_soreceive(pipe->from->so, NULL, &uio, NULL);
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
			error = uinet_sosend(pipe->to->so, NULL, &uio, 0);
			if (0 != error) {
				printf("write error (%d), closing\n", error);
				goto err;
			}

			if (max_write < max_read) {
				/* limited by write space, so continue when
				 * the destination watcher is writable
				 */
				assert(uinet_soreadable(pipe->from->so, 0) > 0);
				if (w->events & EV_READ) {
					/* we need to switch to a write
					 * watch on &pipe->to_watcher
					 */
					assert(w == &pipe->from_watcher);
					ev_uinet_stop(loop, &pipe->from_watcher);
					ev_uinet_start(loop, &pipe->to_watcher);
				}
				/* else, continue as a write watch on &pipe->to_watcher */
			} else if (!(w->events & EV_READ)) {
				/* w is a write watcher (which implies w ==
				 * &pipe->to_watcher), but write space
				 * wasn't a limitation this time, so switch
				 * back to a read watch on
				 * &pipe->from_watcher.
				 */
				assert(w == &pipe->to_watcher);
				ev_uinet_stop(loop, &pipe->to_watcher);
				ev_uinet_start(loop, &pipe->from_watcher);
			}
			/* else, continue as a read watch on &pipe->from_watcher */
		}
	}

	return;

err:
	ev_uinet_stop(loop, w);

	uinet_soshutdown(pipe->to->so, UINET_SHUT_WR);
	pipe->to->write_shut = 1;
	splice_pipe_shut(pipe->splice, pipe);
}


void
pipe_init(const char *name, struct ev_loop *loop, struct pipe_context *pipe, struct splice_context *splice,
	  struct connection_context *from, struct connection_context *to)
{
	pipe->name = name;
	pipe->splice = splice;

	pipe->to = to;
	ev_init(&pipe->to_watcher, pipe_cb);
	ev_uinet_set(&pipe->to_watcher, to->soctx, EV_WRITE);
	pipe->to_watcher.data = pipe;

	pipe->from = from;
	ev_init(&pipe->from_watcher, pipe_cb);
	ev_uinet_set(&pipe->from_watcher, from->soctx, EV_READ);
	pipe->from_watcher.data = pipe;

	ev_uinet_start(loop, &pipe->from_watcher);
}


static void
accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct proxy_context *proxy = w->data;
	struct uinet_socket *newso;
	struct splice_context *splice;
	struct uinet_in_l2info l2i;
	struct uinet_in_conninfo inc;
	struct ev_uinet_ctx *soctx;
	int error;

	if (0 != (error = uinet_soaccept(w->so, NULL, &newso))) {
		printf("accept failed (%d)\n", error);
	} else {
		uinet_getl2info(newso, &l2i);
		uinet_sogetconninfo(newso, &inc);

		splice_table_lock(&proxy->splicetab);
		splice = splice_table_lookup(&proxy->splicetab, &l2i, &inc);
		if (NULL == splice) {
			printf("Unexpected inbound connection\n");
			goto fail;
		} else {
			if (proxy->verbose > 1) {
				printf("Inbound connection from "); print_inc(&inc, 0); printf(" to "); print_inc(&inc, 1); printf("\n");
			}

			soctx = ev_uinet_attach(newso);
			if (NULL == soctx) {
				printf("Failed to alloc libev context for client socket\n");
				goto fail;
			}

			conn_init(&splice->client, newso, soctx);

			pipe_init("client->server", loop, &splice->client_to_server, splice, &splice->client, &splice->server);
			pipe_init("server->client", loop, &splice->server_to_client, splice, &splice->server, &splice->client);

		}
		splice_table_unlock(&proxy->splicetab);
	}

	return;

fail:
	if (splice)
		splice_table_remove(&proxy->splicetab, splice);
	splice_table_unlock(&proxy->splicetab);

}


static struct proxy_context *
create_proxy(struct ev_loop *loop,  struct interface_config *client_ifcfg, struct interface_config *server_ifcfg,
	     uinet_in_addr_t listen_addr, uinet_in_port_t listen_port, int verbose)
{
	struct proxy_context *proxy = NULL;
	struct uinet_socket *listener = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	int optlen, optval;
	int error;
	int async_watcher_started = 0;

	error = uinet_socreate(client_ifcfg->uinst, UINET_PF_INET, &listener, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("Listen socket creation failed (%d)\n", error);
		goto fail;
	}

	soctx = ev_uinet_attach(listener);
	if (NULL == soctx) {
		printf("Failed to alloc libev socket context\n");
		goto fail;
	}
	
	if ((error = uinet_make_socket_promiscuous(listener, NULL))) {
		printf("Failed to make listen socket promiscuous (%d)\n", error);
		goto fail;
	}

	uinet_sosetnonblocking(listener, 1);

	/* Set NODELAY on the listen socket so it will be set on all
	 * accepted sockets via inheritance.
	 */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_NODELAY, &optval, optlen)))
		goto fail;

	proxy = proxy_alloc(10000); /* XXX make tunable */
	if (NULL == proxy)
		goto fail;

	
	pthread_mutex_init(&proxy->synf_queue_lock, NULL);
	UINET_STAILQ_INIT(&proxy->synf_queue);

	ev_async_init(&proxy->synf_watcher, process_synf_queue);
	proxy->synf_watcher.data = proxy;
	ev_async_start(loop, &proxy->synf_watcher);
	async_watcher_started = 1;

	if ((error = uinet_synfilter_install(listener, proxy_syn_filter, proxy))) {
		printf("Listen socket SYN filter install failed (%d)\n", error);
		goto fail;
	}
	
	/* Listen on all VLANs */
	if ((error = uinet_setl2info2(listener, NULL, NULL, UINET_INL2I_TAG_ANY, NULL))) {
		printf("Listen socket L2 info set failed (%d)\n", error);
		goto fail;
	}

	proxy->loop = loop;
	proxy->listener = listener;
	proxy->verbose = verbose;
	proxy->client_ifcfg = *client_ifcfg;
	proxy->server_ifcfg = *server_ifcfg;

	error = dobind(proxy->listener, listen_addr, htons(listen_port));
	if (0 != error)
		goto fail;
	
	error = uinet_solisten(proxy->listener, -1);
	if (0 != error)
		goto fail;

	if (proxy->verbose) {
		char buf[32];
		struct uinet_in_addr in;

		in.s_addr = listen_addr;
		printf("Listening on %s:%u\n", uinet_inet_ntoa(in, buf, sizeof(buf)), listen_port);
	}

	ev_init(&proxy->listen_watcher, accept_cb);
	ev_uinet_set(&proxy->listen_watcher, soctx, EV_READ);
	proxy->listen_watcher.data = proxy;
	ev_uinet_start(loop, &proxy->listen_watcher);

	return (proxy);

fail:
	if (async_watcher_started) ev_async_stop(loop, &proxy->synf_watcher);
	if (soctx) ev_uinet_detach(soctx);
	if (listener) uinet_soclose(listener);
	if (proxy) free(proxy);

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
#define MIN_IFS 2
#define MAX_IFS 2
	int num_ifs = 0;
	char *ifnames[MAX_IFS];
	struct interface_config ifs[MAX_IFS];
	char *listen_addr = NULL;
	int listen_port = -1;
	int verbose = 0;
	int i;
	int error;
	struct uinet_if_cfg ifcfg;

	while ((ch = getopt(argc, argv, "hi:l:p:v")) != -1) {
		switch (ch) {
		case 'h':
			usage(progname);
			return (0);
		case 'i':
			if (num_ifs < MAX_IFS) {
				ifnames[num_ifs] = optarg;
				num_ifs++;
			}
			break;
		case 'l':
			listen_addr = optarg;
			break;
		case 'p':
			listen_port = strtoul(optarg, NULL, 10);
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

	if (num_ifs < MIN_IFS) {
		printf("Specify at least %u interface%s\n", MIN_IFS, MIN_IFS == 1 ? "" : "s");
		return (1);
	}

	if (NULL == listen_addr) {
		printf("Specify a listen address\n");
		return (1);
	}

	if (listen_port < 0 || listen_port > 65535) {
		printf("Specify a listen port [0, 65535]\n");
		return (1);
	}

	struct uinet_global_cfg cfg;
	uinet_default_cfg(&cfg, UINET_GLOBAL_CFG_MEDIUM);
	uinet_init(&cfg, NULL);
	uinet_install_sighandlers();

	for (i = 0; i < num_ifs; i++) {
		ifs[i].uinst = uinet_instance_create(NULL);
		if (ifs[i].uinst == NULL) {
			printf("Failed to create uinet instance %d\n", i);
			exit(1);
		}

		uinet_if_default_config(UINET_IFTYPE_NETMAP, &ifcfg);
		ifcfg.configstr = ifnames[i];
		ifcfg.alias = ifnames[i];
		error = uinet_ifcreate(ifs[i].uinst, &ifcfg, &ifs[i].uif);
		if (0 != error) {
			printf("Failed to create interface %s (%d)\n", ifnames[i], error);
		} else {
			error = uinet_interface_up(uinet_instance_default(), ifnames[i], 1, 1);
			if (0 != error) {
				printf("Failed to bring up interface %s (%d)\n", ifnames[i], error);
			}
		}
	}

	struct ev_loop *loop = ev_default_loop(0);

	struct proxy_context *proxy;

	struct uinet_in_addr addr;
	if (uinet_inet_pton(UINET_AF_INET, listen_addr, &addr) <= 0) {
		printf("Malformed address %s\n", listen_addr);
		return (1);
	}

	proxy = create_proxy(loop,
			     &ifs[0], &ifs[1],
			     addr.s_addr, listen_port,
			     verbose);

	ev_run(loop, 0);

	uinet_shutdown(0);

	return (0);
}
