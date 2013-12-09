/*
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
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


#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/queue.h>

#include "uinet_api.h"


enum event_type {
	EVENT_CONNECTED,
	EVENT_RCV_READY,
	EVENT_SND_READY
};

struct connection_context;

struct event {
	TAILQ_ENTRY(event) event_queue;
	struct connection_context *conn;
	enum event_type type;
	int active;
};


struct event_queue {
	TAILQ_HEAD(event_list_head, event) queue;
	pthread_mutex_t lock;
	pthread_cond_t cv;
};


struct splice_context *splice;

struct connection_context {
	struct splice_context *splice;
	struct uinet_socket *so;
	struct uinet_sockaddr *local_addr;	/* debugging aid */
	struct uinet_sockaddr *foreign_addr;	/* debugging aid */
	struct event_queue *eq;
	struct event rcv_ready;
	struct event snd_ready;
	struct event connected;
#define CONN_BUFFER_SIZE 1024
	unsigned int occupied;
	unsigned int input_index;
	unsigned int output_index;
	uint8_t buffer[CONN_BUFFER_SIZE];
};


struct splice_context {
	TAILQ_ENTRY(splice_context) splice_table;
	struct proxy_context *proxy;
	void *synf_deferral;
	struct uinet_sockaddr *client_addr;
	struct uinet_sockaddr *server_addr;
	struct connection_context client;
	struct connection_context server;
};


struct splice_table {
	pthread_mutex_t lock;
	TAILQ_HEAD(splice_table_bucket, splice_context) *buckets;
	uint32_t mask;
};

struct proxy_context {
	pthread_t thread;
	struct uinet_socket *listener;
	struct event_queue eq;
	struct splice_table splicetab;
	int verbose;
	unsigned int client_fib;
	unsigned int server_fib;
};




static int
event_init(struct event *e, struct connection_context *conn, enum event_type type)
{
	e->conn = conn;
	e->type = type;
	e->active = 0;

	return (0);
}


static void
event_send(struct event_queue *q, struct event *e)
{
	pthread_mutex_lock(&q->lock);
	if (!e->active) {
		e->active = 1;
		TAILQ_INSERT_TAIL(&q->queue, e, event_queue);
		pthread_cond_signal(&q->cv);
	}
	pthread_mutex_unlock(&q->lock);
}


static void
event_queue_init(struct event_queue *q)
{
	TAILQ_INIT(&q->queue);
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->cv, NULL);
}


static struct event *
event_queue_next(struct event_queue *q)
{
	struct event * e;

	pthread_mutex_lock(&q->lock);
	while (TAILQ_EMPTY(&q->queue)) {
		pthread_cond_wait(&q->cv, &q->lock);
	}
	e = TAILQ_FIRST(&q->queue);
	TAILQ_REMOVE(&q->queue, e, event_queue);
	e->active = 0;
	pthread_mutex_unlock(&q->lock);

	return (e);
}


static void
conn_init(struct connection_context *conn, struct uinet_socket *so, struct splice_context *splice)
{
	conn->splice = splice;
	conn->so = so;
	conn->local_addr = NULL;
	conn->foreign_addr = NULL;
	conn->eq = &splice->proxy->eq;
	event_init(&conn->rcv_ready, conn, EVENT_RCV_READY);
	event_init(&conn->snd_ready, conn, EVENT_SND_READY);
	event_init(&conn->connected, conn, EVENT_CONNECTED);
	conn->occupied = 0;
	conn->input_index = 0;
	conn->output_index = 0;
}


static struct splice_context *
splice_alloc(struct uinet_in_conninfo *inc)
{
	struct splice_context *s;
	struct uinet_sockaddr_in *sin;

	s = malloc(sizeof(struct splice_context));
	if (NULL != s) {
		s->proxy = NULL;
		s->synf_deferral = 0;


		/* XXX assuming IPV4 */
		sin = calloc(2, sizeof(struct uinet_sockaddr_in));
		if (NULL == sin) {
			free(s);
			return (NULL);
		}

		sin->sin_len = sizeof(struct uinet_sockaddr_in);
		sin->sin_family = UINET_AF_INET;
		sin->sin_port = inc->inc_ie.ie_fport;
		sin->sin_addr = inc->inc_ie.ie_faddr;
		s->client_addr = (struct uinet_sockaddr *)sin;

		sin++;

		sin->sin_len = sizeof(struct uinet_sockaddr_in);
		sin->sin_family = UINET_AF_INET;
		sin->sin_port = inc->inc_ie.ie_lport;
		sin->sin_addr = inc->inc_ie.ie_laddr;
		s->server_addr = (struct uinet_sockaddr *)sin;
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
		TAILQ_INIT(&t->buckets[i]);
	}

	t->mask = actual_buckets - 1;

	return (0);
}


static uint32_t
splice_table_hash(struct splice_table *t, uinet_in_addr_t laddr, uinet_in_port_t lport, uinet_in_addr_t faddr, uinet_in_port_t fport)
{
	uint32_t hash;

	hash = laddr ^ lport ^ faddr ^ fport;
	hash ^= hash >> 16;

	return (hash & t->mask);
}


static void
splice_table_insert(struct splice_table *t, struct splice_context *splice)
{
	struct splice_table_bucket *bucket;
	struct uinet_sockaddr_in *client_sin = (struct uinet_sockaddr_in *)splice->client_addr;
	struct uinet_sockaddr_in *server_sin = (struct uinet_sockaddr_in *)splice->server_addr;

	pthread_mutex_lock(&t->lock);

	bucket = &t->buckets[splice_table_hash(t,
					       server_sin->sin_addr.s_addr, server_sin->sin_port,
					       client_sin->sin_addr.s_addr, client_sin->sin_port)];
	
	TAILQ_INSERT_HEAD(bucket, splice, splice_table);

	pthread_mutex_unlock(&t->lock);
}


static void
splice_table_remove(struct splice_table *t, struct splice_context *splice)
{
	struct splice_table_bucket *bucket;
	struct uinet_sockaddr_in *client_sin = (struct uinet_sockaddr_in *)splice->client_addr;
	struct uinet_sockaddr_in *server_sin = (struct uinet_sockaddr_in *)splice->server_addr;
	
	pthread_mutex_lock(&t->lock);

	bucket = &t->buckets[splice_table_hash(t,
					       server_sin->sin_addr.s_addr, server_sin->sin_port,
					       client_sin->sin_addr.s_addr, client_sin->sin_port)];
	
	TAILQ_REMOVE(bucket, splice, splice_table);

	pthread_mutex_unlock(&t->lock);
}


static struct splice_context *
splice_table_lookup(struct splice_table *t, struct uinet_in_conninfo *inc)
{
	struct splice_table_bucket *bucket;
	struct splice_context *splice;

	pthread_mutex_lock(&t->lock);
	bucket = &t->buckets[splice_table_hash(t,
					       inc->inc_ie.ie_laddr.s_addr, inc->inc_ie.ie_lport,
					       inc->inc_ie.ie_faddr.s_addr, inc->inc_ie.ie_fport)];
					       
	
	TAILQ_FOREACH(splice, bucket, splice_table) {
		struct uinet_sockaddr_in *client_sin = (struct uinet_sockaddr_in *)splice->client_addr;
		struct uinet_sockaddr_in *server_sin = (struct uinet_sockaddr_in *)splice->server_addr;

		/*
		 * The connection info in inc is from the incoming SYN from
		 * the client, so the client's address is in the foreign part.
		 */
		if ((client_sin->sin_addr.s_addr == inc->inc_ie.ie_faddr.s_addr) &&
		    (client_sin->sin_port == inc->inc_ie.ie_fport) &&
		    (server_sin->sin_addr.s_addr == inc->inc_ie.ie_laddr.s_addr) &&
		    (server_sin->sin_port == inc->inc_ie.ie_lport)) {
			pthread_mutex_unlock(&t->lock);
			return (splice);
		}
	}

	pthread_mutex_unlock(&t->lock);
	return (NULL);
}


static struct proxy_context *
proxy_alloc(unsigned int num_splices)
{
	struct proxy_context *p;

	p = malloc(sizeof(struct proxy_context));
	if (NULL != p) {
		p->listener = NULL;
		event_queue_init(&p->eq);
		splice_table_init(&p->splicetab, num_splices);
		p->verbose = 0;
	}

	return (p);
}


static int
proxy_conn_rcv(struct uinet_socket *so, void *arg, int waitflag)
{
	struct connection_context *conn = (struct connection_context *)arg;

	event_send(conn->eq, &conn->rcv_ready);

	return (UINET_SU_OK);
}


static int
outbound_conn_complete(struct uinet_socket *so, void *arg, int waitflag)
{
	struct connection_context *conn = (struct connection_context *)arg;

	if (conn->splice->proxy->verbose > 1)
		printf("outbound_conn_complete\n");

	event_send(conn->eq, &conn->connected);

	uinet_soupcall_set(so, UINET_SO_RCV, proxy_conn_rcv, conn);

	proxy_conn_rcv(so, conn, waitflag);

	return (UINET_SU_OK);
}


static int
inbound_conn_complete(struct uinet_socket *so, void *arg, int waitflag)
{
	struct proxy_context *proxy = (struct proxy_context *)arg;
	struct uinet_in_conninfo inc;
	struct connection_context *conn;
	struct splice_context *splice;

	if (proxy->verbose > 1)
		printf("inbound_conn_complete\n");

	uinet_sogetconninfo(so, &inc);

	splice = splice_table_lookup(&proxy->splicetab, &inc);
	if (NULL != splice) {
		conn = &splice->client;
		conn_init(conn, so, splice);

		event_send(conn->eq, &conn->connected);

		uinet_soupcall_set(so, UINET_SO_RCV, proxy_conn_rcv, conn);

		proxy_conn_rcv(so, conn, waitflag);
	} else {
		printf("Failed to find splice for inbound connection\n");
	}

	return (UINET_SU_OK);
}


static int
listener_upcall(struct uinet_socket *head, void *arg, int waitflag)
{
	struct uinet_socket *so;
	struct uinet_sockaddr *sa = NULL;
	struct proxy_context *proxy = arg;
	struct splice_context *splice;
	int error;

	if (proxy->verbose > 1)
		printf("listener_upcall\n");

	error = uinet_soaccept(head, &sa, &so);
	if (error != 0)
		goto out;

	if (proxy->verbose)
		printf("new inbound connection\n");

	splice = malloc(sizeof(struct splice_context));
	if (NULL == splice) {
		uinet_soclose(so);
		goto out;
	}

	splice->proxy = proxy;
	conn_init(&splice->client, so, splice);

	uinet_soupcall_set(so, UINET_SO_RCV, inbound_conn_complete, proxy);

out:
	if (sa)
		uinet_free_sockaddr(sa);

	return (UINET_SU_OK);
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
		char buf[32];
		printf("Bind to %s:%u failed (%d)\n", uinet_inet_ntoa(sin.sin_addr, buf, sizeof(buf)), ntohs(port), error);
	}

	return (error);
}


static void
on_receive_ready(struct connection_context *rx, struct connection_context *tx)
{
	struct uinet_iovec iov[2];
	struct uinet_uio uio;
	unsigned int space = CONN_BUFFER_SIZE - rx->occupied;
	unsigned int bytes_to_end_of_buffer;
	unsigned int bytes_read;
	unsigned int bytes_written;
	int error;

	if (space > 0) {
		bytes_to_end_of_buffer = CONN_BUFFER_SIZE - rx->input_index;

		uio.uio_iov = iov;
		iov[0].iov_base = &rx->buffer[rx->input_index];
		iov[0].iov_len = (space > bytes_to_end_of_buffer) ? bytes_to_end_of_buffer : space;
		if (space > bytes_to_end_of_buffer) {
			iov[1].iov_base = rx->buffer;
			iov[1].iov_len = space - bytes_to_end_of_buffer;
			uio.uio_iovcnt = 2;
		} else {
			uio.uio_iovcnt = 1;
		}
		uio.uio_offset = 0;
		uio.uio_resid = space;
	
		error = uinet_soreceive(rx->so, NULL, &uio, NULL);
		bytes_read = space - uio.uio_resid;

		printf("read %u bytes from %p\n", bytes_read, rx);
		
		rx->occupied += bytes_read;
		rx->input_index += bytes_read;
		if (rx->input_index >= CONN_BUFFER_SIZE)
			rx->input_index -= CONN_BUFFER_SIZE;
	}


	if (rx->occupied) {
		bytes_to_end_of_buffer = CONN_BUFFER_SIZE - rx->output_index;

		uio.uio_iov = iov;
		iov[0].iov_base = &rx->buffer[rx->output_index];
		iov[0].iov_len = (rx->occupied > bytes_to_end_of_buffer) ? bytes_to_end_of_buffer : rx->occupied;
		if (rx->occupied > bytes_to_end_of_buffer) {
			iov[1].iov_base = rx->buffer;
			iov[1].iov_len = rx->occupied - bytes_to_end_of_buffer;
			uio.uio_iovcnt = 2;
		} else {
			uio.uio_iovcnt = 1;
		}
		uio.uio_offset = 0;
		uio.uio_resid = rx->occupied;
		error = uinet_sosend(tx->so, NULL, &uio, 0);
		bytes_written = rx->occupied - uio.uio_resid;

		printf("wrote %u bytes to %p\n", bytes_written, tx);

		rx->occupied -= bytes_written;
		rx->output_index += bytes_written;
		if (rx->output_index >= CONN_BUFFER_SIZE)
			rx->output_index -= CONN_BUFFER_SIZE;
	}
}


static void *
proxy_event_loop(void *arg)
{
	struct proxy_context *proxy = arg;
	struct splice_context *splice;
	struct event *e;
	struct connection_context *client;
	struct connection_context *server;
	struct uinet_socket *so;
	struct uinet_sockaddr_in *client_sin;
	struct uinet_sockaddr_in *server_sin;
	struct uinet_sockaddr_in *local_sin;
	struct uinet_sockaddr_in *foreign_sin;
	int error;

	uinet_initialize_thread();

	if (proxy->verbose)
		printf("Event loop started\n");

	while (1) {
		e = event_queue_next(&proxy->eq);
		splice = e->conn->splice;
		client = &splice->client;
		server = &splice->server;
		client_sin = (struct uinet_sockaddr_in *)splice->client_addr;
		server_sin = (struct uinet_sockaddr_in *)splice->server_addr;

		if (e->conn == client) {
			so = client->so;

			switch (e->type) {
			case EVENT_CONNECTED:
				if (uinet_sogetstate(so) & UINET_SS_ISCONNECTED) {
					error = uinet_sogetpeeraddr(so, &client->foreign_addr);
					if (error) {
						printf("Error getting peer address for client connection (%d)\n", error);
					}
					
					error = uinet_sogetsockaddr(so, &client->local_addr);
					if (error) {
						printf("Error getting local address for client connection (%d)\n", error);
					}
	
					if (proxy->verbose) {
						char buf1[32], buf2[32];

						local_sin = (struct uinet_sockaddr_in *)client->local_addr;
						foreign_sin = (struct uinet_sockaddr_in *)client->foreign_addr;

						printf("Inbound connection to %s:%u from %s:%u established\n",
						       uinet_inet_ntoa(local_sin->sin_addr, buf1, sizeof(buf1)),
						       ntohs(local_sin->sin_port),
						       uinet_inet_ntoa(foreign_sin->sin_addr, buf2, sizeof(buf2)),
						       ntohs(foreign_sin->sin_port));
					}
				}
				break;

			case EVENT_RCV_READY:
				if (uinet_sogetstate(so) & UINET_SS_ISDISCONNECTED) {
					if (proxy->verbose) {
						char buf1[32], buf2[32];
						printf("Inbound connection to %s:%u from %s:%u closed\n",
						       uinet_inet_ntoa(server_sin->sin_addr, buf1, sizeof(buf1)),
						       ntohs(server_sin->sin_port),
						       uinet_inet_ntoa(client_sin->sin_addr, buf2, sizeof(buf2)),
						       ntohs(client_sin->sin_port));
					}
				} else {
					on_receive_ready(client, server);
				}
				break;

			default:
				printf("Client connection event type %d\n", e->type);
				break;
			}
		} else {
			so = server->so;

			switch (e->type) {
			case EVENT_CONNECTED:
				if (uinet_sogetstate(so) & UINET_SS_ISCONNECTED) {
					error = uinet_sogetpeeraddr(so, &server->foreign_addr);
					if (error) {
						printf("Error getting peer address for server connection (%d)\n", error);
					}

					error = uinet_sogetsockaddr(so, &server->local_addr);
					if (error) {
						printf("Error getting local address for server connection (%d)\n", error);
					}
	
					if (proxy->verbose) {
						char buf1[32], buf2[32];

						local_sin = (struct uinet_sockaddr_in *)server->local_addr;
						foreign_sin = (struct uinet_sockaddr_in *)server->foreign_addr;
			
						printf("Outbound connection to %s:%u from %s:%u established\n",
						       uinet_inet_ntoa(local_sin->sin_addr, buf1, sizeof(buf1)),
						       ntohs(local_sin->sin_port),
						       uinet_inet_ntoa(foreign_sin->sin_addr, buf2, sizeof(buf2)),
						       ntohs(foreign_sin->sin_port));
					}

					uinet_synfilter_deferral_deliver(proxy->listener, splice->synf_deferral, UINET_SYNF_ACCEPT);
				}
				break;

			case EVENT_RCV_READY:
				if (uinet_sogetstate(so) & UINET_SS_ISDISCONNECTED) {
					if (proxy->verbose) {
						char buf1[32], buf2[32];
						printf("Outbound connection to %s:%u from %s:%u closed\n",
						       uinet_inet_ntoa(server_sin->sin_addr, buf1, sizeof(buf1)),
						       ntohs(server_sin->sin_port),
						       uinet_inet_ntoa(client_sin->sin_addr, buf2, sizeof(buf2)),
						       ntohs(client_sin->sin_port));
					}

					uinet_synfilter_deferral_deliver(proxy->listener, splice->synf_deferral, UINET_SYNF_REJECT);

					uinet_soupcall_clear(so, UINET_SO_RCV);					

					splice_table_remove(&proxy->splicetab, splice);
				} else {
					on_receive_ready(server, client);
				}
				break;

			default:
				printf("Client connection event type %d\n", e->type);
				break;
			}
			
		}

	}

	if (proxy->verbose)
		printf("Event loop exiting\n");

	pthread_exit(NULL);
}


static int
proxy_syn_filter(struct uinet_socket *lso, void *arg, uinet_api_synfilter_cookie_t cookie)
{
	struct proxy_context *proxy = arg;
	struct uinet_socket *so = NULL;
	struct splice_context *splice = NULL;
	struct uinet_in_conninfo inc;
	struct uinet_in_l2info l2i;
	struct uinet_sockaddr_in sin;
	unsigned int optval, optlen;
	int error;

	if (proxy->verbose > 1)
		printf("proxy_syn_filter\n");

	uinet_synfilter_getconninfo(cookie, &inc);

	if (NULL == splice_table_lookup(&proxy->splicetab, &inc)) {

		error = uinet_socreate(UINET_PF_INET, &so, UINET_SOCK_STREAM, 0);
		if (0 != error) {
			printf("Socket creation failed (%d)\n", error);
			goto err;
		}
	
		if ((error = uinet_make_socket_promiscuous(so, proxy->server_fib))) {
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


		if (proxy->verbose > 1) {
			char buf1[32], buf2[32];
			printf("SYN arrived from %s:%u to %s:%u\n",
			       uinet_inet_ntoa(inc.inc_ie.ie_faddr, buf1, sizeof(buf1)), ntohs(inc.inc_ie.ie_fport),
			       uinet_inet_ntoa(inc.inc_ie.ie_laddr, buf2, sizeof(buf2)), ntohs(inc.inc_ie.ie_lport));
		}

		if ((error = dobind(so, inc.inc_ie.ie_faddr.s_addr, inc.inc_ie.ie_fport))) {
			char buf[32];
			printf("Bind to %s:%u failed (%d)\n", uinet_inet_ntoa(inc.inc_ie.ie_faddr, buf, sizeof(buf)), ntohs(inc.inc_ie.ie_fport), error);
			goto err;
		}

		uinet_synfilter_getl2info(cookie, &l2i);
		if ((error = uinet_setl2info2(so, l2i.inl2i_foreign_addr, l2i.inl2i_local_addr,
					      l2i.inl2i_tags, l2i.inl2i_mask, l2i.inl2i_cnt))) {
			printf("Failed to set l2info on socket (%d)\n", error);
			goto err;
		}

		splice = splice_alloc(&inc);
		if (NULL == splice) {
			goto err;
		}

		splice->proxy = proxy;
		splice->synf_deferral = uinet_synfilter_deferral_alloc(lso, cookie);
		if (NULL == splice->synf_deferral) {
			printf("Failed to allocate SYN filter deferral\n");
			goto err;
		}

		conn_init(&splice->server, so, splice);

		splice_table_insert(&proxy->splicetab, splice);

		uinet_soupcall_set(so, UINET_SO_RCV, outbound_conn_complete, &splice->server);

		if (proxy->verbose) {
			char buf1[32], buf2[32];
			printf("Connecting from %s:%u to %s:%u\n",
			       uinet_inet_ntoa(inc.inc_ie.ie_faddr, buf1, sizeof(buf1)), ntohs(inc.inc_ie.ie_fport),
			       uinet_inet_ntoa(inc.inc_ie.ie_laddr, buf2, sizeof(buf2)), ntohs(inc.inc_ie.ie_lport));
		}
	
		memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
		sin.sin_len = sizeof(struct uinet_sockaddr_in);
		sin.sin_family = UINET_AF_INET;
		sin.sin_addr.s_addr = inc.inc_ie.ie_laddr.s_addr;
		sin.sin_port = inc.inc_ie.ie_lport;
		error = uinet_soconnect(so, (struct uinet_sockaddr *)&sin);
		if (error && UINET_EINPROGRESS != error) {
			char buf[32];
			printf("Connect to %s:%u failed (%d)\n", uinet_inet_ntoa(inc.inc_ie.ie_laddr, buf, sizeof(buf)), ntohs(inc.inc_ie.ie_lport), error);
			goto err;
		}

		return (UINET_SYNF_DEFER);
	}

err:
	if (so) uinet_soclose(so);
	if (splice) free(splice);

	return (UINET_SYNF_REJECT);
}


static struct proxy_context *
create_proxy(unsigned int client_fib, unsigned int server_fib,
	     uinet_in_addr_t listen_addr, uinet_in_port_t listen_port, int verbose)
{
	struct proxy_context *proxy = NULL;
	struct uinet_socket *listener = NULL;
	int optlen, optval;
	int error;

	error = uinet_socreate(UINET_PF_INET, &listener, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("Listen socket creation failed (%d)\n", error);
		goto fail;
	}
	
	if ((error = uinet_make_socket_promiscuous(listener, client_fib))) {
		printf("Failed to make listen socket promiscuous (%d)\n", error);
		goto fail;
	}

	uinet_sosetnonblocking(listener, 1);

	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_NODELAY, &optval, optlen)))
		goto fail;

	proxy = proxy_alloc(10000);
	if (NULL == proxy)
		goto fail;

	if ((error = uinet_synfilter_install(listener, proxy_syn_filter, proxy))) {
		printf("Listen socket SYN filter install failed (%d)\n", error);
		goto fail;
	}
	
	uinet_soupcall_set(listener, UINET_SO_RCV, listener_upcall, proxy);
	
	if ((error = uinet_setl2info2(listener, NULL, NULL, NULL, 0, -1))) {
		printf("Listen socket L2 info set failed (%d)\n", error);
		goto fail;
	}

	proxy->listener = listener;
	proxy->verbose = verbose;
	proxy->client_fib = client_fib;
	proxy->server_fib = server_fib;

	pthread_create(&proxy->thread, NULL, proxy_event_loop, proxy);

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

	return (proxy);

fail:
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
	char *listen_addr = NULL;
	int listen_port = -1;
	int verbose = 0;
	int i;
	int error;

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
		printf("Specify at least %u interfaces\n", MIN_IFS);
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
	
	for (i = 0; i < num_ifs; i++) {
		uinet_config_if(ifnames[i], UINET_IFTYPE_NETMAP, i + 1, 0);
	}

	uinet_init(1, 128*1024, 0);

	for (i = 0; i < num_ifs; i++) {
		error = uinet_interface_up(ifnames[i], 0, 1);
		if (0 != error) {
			printf("Failed to bring up interface %s (%d)\n", ifnames[i], error);
		}
	}

	struct proxy_context *proxy;

	struct uinet_in_addr addr;
	if (uinet_inet_pton(UINET_AF_INET, listen_addr, &addr) <= 0) {
		printf("Malformed address %s\n", listen_addr);
		return (1);
	}

	proxy = create_proxy(1, 2,
			     addr.s_addr, listen_port,
			     verbose);

	while (1) {
		sleep(1);
	}

	return (0);
}
