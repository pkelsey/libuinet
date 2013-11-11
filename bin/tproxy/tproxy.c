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

	bucket = &t->buckets[splice_table_hash(t,
					       server_sin->sin_addr.s_addr, server_sin->sin_port,
					       client_sin->sin_addr.s_addr, client_sin->sin_port)];
	
	TAILQ_INSERT_HEAD(bucket, splice, splice_table);
}


static void
splice_table_remove(struct splice_table *t, struct splice_context *splice)
{
	struct splice_table_bucket *bucket;
	struct uinet_sockaddr_in *client_sin = (struct uinet_sockaddr_in *)splice->client_addr;
	struct uinet_sockaddr_in *server_sin = (struct uinet_sockaddr_in *)splice->server_addr;
	
	bucket = &t->buckets[splice_table_hash(t,
					       server_sin->sin_addr.s_addr, server_sin->sin_port,
					       client_sin->sin_addr.s_addr, client_sin->sin_port)];
	
	TAILQ_REMOVE(bucket, splice, splice_table);
}


static struct splice_context *
splice_table_lookup(struct splice_table *t, uinet_in_addr_t laddr, uinet_in_port_t lport, uinet_in_addr_t faddr, uinet_in_port_t fport)
{
	struct splice_table_bucket *bucket;
	struct splice_context *splice;

	bucket = &t->buckets[splice_table_hash(t, laddr, lport, faddr, fport)];
	
	TAILQ_FOREACH(splice, bucket, splice_table) {
		struct uinet_sockaddr_in *client_sin = (struct uinet_sockaddr_in *)splice->client_addr;
		struct uinet_sockaddr_in *server_sin = (struct uinet_sockaddr_in *)splice->server_addr;

		if ((client_sin->sin_addr.s_addr == faddr) &&
		    (client_sin->sin_port == fport) &&
		    (server_sin->sin_addr.s_addr == laddr) &&
		    (server_sin->sin_port == lport)) {
			return (splice);
		}
	}

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
conn_established(struct uinet_socket *so, void *arg, int waitflag)
{
	struct connection_context *conn = (struct connection_context *)arg;

	if (conn->splice->proxy->verbose > 1)
		printf("conn_established\n");

	event_send(conn->eq, &conn->connected);

	uinet_soupcall_set(so, UINET_SO_RCV, proxy_conn_rcv, conn);

	proxy_conn_rcv(so, conn, waitflag);

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

	so = uinet_soaccept(head, &sa);
	if (NULL == so)
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

	uinet_soupcall_set(so, UINET_SO_RCV, conn_established, &splice->client);

out:
	if (sa)
		uinet_free_sockaddr(sa);

	return (UINET_SU_OK);
}


static struct uinet_socket *
create_socket(unsigned int listen, unsigned int fib,
	      const char *local_mac, const char *foreign_mac,
	      const uint32_t *vlan_stack, int vlan_stack_depth,
	      uinet_api_synfilter_callback_t synfilter_cb, void *synfilter_cb_arg,
	      int (*upcall)(struct uinet_socket *, void *, int), void *upcall_arg)
{
	int error;
	struct uinet_socket *so;
#define MAX_TAGS 16
	uint32_t tags[16];
	int i;
	unsigned int optval, optlen;
	uint8_t foreign_mac_bytes[6];
	uint8_t local_mac_bytes[6];

	error = uinet_socreate(UINET_PF_INET, &so, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("Socket creation failed (%d)\n", error);
		return (NULL);
	}
	
	if ((error = uinet_make_socket_promiscuous(so, fib))) {
		printf("Failed to make socket promiscuous (%d)\n", error);
		goto err;
	}

	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(so, UINET_IPPROTO_TCP, UINET_TCP_NODELAY, &optval, optlen)))
		goto err;

	if ((error = uinet_mac_aton(foreign_mac, foreign_mac_bytes)))
		goto err;
	
	if ((error = uinet_mac_aton(local_mac, local_mac_bytes)))
		goto err;

	if (listen) {
		if (synfilter_cb) {
			if ((error = uinet_synfilter_install(so, synfilter_cb, synfilter_cb_arg))) {
				printf("Socket SYN filter install failed (%d)\n", error);
				goto err;
			}
		}
		
		uinet_sosetnonblocking(so, 1);
	}		

	uinet_soupcall_set(so, UINET_SO_RCV, upcall, upcall_arg);
	
	if (vlan_stack_depth > MAX_TAGS) {
		vlan_stack_depth = MAX_TAGS;
	}

	/* XXX assuming 802.1ad/802.1q */
	for (i = 0; i < vlan_stack_depth; i++) {
		uint32_t ethertype;
		
		/* this is standards compliant to two levels, questionable beyond that */
		if ((vlan_stack_depth - 1) == i) ethertype = 0x8100;
		else ethertype = 0x88a8;
		
		tags[i] = htonl((ethertype << 16) | vlan_stack[i]);
	}

	if ((error = uinet_setl2info(so, local_mac_bytes, foreign_mac_bytes, tags, htonl(0x00000fff), vlan_stack_depth))) {
		printf("Socket SO_L2INFO set failed (%d)\n", error);
		goto err;
	}

	return (so);

 err:
	uinet_soclose(so);
	return (NULL);
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

	uinet_synfilter_get_conninfo(cookie, &inc);

	if (NULL == splice_table_lookup(&proxy->splicetab,
					inc.inc_ie.ie_laddr.s_addr, inc.inc_ie.ie_lport,
					inc.inc_ie.ie_faddr.s_addr, inc.inc_ie.ie_fport)) {

		error = uinet_socreate(UINET_PF_INET, &so, UINET_SOCK_STREAM, 0);
		if (0 != error) {
			printf("Socket creation failed (%d)\n", error);
			goto err;
		}
	
		if ((error = uinet_make_socket_promiscuous(so, proxy->server_fib))) {
			printf("Failed to make socket promiscuous (%d)\n", error);
			goto err;
		}

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

		uinet_synfilter_get_l2info(cookie, &l2i);
		if ((error = uinet_setl2info(so, l2i.inl2i_foreign_addr, l2i.inl2i_local_addr,
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

		uinet_soupcall_set(so, UINET_SO_RCV, conn_established, &splice->server);

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
		if ((error = uinet_soconnect(so, (struct uinet_sockaddr *)&sin))) {
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
	struct proxy_context *proxy;
	struct uinet_socket *listener = NULL;
	int error;

	proxy = proxy_alloc(10000);
	if (NULL == proxy)
		goto fail;

	listener = create_socket(1, client_fib,
				 NULL, NULL,
				 NULL, -1,
				 proxy_syn_filter, proxy,
				 listener_upcall, proxy);
	if (NULL == listener)
		goto fail;

	proxy->listener = listener;
	proxy->verbose = verbose;
	proxy->client_fib =  client_fib;
	proxy->server_fib =  server_fib;

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
	char ch;
	char *progname = argv[0];
#define MIN_IFS 2
#define MAX_IFS 2
	int num_ifs = 0;
	char *ifnames[MAX_IFS];
	char *listen_addr = NULL;
	int listen_port = -1;
	int verbose = 0;
	int i;

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
		uinet_config_if(ifnames[i], 0, i + 1);
	}

	uinet_init(1, 128*1024);

	uinet_config_blackhole(UINET_BLACKHOLE_TCP_ALL);
	uinet_config_blackhole(UINET_BLACKHOLE_UDP_ALL);

	for (i = 0; i < num_ifs; i++) {
		uinet_interface_up(ifnames[i], 0);
	}

	struct proxy_context *proxy;

	proxy = create_proxy(1, 2,
			     uinet_inet_addr(listen_addr), listen_port,
			     verbose);

	while (1) {
		sleep(1);
	}

	return (0);
}
