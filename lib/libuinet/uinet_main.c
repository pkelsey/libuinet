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

#define pause user_pause
#include <unistd.h>
#undef pause

#include <time.h>

#include <uinet_sys/param.h>
#include <uinet_sys/kernel.h>
#include <uinet_sys/systm.h>
#include <uinet_sys/file.h>
#include <uinet_sys/limits.h>
#include <uinet_sys/malloc.h>
#include <uinet_sys/kthread.h>
#include <uinet_sys/lock.h>
#include <uinet_sys/mutex.h>
#include <uinet_sys/proc.h>
#include <uinet_sys/protosw.h>
#include <uinet_sys/socket.h>
#include <uinet_sys/socketvar.h>
#include <uinet_sys/sockio.h>
#include <uinet_sys/sysctl.h>
#include <uinet_sys/uio.h>

#include <uinet_net/if.h>
#include <uinet_netinet/in.h>
#include <uinet_netinet/in_promisc.h>

#include "uinet_api.h"
#include "uinet_config.h"

extern in_addr_t inet_addr(const char *cp);


/* 12 bits, 0 and 4095 are reserved */
#define MAX_VLANS_PER_TAG 4094


typedef enum {
	CS_INIT,
	CS_RETRY,
	CS_CONNECTING,
	CS_CONNECTED,
	CS_SEND,
	CS_WAIT_REPLY,
	CS_DISCONNECTING,
	CS_DONE
} conn_state_t;

struct server_context;

struct server_conn {
	TAILQ_ENTRY(server_conn) server_queue;
	int active;
	struct server_context *server;
	struct socket *so;
	conn_state_t conn_state;
	struct sockaddr_in local_sin;
	struct sockaddr_in remote_sin;
};

enum whichq { Q_NONE, Q_CONN, Q_SEND };

struct client_conn {
	TAILQ_ENTRY(client_conn) connsend_queue;
	TAILQ_ENTRY(client_conn) active_queue;
	enum whichq qid;
	unsigned long long sends;
	unsigned long long recvs;
	struct client_context *client;
	struct socket *so;
	int active;
	conn_state_t conn_state;
	conn_state_t last_conn_state;
	unsigned int fib;
	char *local_mac;
	char *foreign_mac;
	uint32_t vlan_stack[IN_L2INFO_MAX_TAGS];
	int vlan_stack_depth;
	in_addr_t local_addr;
	uint16_t local_port;
	in_addr_t foreign_addr;
	uint16_t foreign_port;
	struct sockaddr_in local_sin;
	struct sockaddr_in remote_sin;
	unsigned int rcv_len;
	char connstr[80];
};


TAILQ_HEAD(client_conn_listhead, client_conn);

struct client_context {
	unsigned int id;
	struct client_conn_listhead connect_queue;
	struct client_conn_listhead send_queue;
	struct client_conn_listhead active_queue;
	struct mtx active_queue_lock;
	unsigned int outstanding;
	int notify;
	int interleave;
	uint8_t wirebuf[1024];
	uint8_t verifybuf[1024];
	unsigned int connecting;
	unsigned int connected;
	unsigned int disconnecting;
	unsigned int retrying;
	unsigned int connects;
	unsigned int disconnects;
	unsigned int retries;
};


TAILQ_HEAD(server_conn_listhead, server_conn);

struct server_context {
	unsigned int id;
	struct server_conn_listhead queue;
	struct mtx lock;
	int notify;
	uint8_t copybuf[2048];
};

#define TEST_TYPE_ACTIVE	0
#define TEST_TYPE_PASSIVE	1

struct test_config {
	unsigned int num;
	char *name;
	char *ifname;
	unsigned int type;
	unsigned int fib;
	char *local_ip_start;
	unsigned int num_local_ips;
	uint16_t local_port_start;
	uint16_t num_local_ports;
	char *foreign_ip_start;
	unsigned int num_foreign_ips;
	uint16_t foreign_port_start;
	uint16_t num_foreign_ports;
	char *local_mac;
	char *foreign_mac;
	uint32_t vlan_start;
        unsigned int num_vlans;
	int vlan_stack_depth;
	char * syn_filter_name;
	unsigned int notify;
};

static int dobind(struct socket *so, in_addr_t addr, in_port_t port);
static int doconnect(struct socket *so, in_addr_t addr, in_port_t port);
static struct socket * create_test_socket(unsigned int test_type, unsigned int fib,
					  const char *local_mac, const char *foreign_mac,
					  const uint32_t *vlan_stack, int vlan_stack_depth,
					  const char *syn_filter_name, void *upcall_arg);




static void
loopback_thread(void *arg)
{
	struct server_context *server = (struct server_context *)arg;
	struct server_conn *sc;
	struct socket *so;
	struct iovec iov;
	struct uio uio;
	int error;
	ssize_t len;
	char buf1[32], buf2[32];


	while(1) {
		mtx_lock(&server->lock);
		while (NULL == (sc = TAILQ_FIRST(&server->queue))) {
			mtx_sleep(&server->queue, &server->lock, 0, "wsvrlk", 0);
		}
		TAILQ_REMOVE(&server->queue, sc, server_queue);
		sc->active = 0;
		mtx_unlock(&server->lock);

		if (CS_DONE == sc->conn_state)
			continue;

		so = sc->so;

		iov.iov_base = server->copybuf;
		iov.iov_len = sizeof(server->copybuf);
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = sizeof(server->copybuf);
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = curthread;
		error = soreceive(so, NULL, &uio, NULL, NULL, NULL);
		if ((0 != error) && (EAGAIN != error)) {
			if (ECONNRESET != error) {
				printf("loopback_thread: soreceive failed %d\n", error);
			}
			len = 0;
		} else {
			len = sizeof(server->copybuf) - uio.uio_resid;
			if (len) {
				iov.iov_base = server->copybuf;
				iov.iov_len = sizeof(server->copybuf);
				uio.uio_iov = &iov;
				uio.uio_iovcnt = 1;
				uio.uio_offset = 0;
				uio.uio_resid = len;
				uio.uio_rw = UIO_WRITE;
				error = sosend(so, NULL, &uio, NULL, NULL, 0, curthread);
				if (0 != error) {
					printf("loopback_thread: sosend failed %d\n", error);
				}
			}
		}
		
		if ((0 == len) && (SBS_CANTRCVMORE & so->so_rcv.sb_state)) {
			if (server->notify) {
				printf("loopback_thread: connection to %s:%u from %s:%u closed\n",
				       inet_ntoa_r(sc->local_sin.sin_addr, buf1), ntohs(sc->local_sin.sin_port),
				       inet_ntoa_r(sc->remote_sin.sin_addr, buf2), ntohs(sc->remote_sin.sin_port));
			}
			sc->conn_state = CS_DONE;
		}
	}

	mtx_destroy(&server->lock);
	free(server, M_DEVBUF);
}


static int
server_conn_rcv(struct socket *so, void *arg, int waitflag)
{
	struct server_conn *sc = (struct server_conn *)arg;

	mtx_lock(&sc->server->lock);
	if (0 == sc->active) {
		sc->active = 1;
		TAILQ_INSERT_TAIL(&sc->server->queue, sc, server_queue);
		wakeup(&sc->server->queue);
	}
	mtx_unlock(&sc->server->lock);

	return (SU_OK);
}


/*
 * This will be called after the ACK segment from the peer is processed, at
 * which point the peer address information will be populated in the
 * socket's inpcb.
 */
static int
server_conn_established(struct socket *so, void *arg, int waitflag)
{
	struct server_conn *sc = (struct server_conn *)arg;
	struct sockaddr_in *sin;
	int error;

	sin = NULL;
	error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, (struct sockaddr **)&sin);
	if (error) {
		printf("Error getting peer address %d\n", error);
	}
	
	if (sin) {
		memcpy(&sc->remote_sin, sin, sizeof(struct sockaddr_in));
		free(sin, M_SONAME);
	}

	sin = NULL;
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, (struct sockaddr **)&sin);
	if (error) {
		printf("Error getting local address %d\n", error);
	}
	
	if (sin) {
		memcpy(&sc->local_sin, sin, sizeof(struct sockaddr_in));
		free(sin, M_SONAME);
	}
	
	sc->conn_state = CS_CONNECTED;

	if (sc->server->notify) {
		char buf1[32], buf2[32];
		printf("loopback_thread: connection to %s:%u from %s:%u established\n",
		       inet_ntoa_r(sc->local_sin.sin_addr, buf1), ntohs(sc->local_sin.sin_port),
		       inet_ntoa_r(sc->remote_sin.sin_addr, buf2), ntohs(sc->remote_sin.sin_port));
	}

	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, server_conn_rcv, sc);
	SOCKBUF_UNLOCK(&so->so_rcv);

	server_conn_rcv(so, arg, waitflag);

	return (SU_OK);
}


static int
server_upcall(struct socket *head, void *arg, int waitflag)
{
	struct socket *so;
	struct sockaddr *sa;
	struct server_conn *sc;
	struct server_context *server = arg;
	int error;

	ACCEPT_LOCK();
	if (TAILQ_EMPTY(&head->so_comp)) {
		ACCEPT_UNLOCK();
		printf("head->so_comp empty\n");
		goto out;
	}

	so = TAILQ_FIRST(&head->so_comp);
	KASSERT(!(so->so_qstate & SQ_INCOMP), ("server_upcall: so SQ_INCOMP"));
	KASSERT(so->so_qstate & SQ_COMP, ("server_upcall: so not SQ_COMP"));

	/*
	 * Before changing the flags on the socket, we have to bump the
	 * reference count.  Otherwise, if the protocol calls sofree(),
	 * the socket will be released due to a zero refcount.
	 */
	SOCK_LOCK(so);			/* soref() and so_state update */
	soref(so);			/* socket came from sonewconn() with an so_count of 0 */

	TAILQ_REMOVE(&head->so_comp, so, so_list);
	head->so_qlen--;
	so->so_state |= (head->so_state & SS_NBIO);
	so->so_qstate &= ~SQ_COMP;
	so->so_head = NULL;

	SOCK_UNLOCK(so);
	ACCEPT_UNLOCK();

	sa = NULL;
	error = soaccept(so, &sa);
	if (error) {
		soclose(so);
		goto out;
	}

	sc = malloc(sizeof(struct server_conn), M_DEVBUF, M_WAITOK | M_ZERO);
	if (NULL == sc) {
		soclose(so);
		goto out;
	}
	
	sc->so = so;
	sc->conn_state = CS_INIT;
	sc->server = server;

	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, server_conn_established, sc);
	SOCKBUF_UNLOCK(&so->so_rcv);

out:
	if (sa)
		free(sa, M_SONAME);

	return (SU_OK);
}


static int
client_issue(struct client_context *client, struct client_conn *cc)
{
	int error = 0;
	int len;
	struct iovec iov;
	struct uio uio;


	switch (cc->conn_state) {
	case CS_INIT:
	case CS_RETRY:
		if (cc->so) {
			if (client->notify) printf("%s CLOSING -> RETRYING\n", cc->connstr);
			SOCKBUF_LOCK(&cc->so->so_rcv);
			soupcall_clear(cc->so, SO_RCV);
			SOCKBUF_UNLOCK(&cc->so->so_rcv);
			soclose(cc->so);
		}
		

		if (client->notify) printf("%s CONNECTING\n", cc->connstr);

		TAILQ_REMOVE(&client->connect_queue, cc, connsend_queue);
		cc->qid = Q_NONE;

		cc->so = create_test_socket(TEST_TYPE_ACTIVE, cc->fib,
					    cc->local_mac, cc->foreign_mac,
					    cc->vlan_stack, cc->vlan_stack_depth,
					    NULL, cc);
		if (NULL == cc->so) {
			printf("socket create failed\n");
			error = EINVAL;
		} else {
			if ((error = dobind(cc->so, cc->local_addr, cc->local_port))) {
				printf("dobind failed\n");
			} else {
				if ((error = doconnect(cc->so, cc->foreign_addr, cc->foreign_port))) {
					printf("doconnect failed\n");
				}
			}
		}

		if (!error) {
			client->connecting++;
			cc->conn_state = CS_CONNECTING;
		} else {
			cc->conn_state = CS_RETRY;
			TAILQ_INSERT_TAIL(&client->connect_queue, cc, connsend_queue);
			cc->qid = Q_CONN;
		}
		break;

	case CS_SEND:
		TAILQ_REMOVE(&client->send_queue, cc, connsend_queue);
		cc->qid = Q_NONE;

		cc->sends++;

		len = snprintf(client->wirebuf, sizeof(client->wirebuf), "%s %llu", cc->connstr, cc->sends);
		cc->rcv_len = len >= sizeof(client->wirebuf) - 1 ? sizeof(client->wirebuf) : len + 1;

		if (client->notify > 1) printf("%s sending %u bytes\n", cc->connstr, cc->rcv_len);
		

		iov.iov_base = client->wirebuf;
		iov.iov_len = cc->rcv_len;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = iov.iov_len;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_WRITE;
		uio.uio_td = curthread;
		if ((error = sosend(cc->so, NULL, &uio, NULL, NULL, 0, curthread))) {
			printf("verify_thread: sosend failed %d\n", error);
		}

		if (!error) {
			cc->conn_state = CS_WAIT_REPLY;
		} else {
			cc->conn_state = CS_RETRY;
			TAILQ_INSERT_TAIL(&client->connect_queue, cc, connsend_queue);
			cc->qid = Q_CONN;
		}

		break;
	default:
		break;
	}

	return error;
}



static int
handle_disconnect(struct client_context *client, struct client_conn *cc, unsigned int state_mask)
{

	if ((cc->so->so_state & SS_ISDISCONNECTED) & state_mask) {
		if (client->notify) printf("%s DISCONNECTED\n", cc->connstr);
		cc->conn_state = CS_RETRY;
		client->connected--;
		
		switch (cc->qid) {
		case Q_CONN:
			TAILQ_REMOVE(&client->connect_queue, cc, connsend_queue);
			break;
		case Q_SEND:
			TAILQ_REMOVE(&client->send_queue, cc, connsend_queue);
			break;
		default:
			client->outstanding--;
			break;
		}
		TAILQ_INSERT_TAIL(&client->connect_queue, cc, connsend_queue);
		cc->qid = Q_CONN;
	} else if ((cc->so->so_state & SS_ISDISCONNECTING) & state_mask) {
		if (client->notify) printf("%s DISCONNECTING\n", cc->connstr);
		cc->conn_state = CS_DISCONNECTING;
	} else {
		return (0);
	}

	return (1);
}



static void
verify_thread(void *arg)
{
	struct client_context *client = (struct client_context *)arg;
	struct client_conn *cc, *cctmp;
	struct socket *so;
	struct iovec iov;
	struct uio uio;
	int error;
	unsigned int pass = 0, fail = 0;
	unsigned int max_outstanding = 1024;
	unsigned int max_connects_per_period = 1500;
	struct timespec connect_rate_limit_period = { 0, 100 * 1000 * 1000 };
	unsigned int connects_in_last_period;
	unsigned int sends_in_last_period;
	unsigned int last_connected;
	struct timespec this_time, elapsed_time;
	struct timespec last_print_time;
	struct timespec last_conn_rate_limit_time;

	client->outstanding = 0;
	connects_in_last_period = 0;
	sends_in_last_period = 0;
	last_connected = 0;

	clock_gettime(CLOCK_REALTIME, &this_time);
	last_conn_rate_limit_time = last_print_time = this_time;

	while(1) {
		clock_gettime(CLOCK_REALTIME, &this_time);

		elapsed_time = this_time;
		timespecsub(&elapsed_time, &last_print_time);
		if (elapsed_time.tv_sec >= 5) {
			printf("id %3u: outstanding=%u connecting=%u connected=%u pass=%u fail=%u connects/sec=%u sends/sec=%u\n",
			       client->id, client->outstanding, client->connecting, client->connected, pass, fail,
			       client->connected > last_connected ? (client->connected - last_connected) / (unsigned int)elapsed_time.tv_sec : 0,
			       sends_in_last_period / (unsigned int)elapsed_time.tv_sec);

			last_connected = client->connected;
			sends_in_last_period = 0;
			last_print_time = this_time;
		}

		elapsed_time = this_time;
		timespecsub(&elapsed_time, &last_conn_rate_limit_time);
		if (timespeccmp(&elapsed_time, &connect_rate_limit_period, >)) {
			connects_in_last_period = 0;
			last_conn_rate_limit_time = this_time;
		}		

		TAILQ_FOREACH_SAFE(cc, &client->connect_queue, connsend_queue, cctmp) {
			if ((client->outstanding == max_outstanding) ||
			    (connects_in_last_period >= max_connects_per_period))
				break;
			
			if (0 == client_issue(client, cc)) {
				client->outstanding++;
				connects_in_last_period++;
			}
		}	
		
		TAILQ_FOREACH_SAFE(cc, &client->send_queue, connsend_queue, cctmp) {
			if (client->outstanding == max_outstanding)
				break;
			
			if (0 == client_issue(client, cc)) {
				client->outstanding++;
				sends_in_last_period++;
			}
		}	
		
		mtx_lock(&client->active_queue_lock);
		while (NULL == TAILQ_FIRST(&client->active_queue))
			mtx_sleep(&client->active_queue, &client->active_queue_lock, 0, "wcaqlk", 0);
		mtx_unlock(&client->active_queue_lock);
	

		while (1) {
			mtx_lock(&client->active_queue_lock);
			cc = TAILQ_FIRST(&client->active_queue);
			if (cc) {
				TAILQ_REMOVE(&client->active_queue, cc, active_queue);
				cc->active = 0;
			}
			mtx_unlock(&client->active_queue_lock);

			if (NULL == cc) {
				break;
			}

			so = cc->so;

			switch (cc->conn_state) {
			case CS_CONNECTING:
				client->connecting--;
				if (0 == handle_disconnect(client, cc,
							   SS_ISDISCONNECTING | SS_ISDISCONNECTED)) {

					if (client->notify) printf("%s CONNECTED\n", cc->connstr);
					cc->conn_state = CS_SEND;
					client->connected++;
					client->outstanding--;
					
					TAILQ_INSERT_TAIL(&client->send_queue, cc, connsend_queue);
					cc->qid = Q_SEND;
				}
				break;
			case CS_SEND:
				handle_disconnect(client, cc,
						  SS_ISDISCONNECTING | SS_ISDISCONNECTED);
				break;
			case CS_WAIT_REPLY:
				if (0 == handle_disconnect(client, cc,
							   SS_ISDISCONNECTING | SS_ISDISCONNECTED)) {
					int ready;

					SOCKBUF_LOCK(&so->so_rcv);
					ready = (so->so_rcv.sb_cc >= cc->rcv_len);
					SOCKBUF_UNLOCK(&so->so_rcv);
					
					if (ready) {
						cc->recvs++;

						iov.iov_base = client->wirebuf;
						iov.iov_len = cc->rcv_len;
						uio.uio_iov = &iov;
						uio.uio_iovcnt = 1;
						uio.uio_offset = 0;
						uio.uio_resid = iov.iov_len;
						uio.uio_segflg = UIO_SYSSPACE;
						uio.uio_rw = UIO_READ;
						uio.uio_td = curthread;
						error = soreceive(so, NULL, &uio, NULL, NULL, NULL);
						if (0 != error) {
							printf("verify_thread: soreceive failed %d\n", error);
							cc->conn_state = CS_RETRY;
						} else {
							if (0 != strncmp(cc->connstr, client->wirebuf, strlen(cc->connstr))) {
								printf("verification failed\n");
								cc->conn_state = CS_RETRY;
								fail++;
							} else {
								cc->conn_state = CS_SEND;
								pass++;
							}
						}

						client->outstanding--;

						if (CS_SEND == cc->conn_state) {
							TAILQ_INSERT_TAIL(&client->send_queue, cc, connsend_queue);
							cc->qid = Q_SEND;
						} else {
							TAILQ_INSERT_TAIL(&client->connect_queue, cc, connsend_queue);
							cc->qid = Q_CONN;
						}
					} else {
						if (client->notify) printf("NOT READY\n");
					}
				}
				break;
			case CS_DISCONNECTING:
				handle_disconnect(client, cc, SS_ISDISCONNECTED);
				break;
			default:
				printf("connection active in unexpected state %u\n", cc->conn_state);
				break;
				
			}
		}
	}

	mtx_destroy(&client->active_queue_lock);
	free(client, M_DEVBUF);
}


static int
client_upcall(struct socket *so, void *arg, int waitflag)
{
	struct client_conn *cc = arg;
	struct client_context *client = cc->client;

	mtx_lock(&client->active_queue_lock);
	if (!cc->active) {
		cc->active = 1;
		TAILQ_INSERT_TAIL(&client->active_queue, cc, active_queue);
		wakeup_one(&client->active_queue);
	}
	mtx_unlock(&client->active_queue_lock);

	return (SU_OK);
}


static int
setopt_int(struct socket *so, int level, int opt, int val, const char *msg)
{
	int sopt_int;
	int error;

	sopt_int = val;
	error = so_setsockopt(so, level, opt, &sopt_int, sizeof(sopt_int));
	if (0 != error) {
		printf("Setting %s failed (%d)\n", msg ? msg : "socket option", error);
	}

	return (error);
}


static int
dobind(struct socket *so, in_addr_t addr, in_port_t port)
{
	struct sockaddr_in sin;
	struct thread *td = curthread;
	int error;

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	sin.sin_port = htons(port);
	error = sobind(so, (struct sockaddr *)&sin, td);
	if (0 != error) {
		printf("Bind to %s:%u failed (%d)\n", inet_ntoa(sin.sin_addr), port, error);
	}

	return (error);
}


static int
doconnect(struct socket *so, in_addr_t addr, in_port_t port)
{
	struct sockaddr_in sin;
	struct thread *td = curthread;
	int error;

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = addr;
	sin.sin_port = htons(port);
	error = soconnect(so, (struct sockaddr *)&sin, td);
	if (0 != error) {
		printf("Connect to %s:%u failed (%d)\n", inet_ntoa(sin.sin_addr), port, error);
	}

	return (error);
}

#if 0
static void
print_macaddr(uint8_t *addr)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
	       addr[0],
	       addr[1],
	       addr[2],
	       addr[3],
	       addr[4],
	       addr[5]);
}


static void
print_l2info(const char *name, struct in_l2info *l2i)
{
	uint32_t i;
	struct in_l2tagstack *ts = &l2->inl2i;

	printf("%s.local_addr = ", name); print_macaddr(l2i->inl2i_local_addr); printf("\n");
	printf("%s.foreign_addr = ", name); print_macaddr(l2i->inl2i_foreign_addr); printf("\n");
	printf("%s.tags = %u\n", name, ts->inl2t_cnt);
	for (i = 0; i < ts->inl2t_cnt; i++) {
		printf("  tag %2u = 0x%08x\n", i, ts->inl2t_tags[i]);
	}
}
#endif

static int uinet_test_synf_callback(struct inpcb *inp, void *inst_arg, struct syn_filter_cbarg *arg)
{
	if (0 == strncmp("10.", inet_ntoa(arg->inc.inc_laddr), 3)) {
//		printf("ACCEPT\n");
//		printf("--------------------------------\n");
		return (SYNF_ACCEPT);
	}

//	printf("REJECT\n");
//	printf("--------------------------------\n");
	return (SYNF_REJECT);
}


static struct syn_filter synf_uinet_test = {
	"uinet_test",
	uinet_test_synf_callback,
	NULL,
	NULL
};

static moduledata_t synf_uinet_test_mod = {
	"uinet_test_synf",
	syn_filter_generic_mod_event,
	&synf_uinet_test
};

DECLARE_MODULE(synf_uinet_test, synf_uinet_test_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);


static int
mac_aton(const char *macstr, uint8_t *macout)
{

	unsigned int i;
	const char *p;
	char *endp;

	if ((NULL == macstr) || (macstr[0] == '\0')) {
		memset(macout, 0, ETHER_ADDR_LEN);
		return (0);
	}

	p = macstr;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		macout[i] = strtoul(p, &endp, 16);
		if ((endp != &p[2]) ||					/* two hex digits */
		    ((i < ETHER_ADDR_LEN - 1) && (*endp != ':')) ||	/* followed by ':', unless last pair */
		    ((i == ETHER_ADDR_LEN - 1) && (*endp != '\0'))) {	/* followed by '\0', if last pair */
			printf("malformed MAC address: %s\n", macstr);
			printf("p=%p *p=%c endp=%p *endp=%c\n", p, *p, endp, *endp);
			return (1);
		}
		p = endp + 1;
	}

	return (0);
}


/*
 * Convert a vlan number (i.e., the nth valid vlan) into a tag stack.
 * Visualize this as converting the vlan number to base MAX_VLANS_PER_TAG,
 * where each digit in that base starts at 1, and storing the most
 * signifcant digit at the lowest index in the stack.
 */
static void
vlan_number_to_tag_stack(unsigned int vlan_number, uint32_t *tag_stack, int tag_stack_depth)
{
	int i;

	if (tag_stack_depth > 0) {
		for (i = tag_stack_depth - 1; i >= 0; i--) {
			/* vlan id 0 and 4095 are reserved */
			tag_stack[i] = (vlan_number % MAX_VLANS_PER_TAG) + 1;
			vlan_number /= MAX_VLANS_PER_TAG;
		}
	}
}


static void
incr_vlan_tag_stack(uint32_t *tag_stack, int tag_stack_depth)
{
	int i;

	if (tag_stack_depth > 0) {
		tag_stack[tag_stack_depth - 1]++;
		for (i = tag_stack_depth - 1; i >= 0; i--) {
			if (tag_stack[i] > MAX_VLANS_PER_TAG) {
				tag_stack[i] -= MAX_VLANS_PER_TAG;
				if (i > 0) {
					tag_stack[i - 1]++;
				}
			}
		}
	}
}


static void
incr_in_addr_t(in_addr_t *inaddr)
{
	uint8_t *addr_parts = (uint8_t *)inaddr;
	
	// inaddr is in network byte order
	
	addr_parts[3]++;

	// avoid .255 and .0
	if ((255 == addr_parts[3]) || (0 == addr_parts[3])) {
		addr_parts[3] = 1;

		addr_parts[2]++;
		if (0 == addr_parts[2]) {
			addr_parts[1]++;
			if (0 == addr_parts[1]) {
				addr_parts[0]++;
			}
		}
	}
}


static void
incr_in_addr_t_n(in_addr_t *inaddr, unsigned int n)
{
	unsigned int i;
	
	for (i = 0; i < n; i++) {
		incr_in_addr_t(inaddr);
	}
}



static int
ip_range_str(char *buf, unsigned int bufsize, const char *ip_start, unsigned int nips,
	     unsigned int port_start, unsigned int nports)
{
	in_addr_t ip;
	struct in_addr inaddr;
	char ip_end[16];
	char port_end[8];
	char port_range[12];

	ip = inet_addr(ip_start);
	incr_in_addr_t_n(&ip, nips - 1);
	inaddr.s_addr = ip;
	inet_ntoa_r(inaddr, ip_end);

	snprintf(port_end, sizeof(port_end), "-%u", port_start + nports - 1);
	snprintf(port_range, sizeof(port_range), "%u%s",
		 port_start,
		 nports > 1 ? port_end : "");

	return (snprintf(buf, bufsize, "[%s:%s, %s:%s]",
			 ip_start,
			 port_range,
			 ip_end,
			 port_range));
}


static void
print_test_config(struct test_config *test)
{
	unsigned int num_tags;
	unsigned int tagnum;
	unsigned int local_length;
	unsigned int foreign_length;
	char local_ip_range[64];
	char foreign_ip_range[64];
	uint32_t vlan_tag_stack[IN_L2INFO_MAX_TAGS];

	printf("%2u ", test->num);

	local_length = ip_range_str(local_ip_range, sizeof(local_ip_range),
				    test->local_ip_start,
				    test->num_local_ips,
				    test->local_port_start,
				    test->num_local_ports);

	if (TEST_TYPE_PASSIVE == test->type) {

		printf("%-36s PASSIVE num_sockets=%-7u fib=%-2u  local_range=%s%*s nvlans=%-2d tag_range=",
		       test->name,
		       test->num_vlans * test->num_local_ips * test->num_local_ports,
		       test->fib,
		       local_ip_range,
		       58 - local_length,
		       "",
		       test->num_vlans);


		num_tags = (test->vlan_stack_depth < 0) ? 0 : test->vlan_stack_depth;

		vlan_number_to_tag_stack(test->vlan_start, vlan_tag_stack, test->vlan_stack_depth);
		printf("[");
		for(tagnum = 0; tagnum < num_tags; tagnum++) {
			printf(" %u", vlan_tag_stack[tagnum]);
		}
		printf(" ]...");

		vlan_number_to_tag_stack(test->vlan_start + test->num_vlans - 1, vlan_tag_stack, test->vlan_stack_depth);
		printf("[");
		for(tagnum = 0; tagnum < num_tags; tagnum++) {
			printf(" %u", vlan_tag_stack[tagnum]);
		}
		printf(" ]\n");
	} else {
		printf("%-36s ACTIVE  num_sockets=%-7u fib=%-2u  local_range=%s\n",
		       test->name,
		       test->num_vlans * test->num_local_ips * test->num_local_ports * test->num_foreign_ips * test->num_foreign_ports,
		       test->fib,
		       local_ip_range);

		foreign_length = ip_range_str(foreign_ip_range, sizeof(foreign_ip_range),
					      test->foreign_ip_start,
					      test->num_foreign_ips,
					      test->foreign_port_start,
					      test->num_foreign_ports);

		printf("%-36s                                      foreign_range=%s%*s nvlans=%-2d tag_range=",
		       "",
		       foreign_ip_range,
		       58 - foreign_length,
		       "",
		       test->num_vlans);

		num_tags = (test->vlan_stack_depth < 0) ? 0 : test->vlan_stack_depth;

		vlan_number_to_tag_stack(test->vlan_start, vlan_tag_stack, test->vlan_stack_depth);
		printf("[");
		for(tagnum = 0; tagnum < num_tags; tagnum++) {
			printf(" %u", vlan_tag_stack[tagnum]);
		}
		printf(" ]...");

		vlan_number_to_tag_stack(test->vlan_start + test->num_vlans - 1, vlan_tag_stack, test->vlan_stack_depth);
		printf("[");
		for(tagnum = 0; tagnum < num_tags; tagnum++) {
			printf(" %u", vlan_tag_stack[tagnum]);
		}
		printf(" ]\n");

		printf("%-36s                                          local_mac=%s\n",
		       "", test->local_mac);
		printf("%-36s                                        foreign_mac=%s\n",
		       "", test->foreign_mac);
	}

}


static struct socket *
create_test_socket(unsigned int test_type, unsigned int fib,
		   const char *local_mac, const char *foreign_mac,
		   const uint32_t *vlan_stack, int vlan_stack_depth,
		   const char *syn_filter_name, void *upcall_arg)
{
	int error;
	struct socket *so;
	struct thread *td = curthread;
	struct in_l2info l2i;
	struct in_l2tagstack *ts = &l2i.inl2i_tagstack;
	struct syn_filter_optarg synf;
	int i;

	error = socreate(PF_INET, &so, SOCK_STREAM, 0, td->td_ucred, td);
	if (0 != error) {
		printf("Promisc socket creation failed (%d)\n", error);
		return (NULL);
	}
	
	if ((error = setopt_int(so, SOL_SOCKET, SO_PROMISC, 1, "SO_PROMISC")))
		goto err;
	
	if ((error = setopt_int(so, SOL_SOCKET, SO_SETFIB, fib, "SO_SETFIB")))
		goto err;

	if ((error = setopt_int(so, SOL_SOCKET, SO_REUSEPORT, 1, "SO_REUSEPORT")))
		goto err;
	
	if ((error = setopt_int(so, IPPROTO_IP, IP_BINDANY, 1, "IP_BINDANY")))
		goto err;

	if ((error = setopt_int(so, IPPROTO_TCP, TCP_NODELAY, 1, "TCP_NODELAY")))
		goto err;

	memset(&l2i, 0, sizeof(l2i));
		
	if (TEST_TYPE_ACTIVE == test_type) {

		if ((error = mac_aton(foreign_mac, l2i.inl2i_foreign_addr)))
			goto err;
		
		if ((error = mac_aton(local_mac, l2i.inl2i_local_addr)))
			goto err;

		SOCKBUF_LOCK(&so->so_rcv);
		soupcall_set(so, SO_RCV, client_upcall, upcall_arg);
		SOCKBUF_UNLOCK(&so->so_rcv);
	} else {
		if (syn_filter_name && (*syn_filter_name != '\0')) {
			memset(&synf, 0, sizeof(synf));
			strlcpy(synf.sfa_name, syn_filter_name, SYNF_NAME_MAX);

			if ((error = so_setsockopt(so, IPPROTO_IP, IP_SYNFILTER, &synf, sizeof(synf)))) {
				printf("Promisc socket IP_SYNFILTER set failed (%d)\n", error);
				goto err;
			}
		}

		so->so_state |= SS_NBIO;

		if (vlan_stack_depth < 0) {
			l2i.inl2i_flags |= INL2I_TAG_ANY;
			vlan_stack_depth = 0;
		}
	
		SOCKBUF_LOCK(&so->so_rcv);
		soupcall_set(so, SO_RCV, server_upcall, upcall_arg);
		SOCKBUF_UNLOCK(&so->so_rcv);
	}

	ts->inl2t_cnt = vlan_stack_depth;

	/* XXX assuming 802.1ad/802.1q */
	for (i = 0; i < vlan_stack_depth; i++) {
		uint32_t ethertype;

		/* this is standards compliant to two levels, questionable beyond that */
		if ((vlan_stack_depth - 1) == i) ethertype = 0x8100;
		else ethertype = 0x88a8;

		ts->inl2t_tags[i] = htonl((ethertype << 16) | vlan_stack[i]);
	}
	ts->inl2t_mask = htonl(0x00000fff); 

	if ((error = so_setsockopt(so, SOL_SOCKET, SO_L2INFO, &l2i, sizeof(l2i)))) {
		printf("Promisc socket SO_L2INFO set failed (%d)\n", error);
		goto err;
	}


	return (so);

 err:
	soclose(so);
	return (NULL);
}


static unsigned int
min_tag_stack_depth(unsigned int first_vlan, unsigned int num_vlans)
{
	unsigned int depth = 0;
	unsigned int remaining_vlans = num_vlans;
	unsigned int residual;

	num_vlans += first_vlan - 1;
	do {
		residual = remaining_vlans % MAX_VLANS_PER_TAG;
		remaining_vlans /= MAX_VLANS_PER_TAG;

		depth++;
	} while (remaining_vlans > 1);

	if (remaining_vlans && residual) {
		depth++;
	}

	return (depth);
}



static int
run_test(struct test_config *test, int verbose)
{
	struct socket *so = NULL;
	struct thread *td = curthread;
	int error = 0;
	unsigned int socket_count;
	uint64_t max_vlans;
	unsigned int num_vlans;
	unsigned int vlan_num;
	uint32_t vlan_tag_stack[IN_L2INFO_MAX_TAGS];

	unsigned int num_local_addrs, num_local_ports;
	unsigned int local_addr_num, local_port_num;
	in_addr_t local_addr;
	in_port_t local_port;

	unsigned int num_foreign_addrs, num_foreign_ports;
	unsigned int foreign_addr_num, foreign_port_num;
	in_addr_t foreign_addr;
	in_port_t foreign_port;
	struct client_context *client = NULL;
	struct server_context *server = NULL;


	print_test_config(test);

	socket_count = 0;

	if (TEST_TYPE_ACTIVE == test->type) {
		client = malloc(sizeof(struct client_context), M_DEVBUF, M_WAITOK | M_ZERO);
		TAILQ_INIT(&client->connect_queue);
		TAILQ_INIT(&client->send_queue);
		TAILQ_INIT(&client->active_queue);
		mtx_init(&client->active_queue_lock, "clnqlk", NULL, MTX_DEF);
		client->id = test->num;
		client->notify = test->notify;
		client->interleave = 0;
	} else {
		server = malloc(sizeof(struct server_context), M_DEVBUF, M_WAITOK | M_ZERO);
		TAILQ_INIT(&server->queue);
		mtx_init(&server->lock, "svrqlk", NULL, MTX_DEF);
		server->id = test->num;
		server->notify = test->notify;

		if (kthread_add(loopback_thread, server, NULL, NULL, 0, 128*1024/PAGE_SIZE, "loopback_svr")) {
			mtx_destroy(&server->lock);
			free(server, M_DEVBUF);
			goto out;
		}
	}

	num_vlans = test->num_vlans < 1 ? 1 : test->num_vlans;

	max_vlans = 1;
	if (test->vlan_stack_depth > 0) {
		int i;

		for (i = 0; i < test->vlan_stack_depth; i++) {
			max_vlans *= MAX_VLANS_PER_TAG;
		}
		max_vlans -= test->vlan_start - 1;
	}

	if (num_vlans > max_vlans) {
		printf("Limiting number of VLANs to unique tag stack limit of %llu\n", (unsigned long long)max_vlans);
		num_vlans = max_vlans;
	}

	num_local_addrs = inet_addr(test->local_ip_start) == INADDR_ANY ? 1 : test->num_local_ips;
	num_local_ports = test->local_port_start == IN_PROMISC_PORT_ANY ? 1 : test->num_local_ports;

	vlan_number_to_tag_stack(test->vlan_start, vlan_tag_stack, test->vlan_stack_depth);

	for (vlan_num = 0; vlan_num < num_vlans; vlan_num++) {

		local_addr = inet_addr(test->local_ip_start);

		for (local_addr_num = 0; local_addr_num < num_local_addrs; local_addr_num++) {

			local_port = test->local_port_start;
			for (local_port_num = 0; local_port_num < num_local_ports; local_port_num++) {

				if (TEST_TYPE_ACTIVE == test->type) {
					num_foreign_addrs = test->num_foreign_ips;
					num_foreign_ports = test->num_foreign_ports;

					foreign_addr = inet_addr(test->foreign_ip_start);

					for (foreign_addr_num = 0; foreign_addr_num < num_foreign_addrs; foreign_addr_num++) {

						foreign_port = test->foreign_port_start;
						for (foreign_port_num = 0; foreign_port_num < num_foreign_ports; foreign_port_num++) {
							struct client_conn *cc;
							struct in_addr laddr, faddr;
							char buf1[16], buf2[16];
							int size, remaining, i;

							cc = malloc(sizeof(struct client_conn), M_DEVBUF, M_WAITOK | M_ZERO);
							if (NULL == cc) {
								error = ENOMEM;
								goto out;
							}
						
							cc->conn_state = CS_INIT;
							cc->client = client;
							cc->local_addr = local_addr;
							cc->local_port = local_port;
							cc->foreign_addr = foreign_addr;
							cc->foreign_port = foreign_port;
							cc->fib = test->fib;
							cc->local_mac = test->local_mac;
							cc->foreign_mac = test->foreign_mac;
							if (test->vlan_stack_depth > 0) {
								memcpy(cc->vlan_stack, vlan_tag_stack, test->vlan_stack_depth * sizeof(vlan_tag_stack[0]));
							}
							cc->vlan_stack_depth = test->vlan_stack_depth;


							remaining = sizeof(cc->connstr);
							
							laddr.s_addr = cc->local_addr;
							faddr.s_addr = cc->foreign_addr;
							size = snprintf(cc->connstr, remaining, "%u: %s:%u -> %s:%u vlans=[ ", 
									cc->fib,
									inet_ntoa_r(laddr, buf1), cc->local_port,
									inet_ntoa_r(faddr, buf2), cc->foreign_port);
							
							for (i = 0; i < cc->vlan_stack_depth; i++) {
								remaining = size > remaining ? 0 : remaining - size;
								if (remaining) {
									size = snprintf(&cc->connstr[sizeof(cc->connstr) - remaining],
											remaining, "%u ", cc->vlan_stack[i]);  
								}
							}
							remaining = size > remaining ? 0 : remaining - size;
							if (remaining) {
								snprintf(&cc->connstr[sizeof(cc->connstr) - remaining], remaining, "]");	
							}

							socket_count++;

							cc->qid = Q_CONN;
							TAILQ_INSERT_TAIL(&cc->client->connect_queue, cc, connsend_queue);

							foreign_port++;
						}

						incr_in_addr_t(&foreign_addr);
					}
				} else {
					so = create_test_socket(TEST_TYPE_PASSIVE, test->fib,
								NULL, NULL,
								vlan_tag_stack, test->vlan_stack_depth,
								test->syn_filter_name, server);
					if (NULL == so)
						goto out;

					socket_count++;					

					if ((error = dobind(so, local_addr, local_port)))
						goto out;

					if ((error = solisten(so, SOMAXCONN, td))) {
						printf("Promisc socket listen failed (%d)\n", error);
						goto out;
					}

					so = NULL;
				}

				local_port++;
			}

			incr_in_addr_t(&local_addr);
		}

		incr_vlan_tag_stack(vlan_tag_stack, test->vlan_stack_depth);
	}

	printf("created %u sockets\n", socket_count);

	if (TEST_TYPE_ACTIVE == test->type) {
		if (kthread_add(verify_thread, client, NULL, NULL, 0, 128*1024/PAGE_SIZE, "verify_cln")) {
			printf("Failed to create client thread\n");
			mtx_destroy(&client->active_queue_lock);
			free(client, M_DEVBUF);
			goto out;
		}
	}

out:
	if (so) 
		soclose(so);

	return (error);
}



static void
usage(const char *progname)
{

	printf("Usage: %s [options]\n", progname);
	printf("    -a ipaddr            set local start IP address\n");
	printf("    -A ipaddr            set foreign start IP address\n");
	printf("    -b num               set number of local IP addresses\n");
	printf("    -B num               set number of foreign IP addresses\n");
	printf("    -f                   set fib\n");
	printf("    -h                   show usage\n");
	printf("    -i ifname            specify network interface\n");
	printf("    -l                   list test defaults\n");
	printf("    -m macaddr           set local MAC address\n");
	printf("    -M macaddr           set foreign MAC address\n");
	printf("    -n                   do not run tests\n");
	printf("    -N name              set test name\n");
	printf("    -p port              set local port start\n");
	printf("    -P port              set foreign port start\n");
	printf("    -q num               set number of local ports\n");
	printf("    -Q num               set number of foreign ports\n");
	printf("    -t active|passive	 set test type\n");
	printf("    -T depth             set tag stack depth\n");
	printf("    -v                   be verbose\n");
	printf("    -V num               set number of vlans\n");

}


extern int min_to_ticks;

extern void exit(int status);

static void
quit_clean(int arg)
{
	printf("Exiting\n");
	exit(0);
}



int main(int argc, char **argv)
{
	int ch;
	char *progname = argv[0];
	int val;
	int minval;
	int norun = 0;
	int verbose = 0;
	int ifname_specified = 0;
	unsigned int i;
	struct test_config default_active_test = {
		.num = 0,
		.name = "default active test",
		.ifname = "bogus0",
		.type = TEST_TYPE_ACTIVE,
		.fib = 1,
		.local_ip_start = "10.20.0.1",
		.num_local_ips = 1,
		.local_port_start = 1,
		.num_local_ports = 1,
		.foreign_ip_start = "10.0.0.1",
		.num_foreign_ips = 1,
		.foreign_port_start = 1,
		.num_foreign_ports = 1,
		.local_mac = "02:00:00:00:00:00",
		.foreign_mac = "02:00:00:00:00:01",
		.vlan_start = 1,
		.num_vlans = 1,
		.vlan_stack_depth = 0,
		.syn_filter_name = NULL,
		.notify = 0
	}; 

	struct test_config default_passive_test = {
		.num = 1,
		.name = "default passive test",
		.ifname = "bogus0",
		.type = TEST_TYPE_PASSIVE,
		.fib = 1,
		.local_ip_start = "10.0.0.1",
		.num_local_ips = 1,
		.local_port_start = 1,
		.num_local_ports = 1,
		.foreign_ip_start = NULL,
		.num_foreign_ips = 0,
		.foreign_port_start = 0,
		.num_foreign_ports = 0,
		.local_mac = "02:00:00:00:00:01",
		.foreign_mac = "02:00:00:00:00:00",
		.vlan_start = 1,
		.num_vlans = 1,
		.vlan_stack_depth = -1,
		.syn_filter_name = NULL,
		.notify = 0
	}; 
	
#define MAX_TESTS 32
	struct test_config tests[MAX_TESTS];
	struct test_config *test = NULL;
	unsigned int num_tests = 0;

	signal(SIGINT, quit_clean);

	while ((ch = getopt(argc, argv, "a:A:b:B:f:hi:lm:M:nN:p:P:q:Q:t:T:V:v")) != -1) {
		if (0 == num_tests) {
			switch (ch) {
			case 'h':
			case 'l':
			case 'n':
			case 't':
			case 'v':
				/* these are all options that can appear before the first test spec */
				break;
			default:
				printf("Test type must be specified before option \"%c\"\n", ch);
				return (1);
			}
		}

		switch (ch) {
		case 'a':
			test->local_ip_start = optarg;
			break;
		case 'A':
			if (TEST_TYPE_PASSIVE == test->type) {
				printf("PASSIVE tests do not use foreign IP addresses\n");
				return (1);
			}

			test->foreign_ip_start = optarg;
			break;
		case 'b':
			val = strtol(optarg, NULL, 10);
			if (val < 1) {
				printf("Number ip addresses must be > 0\n");
				return (1);
			}
			test->num_local_ips = val;
			break;
		case 'B':
			if (TEST_TYPE_PASSIVE == test->type) {
				printf("PASSIVE tests do not use foreign IP addresses\n");
				return (1);
			}

			val = strtol(optarg, NULL, 10);
			if (val < 1) {
				printf("Number ip addresses must be > 0\n");
				return (1);
			}
			test->num_foreign_ips = val;
			break;
		case 'f':
			test->fib = strtol(optarg, NULL, 10);
			break;
		case 'h':
			usage(progname);
			return (0);
		case 'i':
			test->ifname = optarg;
			ifname_specified = 1;
			break;
		case 'l':
			print_test_config(&default_active_test);
			print_test_config(&default_passive_test);
			return (0);
		case 'm':
			test->local_mac = optarg;
			break;
		case 'M':
			test->foreign_mac = optarg;
			break;
		case 'n':
			norun = 1;
			break;
		case 'N':
			test->name = optarg;
			break;
		case 'p':
			minval = (TEST_TYPE_PASSIVE == test->type) ? 0 : 1; 

			val = strtol(optarg, NULL, 10);
			if ((val < minval) || (val > 65535)) {
				printf("Port number is outside of [%d, 65535]\n", minval);
				return (1);
			}
			test->local_port_start = val;
			break;
		case 'P':
			if (TEST_TYPE_PASSIVE == test->type) {
				printf("PASSIVE tests do not use foreign ports\n");
				return (1);
			}

			val = strtol(optarg, NULL, 10);
			if ((val < 1) || (val > 65535)) {
				printf("Port number is outside of [1, 65535]\n");
				return (1);
			}
			test->foreign_port_start = val;
			break;
		case 'q':
			val = strtol(optarg, NULL, 10);
			if (val < 1) {
				printf("Number of ports must be > 0\n");
				return (1);
			}
			test->num_local_ports = val;
			break;
		case 'Q':
			if (TEST_TYPE_PASSIVE == test->type) {
				printf("PASSIVE tests do not use foreign ports\n");
				return (1);
			}

			val = strtol(optarg, NULL, 10);
			if (val < 1) {
				printf("Number of ports must be > 0\n");
				return (1);
			}
			test->num_foreign_ports = val;
			break;
		case 't':
			if ((num_tests > 0) & !ifname_specified) {
				printf("Interface name must be specified for each test\n");
				return (1);
			}

			test = &tests[num_tests];
			num_tests++;

			if (0 == strcmp(optarg, "active")) {
				*test = default_active_test;
			} else if (0 == strcmp(optarg, "passive")) {
				*test = default_passive_test;
			} else {
				printf("Invalid test type \"%s\"\n", optarg);
				return (1);
			}

			test->num = num_tests - 1;
			test->fib = num_tests;
			test->notify = verbose;
			ifname_specified = 0;
			break;
		case 'T':
			test->vlan_stack_depth = strtol(optarg, NULL, 10);
			break;
		case 'v':
			if (0 == num_tests) {
				verbose++;
			} else {
				test->notify++;
			}
			break;
		case 'V':
			val = strtol(optarg, NULL, 10);
			if (val < 1) {
				printf("Number of VLANs must be >= 1\n");
				return (1);
			}
			test->num_vlans = val;
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

	
	if (0 == num_tests) {
		printf("No tests specified\n");
		return (1);
	}

	if (0 == ifname_specified) {
		printf("Interface name must be specified for each test\n");
		return (1);
	}

	for (i = 0; i < num_tests; i++) {
		int required_stack_depth;
		
		test = &tests[i];

		required_stack_depth = min_tag_stack_depth(test->vlan_start, test->num_vlans);

		if ((test->num_vlans > 1) && (test->vlan_stack_depth < required_stack_depth)) {
			test->vlan_stack_depth = required_stack_depth;
		}

		print_test_config(test);
	}

	if (norun) {
		return (0);
	}

	for (i = 0; i < num_tests; i++) {
		test = &tests[i];

		uinet_config_if(test->ifname, 0, test->fib);
	}


	/*
	 * Take care not to do to anything that requires any of the
	 * user-kernel facilities before this point (such as referring to
	 * curthread).
	 */
	uinet_init(1, 5100*1024);

	printf("maxusers=%d\n", maxusers);
	printf("maxfiles=%d\n", maxfiles);
	printf("maxsockets=%d\n", maxsockets);
	printf("nmbclusters=%d\n", nmbclusters);

	for (i = 0; i < num_tests; i++) {
		test = &tests[i];
		if (uinet_interface_up(test->ifname, 0)) {
			printf("Failed to bring up interface %s\n", test->ifname);
			return (1);
		}
	}

	for (i = 0; i < num_tests; i++) {
		if (0 != run_test(&tests[i], verbose)) {
			printf("Test %u failed to run\n", i);
			return (1);
		}
	}


	unsigned int current = 0;
	unsigned int last_read = 0;
	unsigned int min, avg, max;
	struct timespec last_time, this_time, elapsed;
	unsigned int ticks_before, total_ticks;

	total_ticks = 0;
	clock_gettime(CLOCK_MONOTONIC, &last_time);
	while (1) {
		ticks_before = (unsigned int)ticks;
		pause("slp", hz);
		total_ticks += (unsigned int)ticks - ticks_before; 

		current++;
		if (current - last_read == 10) {
			clock_gettime(CLOCK_MONOTONIC, &this_time);
			elapsed = this_time;
			timespecsub(&elapsed, &last_time);
			last_time = this_time;

			last_read = current;
			tcp_tcbinfo_hashstats(&min, &avg, &max);
			printf("TCP tcbinfo hashstats: min=%u avg=%u max=%u\n",
			       min, avg, max);
			
			int values[4];
			ssize_t len = sizeof(values[0]);
			kernel_sysctlbyname(curthread, "debug.to_avg_depth", &values[0], &len, NULL, 0, NULL, 0);
			kernel_sysctlbyname(curthread, "debug.to_avg_gcalls", &values[1], &len, NULL, 0, NULL, 0);
			kernel_sysctlbyname(curthread, "debug.to_avg_lockcalls", &values[2], &len, NULL, 0, NULL, 0);
			kernel_sysctlbyname(curthread, "debug.to_avg_mpcalls", &values[3], &len, NULL, 0, NULL, 0);
			printf("to_avg_depth=%d.%03d ", values[0] / 1000, values[0] % 1000);
			printf("to_avg_gcalls=%d.%03d ", values[1] / 1000, values[1] % 1000);
			printf("to_avg_lockcalls=%d.%03d ", values[2] / 1000, values[2] % 1000);
			printf("to_avg_mpcalls=%d.%03d\n", values[3] / 1000, values[3] % 1000);
			
			printf("ticks=%u\n", ticks);
			
			uint64_t est_hz;
			
			est_hz = (100 * 1000000000ULL * (uint64_t)total_ticks) / ((uint64_t)elapsed.tv_sec * 1000000000 + elapsed.tv_nsec);
			total_ticks = 0;

			printf("est. hz = %u.%02u, min_to_ticks=%d\n", (unsigned int)est_hz/100, (unsigned int)est_hz%100, min_to_ticks);
			clock_gettime(CLOCK_MONOTONIC, &last_time);
		}
	}

	return (0);
}
