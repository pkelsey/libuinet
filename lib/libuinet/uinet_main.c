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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/uio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_promisc.h>

#include <arpa/inet.h>

#include "uinet_api.h"
#include "uinet_config.h"


/* 12 bits, 0 and 4095 are reserved */
#define MAX_VLANS_PER_TAG 4094


typedef enum { CS_INIT, CS_RETRY,CS_CONNECTING, CS_CONNECTED, CS_DISCONNECTING, CS_DONE } conn_state_t;

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


struct client_conn {
	TAILQ_ENTRY(client_conn) client_queue;
	struct client_context *client;
	struct socket *so;
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
};


TAILQ_HEAD(client_conn_listhead, client_conn);

struct client_context {
	struct client_conn_listhead queue;
	struct mtx lock;
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
	struct server_conn_listhead queue;
	struct mtx lock;
	int notify;
	uint8_t copybuf[2048];
};

#define TEST_TYPE_ACTIVE	0
#define TEST_TYPE_PASSIVE	1

struct test_config {
	char *name;
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
};


#define TEST_PASSIVE(name, fib, ip, port, vlanstart, nvlans, vlanstackdepth, synfilter)	\
	TEST_PASSIVE_N(name, fib, ip, 1, port, 1, vlanstart, nvlans, vlanstackdepth, synfilter)

#define TEST_PASSIVE_N(name, fib, ip, nips, port, nports, vlanstart, nvlans, vlanstackdepth, synfilter) \
	{ (name), TEST_TYPE_PASSIVE, (fib), (ip), (nips), (port), (nports), 0, 0, 0, 0, NULL, NULL, (vlanstart), (nvlans), (vlanstackdepth), (synfilter) }

#define TEST_ACTIVE(name, fib, localip, localport, foreignip, foreignport, localmac, foreignmac, vlanstart, nvlans, vlanstackdepth) \
	TEST_ACTIVE_N(name, fib, localip, 1, localport, 1, foreignip, 1, foreignport, 1, localmac, foreignmac, vlanstart, nvlans, vlanstackdepth)

#define TEST_ACTIVE_N(name, fib, localip, nlocalips, localport, nlocalports, foreignip, nforeignips, foreignport, nforeignports, localmac, foreignmac, vlanstart, nvlans, vlanstackdepth) \
	{ (name), TEST_TYPE_ACTIVE, (fib), (localip), (nlocalips), (localport), (nlocalports), (foreignip), (nforeignips), (foreignport), (nforeignports),(localmac), (foreignmac), (vlanstart), (nvlans), (vlanstackdepth) }

#define VLANS(...) { __VA_ARGS__ }


static int dobind(struct socket *so, in_addr_t addr, in_port_t port);
static int doconnect(struct socket *so, in_addr_t addr, in_port_t port);
static struct socket * create_test_socket(unsigned int test_type, unsigned int fib,
					  const char *local_mac, const char *foreign_mac,
					  const uint32_t *vlan_stack, int vlan_stack_depth,
					  const char *syn_filter_name, void *upcall_arg);


struct test_config tests[] = {

	TEST_PASSIVE("sp. ip, sp. port, sp. tags, filt.", 1, "10.0.0.1",                2222, 42, 1,  3, "uinet_test"), 
	TEST_PASSIVE("any ip, sp. port, sp. tags, filt.", 1,  "0.0.0.0",                2222, 42, 1,  1, "uinet_test"), 
	TEST_PASSIVE("sp. ip, any port, sp. tags, filt.", 1, "10.0.0.1", IN_PROMISC_PORT_ANY, 42, 1,  1, "uinet_test"), 
	TEST_PASSIVE("any ip, any port, sp. tags, filt.", 1,  "0.0.0.0", IN_PROMISC_PORT_ANY, 42, 1,  1, "uinet_test"), 
	TEST_PASSIVE("sp. ip, sp. port, any tags, filt.", 1, "10.0.0.1",                2222,  0, 1, -1, "uinet_test"), 
	TEST_PASSIVE("any ip, sp. port, any tags, filt.", 1,  "0.0.0.0",                2222,  0, 1, -1, "uinet_test"), 
	TEST_PASSIVE("sp. ip, any port, any tags, filt.", 1, "10.0.0.1", IN_PROMISC_PORT_ANY,  0, 1, -1, "uinet_test"), 
	TEST_PASSIVE("any ip, any port, any tags, filt.", 1,  "0.0.0.0", IN_PROMISC_PORT_ANY,  0, 1, -1, "uinet_test"), 

	TEST_ACTIVE("one, tags", 1, "10.20.0.1", 1234, "10.0.0.1", 2222, "00:0c:29:15:11:e2", "00:0c:29:d2:ba:ec", 42, 1, 3) ,


	TEST_PASSIVE("any port, filtered", 1, "10.0.0.1", IN_PROMISC_PORT_ANY, 0, 1, 0, "uinet_test"), 
	TEST_PASSIVE("any ip, any port, filtered", 1, "0.0.0.0", IN_PROMISC_PORT_ANY, 0, 1, 0, "uinet_test"), 
	TEST_PASSIVE("any port", 1, "10.0.0.1", IN_PROMISC_PORT_ANY, 0, 1, 0, NULL), 
	TEST_PASSIVE("any port, many vlans", 1, "10.0.0.1", IN_PROMISC_PORT_ANY, 22, 1000000, 2, NULL), 
	TEST_PASSIVE_N("many any port", 1, "10.0.0.1", 10000, IN_PROMISC_PORT_ANY, 1, 0, 1, 0, NULL), 
	TEST_PASSIVE_N("many any port, many vlans", 1, "10.0.0.1", 100, IN_PROMISC_PORT_ANY, 1, 22, 100, 1, NULL), 
	TEST_PASSIVE_N("many specific port", 1, "10.0.0.1", 66, 1, 1000, 0, 1, 0, NULL), 

	TEST_ACTIVE("one", 1, "10.20.0.1", 1234, "10.0.0.1", 2222, "00:0c:29:15:11:e2", "00:0c:29:d2:ba:ec", 0, 1, 0) ,
	TEST_ACTIVE_N("one local, many foreign", 1, "10.20.0.1", 1, 1234, 1, "10.0.0.1", 1000, 1, 100, "00:0c:29:15:11:e2", "00:0c:29:d2:ba:ec", 0, 1, 0),
	TEST_ACTIVE_N("one local, many foreign", 1, "10.20.0.1", 1, 1234, 1, "10.0.0.1", 10000, 1, 100, "00:0c:29:15:11:e2", "00:0c:29:d2:ba:ec", 0, 1, 0),
	TEST_ACTIVE_N("one local, many foreign, many vlans", 1, "10.20.0.1", 1, 1234, 1, "10.0.0.1", 100, 1, 100, "00:0c:29:15:11:e2", "00:0c:29:d2:ba:ec", 22, 100, 1),

	TEST_ACTIVE_N("many local, many foreign", 1, "10.20.0.1", 2, 1234, 1, "10.0.0.1", 1, 1, 40000, "00:0c:29:15:11:e2", "00:0c:29:d2:ba:ec", 0, 1, 0) 
};


static void
loopback_thread(void *arg)
{
	struct server_context *server = (struct server_context *)arg;
	struct server_conn *sc;
	struct socket *so;
	struct iovec iov;
	struct uio uio;
	int error;
	int rcv_flags = 0;
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
		error = soreceive(so, NULL, &uio, NULL, NULL, &rcv_flags);
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
				       inet_ntoa_r(sc->local_sin.sin_addr, buf1, sizeof(buf1)), ntohs(sc->local_sin.sin_port),
				       inet_ntoa_r(sc->remote_sin.sin_addr, buf2, sizeof(buf2)), ntohs(sc->remote_sin.sin_port));
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
		       inet_ntoa_r(sc->local_sin.sin_addr, buf1, sizeof(buf1)), ntohs(sc->local_sin.sin_port),
		       inet_ntoa_r(sc->remote_sin.sin_addr, buf2, sizeof(buf2)), ntohs(sc->remote_sin.sin_port));
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


static void
verify_thread(void *arg)
{
	struct client_context *client = (struct client_context *)arg;
	struct client_conn *cc;
	struct iovec iov;
	struct uio uio;
	int error;
	int rcv_flags = 0;
	ssize_t len;
	unsigned int pass, fail;
	char connstr[80];
	char buf1[32], buf2[32];
	uint64_t cycle_number = 0;
	int connection_cycle;
	int data_cycle;
	int size, remaining;
	int i;

	while(1) {
		printf("verify cycle %llu started\n", (unsigned long long)cycle_number);

		cc = TAILQ_FIRST(&client->queue);
		
		pass = 0;
		fail = 0;

		if (NULL == cc) {
			printf("No connections defined.\n");
			break;
		}
		
		connection_cycle =
		    client->interleave ||
		    (cycle_number <= 1) ||
		    (!client->interleave && !(cycle_number & 0x1));

		data_cycle =
		    client->interleave ||
		    (!client->interleave && (cycle_number > 1) && (cycle_number & 0x1));

		TAILQ_FOREACH(cc, &client->queue, client_queue) {
			remaining = sizeof(connstr);
			size = snprintf(connstr, sizeof(connstr), "%s:%u -> %s:%u vlans=[ ", 
					inet_ntoa_r(cc->local_sin.sin_addr, buf1, sizeof(buf1)), ntohs(cc->local_sin.sin_port),
					inet_ntoa_r(cc->remote_sin.sin_addr, buf2, sizeof(buf2)), ntohs(cc->remote_sin.sin_port));
			for (i = 0; i < cc->vlan_stack_depth; i++) {
				remaining = size > remaining ? 0 : remaining - size;
				if (remaining) {
					size = snprintf(&connstr[sizeof(connstr) - remaining], remaining, "%u ", cc->vlan_stack[i]);  
				}
			}
			remaining = size > remaining ? 0 : remaining - size;
			if (remaining) {
				snprintf(&connstr[sizeof(connstr) - remaining], remaining, "]");	
			}

			if (client->notify) {
				printf("verifying %s\n", connstr);
			}

			mtx_lock(&client->lock);
			switch (cc->conn_state) {
			case CS_INIT:
			case CS_RETRY:
				if (connection_cycle) {
					if (CS_INIT == cc->conn_state) {
						client->connecting++;
					}

					cc->last_conn_state = cc->conn_state;
					cc->conn_state = CS_CONNECTING;
					mtx_unlock(&client->lock);
				
					if (cc->so) {
						soclose(cc->so);
					}

					error = 0;
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

					if (error) {
						mtx_lock(&client->lock);
						client->connecting--;
						client->retrying++;
						client->retries++;

						cc->last_conn_state = cc->conn_state;
						cc->conn_state = CS_RETRY;
						mtx_unlock(&client->lock);
					}
				}
				break;
			case CS_CONNECTING:
				mtx_unlock(&client->lock);
				break;
			case CS_CONNECTED:
				if (data_cycle) {
					mtx_unlock(&client->lock);

					snprintf(client->wirebuf, sizeof(client->wirebuf), "%s", connstr);
					len = strlcpy(client->verifybuf, client->wirebuf, sizeof(client->verifybuf)) + 1;
			
					iov.iov_base = client->wirebuf;
					iov.iov_len = len;
					uio.uio_iov = &iov;
					uio.uio_iovcnt = 1;
					uio.uio_offset = 0;
					uio.uio_resid = iov.iov_len;
					uio.uio_segflg = UIO_SYSSPACE;
					uio.uio_rw = UIO_WRITE;
					uio.uio_td = curthread;
					error = sosend(cc->so, NULL, &uio, NULL, NULL, 0, curthread);
					if (0 != error) {
						printf("verify_thread: sosend failed %d\n", error);
					}

					memset(client->wirebuf, 0, len);

					iov.iov_base = client->wirebuf;
					iov.iov_len = len;
					uio.uio_iov = &iov;
					uio.uio_iovcnt = 1;
					uio.uio_offset = 0;
					uio.uio_resid = iov.iov_len;
					uio.uio_segflg = UIO_SYSSPACE;
					uio.uio_rw = UIO_READ;
					uio.uio_td = curthread;
					error = soreceive(cc->so, NULL, &uio, NULL, NULL, &rcv_flags);
					if (0 != error) {
						printf("loopback_thread: soreceive failed %d\n", error);
					} else {
						if (0 != strcmp(client->verifybuf, client->wirebuf)) {
							printf("verification failed\n");
							fail++;
						} else {
							pass++;
						}
					}
				}
				break;
			case CS_DISCONNECTING:
				break;
			case CS_DONE:
				break;
			}

		}

		if (connection_cycle) {
			printf("connected=%u connecting=%u disconnecting=%u retrying=%u connects=%u disconnects=%u retries=%u\n",
			       client->connected, client->connecting, client->disconnecting, client->retrying, client->connects,
			       client->disconnects, client->retries);
		}

		if (data_cycle) {
			printf("pass=%u fail=%u\n", pass, fail); 
		}

		cycle_number++;
		pause("vrfy", 2*hz);
	}

	mtx_destroy(&client->lock);
	free(client, M_DEVBUF);
}


static int
client_upcall(struct socket *so, void *arg, int waitflag)
{
	struct client_conn *cc = arg;
	struct client_context *client = cc->client;
	struct sockaddr_in *sin;
	int error;
	int notify = 0;

	mtx_lock(&client->lock);
	
	switch (cc->conn_state) {
	case CS_INIT:
	case CS_RETRY:
		break;
	case CS_CONNECTING:
		client->connected++;  /* needs to be out here to count
				       * properly in the
				       * transition-to-disconnect(ing)
				       * cases
				       */
		if (so->so_state & SS_ISCONNECTED) {
			client->connects++;
			if (CS_INIT == cc->last_conn_state) {
				client->connecting--;
			} else {
				client->retrying--;
			}

			if (0 == (client->connected % 1000))
				notify = 1;

			cc->last_conn_state = cc->conn_state;
			cc->conn_state = CS_CONNECTED;

			sin = NULL;
			error = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so, (struct sockaddr **)&sin);
			if (error) {
				printf("Error getting peer address %d\n", error);
			}
	
			if (sin) {
				memcpy(&cc->remote_sin, sin, sizeof(struct sockaddr_in));
				free(sin, M_SONAME);
			}

			sin = NULL;
			error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, (struct sockaddr **)&sin);
			if (error) {
				printf("Error getting local address %d\n", error);
			}
	
			if (sin) {
				memcpy(&cc->local_sin, sin, sizeof(struct sockaddr_in));
				free(sin, M_SONAME);
			}
			break;
		} 
		/* fallthrough */
	case CS_CONNECTED:
		if (so->so_state & SS_ISDISCONNECTED) {
			client->connected--;
			client->retrying++;
			client->disconnects++;
			client->retries++;

			cc->last_conn_state = cc->conn_state;
			cc->conn_state = CS_RETRY;
		} else if (so->so_state & SS_ISDISCONNECTING) {
			client->disconnecting++;

			cc->last_conn_state = cc->conn_state;
			cc->conn_state = CS_DISCONNECTING;
		} 
		break;
	case CS_DISCONNECTING:
		if (so->so_state & SS_ISDISCONNECTED) {
			client->connected--;
			client->disconnecting--;
			client->retrying++;
			client->retries++;
			client->disconnects++;



			cc->last_conn_state = cc->conn_state;
			cc->conn_state = CS_RETRY;
		}
		break;
	case CS_DONE:
		break;
	}

	mtx_unlock(&client->lock);

	if (notify)
		printf("connected=%u connecting=%u disconnecting=%u retrying=%u connects=%u disconnects=%u retries=%u\n",
		       client->connected, client->connecting, client->disconnecting, client->retrying, client->connects, client->disconnects, client->retries);

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
	
	printf("%s.local_addr = ", name); print_macaddr(l2i->inl2i_local_addr); printf("\n");
	printf("%s.foreign_addr = ", name); print_macaddr(l2i->inl2i_foreign_addr); printf("\n");
	printf("%s.tags = %u\n", name, l2i->inl2i_tagcnt);
	for (i = 0; i < l2i->inl2i_tagcnt; i++) {
		printf("  tag %2u = 0x%08x\n", i, l2i->inl2i_tags[i]);
	}
}
#endif

static int uinet_test_synf_callback(struct inpcb *inp, void *inst_arg, struct syn_filter_cbarg *arg)
{
#if 0
	int i;


	printf("SYN received\n");
	printf("src addr = %s.%u\n", inet_ntoa(arg->inc.inc_faddr), ntohs(arg->inc.inc_fport));
	printf("dst addr = %s.%u\n", inet_ntoa(arg->inc.inc_laddr), ntohs(arg->inc.inc_lport));
	printf("src mac = "); print_macaddr(arg->l2i->inl2i_foreign_addr); printf("\n");
	printf("dest mac = "); print_macaddr(arg->l2i->inl2i_local_addr); printf("\n");
	printf("tags(%u) =", arg->l2i->inl2i_tagcnt);
	for (i = 0; i < arg->l2i->inl2i_tagcnt; i++) {
		printf(" 0x%08x", arg->l2i->inl2i_tags[i]);
	}
	printf("\n");

#endif
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
	inet_ntoa_r(inaddr, ip_end, sizeof(ip_end));

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
print_test_config(struct test_config *test, int index)
{
	unsigned int num_tags;
	unsigned int tagnum;
	unsigned int local_length;
	unsigned int foreign_length;
	char local_ip_range[64];
	char foreign_ip_range[64];
	uint32_t vlan_tag_stack[IN_L2INFO_MAX_TAGS];

	if (index >= 0) printf("%2u ", index);

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
	
	if ((error = setopt_int(so, IPPROTO_IP, IP_BINDANY, 1, "IP_BINDANY")))
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

	l2i.inl2i_tagcnt = vlan_stack_depth;
	for (i = 0; i < vlan_stack_depth; i++) {
		uint32_t ethertype;

		/* this is standards compliant to two levels, questionable beyond that */
		if ((vlan_stack_depth - 1) == i) ethertype = 0x8100;
		else ethertype = 0x88a8;

		l2i.inl2i_tags[i] = htonl((ethertype << 16) | vlan_stack[i]);
	}
	l2i.inl2i_tagmask = htonl(0x00000fff);  /* XXX assuming 802.1Q */
		
	if ((error = so_setsockopt(so, SOL_SOCKET, SO_L2INFO, &l2i, sizeof(l2i)))) {
		printf("Promisc socket SO_L2INFO set failed (%d)\n", error);
		goto err;
	}


	return (so);

 err:
	soclose(so);
	return (NULL);
}


static int
run_test(unsigned int test_num, int verbose)
{
	struct socket *so = NULL;
	struct thread *td = curthread;
	int error = 0;
	unsigned int socket_count;

	unsigned int num_tests;

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
	struct test_config *test;
	struct client_context *client;
	struct server_context *server;


	num_tests = sizeof(tests)/sizeof(tests[0]);

	if (test_num >= num_tests) {
		return (1);
	}

	test = &tests[test_num];

	print_test_config(test, test_num);

	socket_count = 0;

	if (TEST_TYPE_ACTIVE == test->type) {
		client = malloc(sizeof(struct client_context), M_DEVBUF, M_WAITOK | M_ZERO);
		TAILQ_INIT(&client->queue);
		mtx_init(&client->lock, "clnqlk", NULL, MTX_DEF);
		client->notify = verbose;
		client->interleave = 0;
	} else {
		server = malloc(sizeof(struct server_context), M_DEVBUF, M_WAITOK | M_ZERO);
		TAILQ_INIT(&server->queue);
		mtx_init(&server->lock, "svrqlk", NULL, MTX_DEF);
		server->notify = verbose;

		if (kthread_add(loopback_thread, server, NULL, NULL, 0, 0, "loopback_svr")) {
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
	}

	if (num_vlans > max_vlans) {
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

							socket_count++;

							TAILQ_INSERT_TAIL(&cc->client->queue, cc, client_queue);

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
		if (kthread_add(verify_thread, client, NULL, NULL, 0, 0, "verify_cln")) {
			printf("Failed to create client thread\n");
			mtx_destroy(&client->lock);
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
list_tests(void)
{
	unsigned int num_tests, test_num;

	num_tests = sizeof(tests)/sizeof(tests[0]);
	for (test_num = 0; test_num < num_tests; test_num++) {
		print_test_config(&tests[test_num], test_num);
	}
}


static void
usage(const char *progname)
{

	printf("Usage: %s [options]\n", progname);
	printf("    -h         show usage\n");
	printf("    -i ifname  specify network interface\n");
	printf("    -l         list all canned tests\n");
	printf("    -t num     run given test number\n");
	printf("    -v         be verbose\n");
}



int main(int argc, char **argv)
{
	char *ifname = NULL;
	struct thread *td;
	char ch;
	char *progname = argv[0];
	int test_num = -1;
	int verbose = 0;

	while ((ch = getopt(argc, argv, "hi:lt:v")) != -1) {
		switch (ch) {
		case 'h':
			usage(progname);
			return (0);
		case 'i':
			ifname = optarg;
			break;
		case 'l':
			list_tests();
			return (0);
		case 't':
			test_num = strtol(optarg, NULL, 10);
			printf("test_num = %d\n", test_num);
			break;
		case 'v':
			verbose++;
			break;
		case '?':
		default:
			usage(progname);
			return (1);
		}
	}
	argc -= optind;
	argv += optind;


	if (NULL == ifname) {
		printf("Specify a network interface\n");
		return (1);
	}

	if (test_num < 0) {
		printf("Specify a test number\n");
		return (1);
	}

	uinet_config_if(ifname, 0, 1);

	/*
	 * Take care not to do to anything that requires any of the
	 * user-kernel facilities before this point (such as referring to
	 * curthread).
	 */
	uinet_init(1, 1100*1024);

	printf("maxusers=%d\n", maxusers);
	printf("maxfiles=%d\n", maxfiles);
	printf("maxsockets=%d\n", maxsockets);
	printf("nmbclusters=%d\n", nmbclusters);

	td = curthread;

	if (uinet_interface_up(ifname, 0)) {
		printf("Failed to bring up interface %s\n", ifname);
		return (1);
	}


	if (0 != run_test(test_num, verbose)) {
		printf("Test %u failed.\n", test_num);
		return (1);
	}

	unsigned int current = 0;
	unsigned int last_read = 0;
	unsigned int min, avg, max;
	while (1) {
		pause("slp", hz);

		current++;
		if (current - last_read > 10) {
			last_read = current;
			tcp_tcbinfo_hashstats(&min, &avg, &max);
			printf("TCP tcbinfo hashstats: min=%u avg=%u max=%u\n",
			       min, avg, max);
		}
	}

	return (0);
}
