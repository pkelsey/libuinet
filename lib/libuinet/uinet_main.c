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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
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



typedef enum { SC_INIT, SC_CONNECTED, SC_DONE } conn_state_t;

struct server_conn {
	struct socket *so;
	struct sockaddr_in peer_sin;
	struct sockaddr_in local_sin;
	conn_state_t conn_state;
	unsigned int go;
	struct mtx go_lock;
	uint8_t copybuf[2048];
};


#define TEST_TYPE_ACTIVE	0
#define TEST_TYPE_PASSIVE	1

struct test_config {
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
	uint32_t tags[IN_L2INFO_MAX_TAGS];
	uint32_t num_tags;
	char * syn_filter_name;
};


#define TEST_PASSIVE(fib, ip, port, vlans, nvlans, synfilter)		\
	TEST_PASSIVE_N(fib, ip, 1, port, 1, vlans, nvlans, synfilter)

#define TEST_PASSIVE_N(fib, ip, nips, port, nports, vlans, nvlans, synfilter)	\
	{ TEST_TYPE_PASSIVE, (fib), (ip), (nips), (port), (nports), 0, 0, 0, 0, NULL, NULL, vlans, (nvlans), (synfilter) }

#define TEST_ACTIVE(fib, localip, localport, foreignip, foreignport, localmac, foreignmac, vlans, nvlans) \
	TEST_ACTIVE_N(fib, localip, 1, localport, 1, foreignip, 1, foreignport, 1, localmac, foreignmac, vlans, nvlans)

#define TEST_ACTIVE_N(fib, localip, nlocalips, localport, nlocalports, foreignip, nforeignips, foreignport, nforeignports, localmac, foreignmac, vlans, nvlans) \
	{ TEST_TYPE_ACTIVE, (fib), (localip), (nlocalips), (localport), (nlocalports), (foreignip), (nforeignips), (foreignport), (nforeignports),(localmac), (foreignmac), vlans, (nvlans) }


extern int get_kernel_stack_if_params(const char *ifname,
				      struct sockaddr_in *addr,
				      struct sockaddr_in *baddr,
				      struct sockaddr_in *netmask);


struct test_config tests[] = {
	//	TEST_PASSIVE(1, "10.0.0.1", IN_PROMISC_PORT_ANY, {}, 0, "uinet_test"), 
	TEST_PASSIVE(1, "0.0.0.0", IN_PROMISC_PORT_ANY, {}, 0, "uinet_test"), 
	//	TEST_PASSIVE(1, "10.0.0.1", IN_PROMISC_PORT_ANY, {}, 0, NULL), 
	//	TEST_PASSIVE_N(1, "10.0.0.1", 10, IN_PROMISC_PORT_ANY, 1, {}, 0, NULL), 
	//	TEST_PASSIVE_N(1, "10.0.0.1", 66, 1, 1000, {}, 0, NULL), 
	//	TEST_ACTIVE(1, "10.0.0.1", 1234, "172.16.22.11", 22222, "00:0c:29:d2:ba:ec", "00:0c:29:15:11:e2", {}, 0) 
	// TEST_ACTIVE_N(1, "10.0.0.1", 1, 1234, 1, "172.16.22.11", 1, 22222, 10, "00:0c:29:d2:ba:ec", "00:0c:29:15:11:e2", {}, 0) 
};



static void
loopback_thread(void *arg)
{
	struct server_conn *sc = (struct server_conn *)arg;
	struct socket *so = sc->so;
	struct iovec iov;
	struct uio uio;
	int error;
	int rcv_flags = 0;
	ssize_t len;

	mtx_lock(&sc->go_lock);
	while (0 == sc->go)
		mtx_sleep(&sc->go, &sc->go_lock, 0, "wgolck", 0);
	mtx_unlock(&sc->go_lock);

	char buf1[32], buf2[32];
	printf("loopback_thread: connection to %s:%u from %s:%u established\n",
	       inet_ntoa_r(sc->local_sin.sin_addr, buf1, sizeof(buf1)), ntohs(sc->local_sin.sin_port),
	       inet_ntoa_r(sc->peer_sin.sin_addr, buf2, sizeof(buf2)), ntohs(sc->peer_sin.sin_port));
	sc->conn_state = SC_CONNECTED;

	while(SC_DONE != sc->conn_state) {
		iov.iov_base = sc->copybuf;
		iov.iov_len = sizeof(sc->copybuf);
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = sizeof(sc->copybuf);
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = curthread;
		error = soreceive(so, NULL, &uio, NULL, NULL, &rcv_flags);
		if (0 != error) {
			printf("loopback_thread: soreceive failed %d\n", error);
			len = 0;
		} else {
			len = sizeof(sc->copybuf) - uio.uio_resid;
			if (len) {
				iov.iov_base = sc->copybuf;
				iov.iov_len = sizeof(sc->copybuf);
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
			printf("loopback_thread: connection to %s:%u from %s:%u closed\n",
			       inet_ntoa_r(sc->local_sin.sin_addr, buf1, sizeof(buf1)), ntohs(sc->local_sin.sin_port),
			       inet_ntoa_r(sc->peer_sin.sin_addr, buf2, sizeof(buf2)), ntohs(sc->peer_sin.sin_port));
			sc->conn_state = SC_DONE;
		}

	}

	soclose(so);
	mtx_destroy(&sc->go_lock);
	free(sc, M_DEVBUF);
}


/*
 * This will be called after the ACK segment from the peer is processed, at
 * which point the peer address information will be populated in the
 * socket's inpcb.
 */
static int
loopback_kickoff(struct socket *so, void *arg, int waitflag)
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
		memcpy(&sc->peer_sin, sin, sizeof(struct sockaddr_in));
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

	mtx_lock(&sc->go_lock);
	sc->go = 1;
	wakeup(&sc->go);
	mtx_unlock(&sc->go_lock);

	return (SU_ISCONNECTED);
}


static int
server_upcall(struct socket *head, void *arg, int waitflag)
{
	struct socket *so;
	struct sockaddr *sa;
	struct server_conn *sc;
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

	sc = malloc(sizeof(struct server_conn), M_DEVBUF, M_WAITOK);
	if (NULL == sc) {
		soclose(so);
		goto out;
	}
	
	sc->so = so;
	memset(&sc->local_sin, 0, sizeof(struct sockaddr_in));
	memset(&sc->peer_sin, 0, sizeof(struct sockaddr_in));
	sc->conn_state = SC_INIT;
	mtx_init(&sc->go_lock, "golck", NULL, MTX_DEF);
	sc->go = 0;

	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, loopback_kickoff, sc);
	SOCKBUF_UNLOCK(&so->so_rcv);

	if (kthread_add(loopback_thread, sc, NULL, NULL, 0, 0, "loopback_svr")) {
		soclose(so);
		mtx_destroy(&sc->go_lock);
		free(sc, M_DEVBUF);
		goto out;
	}

out:
	if (sa)
		free(sa, M_SONAME);

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

#if 0
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


	if (0 == strcmp("10.0.0.1", inet_ntoa(arg->inc.inc_laddr))) {
		printf("ACCEPT\n");
		printf("--------------------------------\n");
		return (SYNF_ACCEPT);
	}

	printf("REJECT\n");
	printf("--------------------------------\n");
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



static void incr_in_addr_t(in_addr_t *inaddr)
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


static void print_test_config(struct test_config *test)
{
	unsigned int tagnum;

	if (TEST_TYPE_PASSIVE == test->type) {
		printf("PASSIVE fib=%u local_ip_start=%s local_ips=%u local_port_start=%u local_ports=%u nvlans=%u tags=",
		       test->fib, test->local_ip_start, test->num_local_ips, test->local_port_start, test->num_local_ports, test->num_tags);
		for(tagnum = 0; tagnum < test->num_tags; tagnum++) {
			printf(" %u", test->tags[tagnum]);
		}
		printf("\n");
	} else {
		printf("ACTIVE fib=%u local_ip_start=%s local_ips=%u local_port_start=%u local_ports=%u\n",
		       test->fib, test->local_ip_start, test->num_local_ips, test->local_port_start, test->num_local_ports);
		printf("              foreign_ip_start=%s foreign_ips=%u foreign_port_start=%u foreign_ports=%u nvlans=%u tags=",
		       test->foreign_ip_start, test->num_foreign_ips, test->foreign_port_start, test->num_foreign_ports, test->num_tags);
		for(tagnum = 0; tagnum < test->num_tags; tagnum++) {
			printf(" %u", test->tags[tagnum]);
		}
		printf("\n");
	}
}



static struct socket *
create_test_socket(unsigned int test_type, unsigned int fib, const char *local_mac, const char *foreign_mac, const char *syn_filter_name)
{
	int error;
	struct socket *so;
	struct thread *td = curthread;
	struct in_l2info l2i;
	struct syn_filter_optarg synf;

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

	if (TEST_TYPE_ACTIVE == test_type) {
		memset(&l2i, 0, sizeof(l2i));
		
		if ((error = mac_aton(foreign_mac, l2i.inl2i_foreign_addr)))
			goto err;
		
		if ((error = mac_aton(local_mac, l2i.inl2i_local_addr)))
			goto err;
		
		if ((error = so_setsockopt(so, SOL_SOCKET, SO_L2INFO, &l2i, sizeof(l2i)))) {
			printf("Promisc socket SO_L2INFO set failed (%d)\n", error);
			goto err;
		}
	} else {
		if (syn_filter_name && (*syn_filter_name != '\0')) {
			memset(&synf, 0, sizeof(synf));
			strlcpy(synf.sfa_name, syn_filter_name, SYNF_NAME_MAX);

			if ((error = so_setsockopt(so, IPPROTO_IP, IP_SYNFILTER, &synf, sizeof(synf)))) {
				printf("Promisc socket IP_SYNFILTER set failed (%d)\n", error);
				goto err;
			}
		}

		SOCKBUF_LOCK(&so->so_rcv);
		soupcall_set(so, SO_RCV, server_upcall, NULL);
		SOCKBUF_UNLOCK(&so->so_rcv);
	}

	return (so);

 err:
	soclose(so);
	return (NULL);
}


static int
test_promisc(void)
{
	struct socket *so;
	struct thread *td = curthread;
	int error;
	struct in_addr inaddr;
	
	unsigned int socket_count;

	unsigned int num_tests;
	unsigned int test_num;

	unsigned int num_local_addrs, num_local_ports;
	unsigned int local_addr_num, local_port_num;
	in_addr_t local_addr;
	in_port_t local_port;

	unsigned int num_foreign_addrs, num_foreign_ports;
	unsigned int foreign_addr_num, foreign_port_num;
	in_addr_t foreign_addr;
	in_port_t foreign_port;
	struct test_config *test;

	num_tests = sizeof(tests)/sizeof(tests[0]);
	for (test_num = 0; test_num < num_tests; test_num++) {
		test = &tests[test_num];

		print_test_config(test);

		socket_count = 0;

		num_local_addrs = inet_addr(test->local_ip_start) == INADDR_ANY ? 1 : test->num_local_ips;
		num_local_ports = test->local_port_start == IN_PROMISC_PORT_ANY ? 1 : test->num_local_ports;

		local_addr = inet_addr(test->local_ip_start);

		for (local_addr_num = 0; local_addr_num < num_local_addrs; local_addr_num++) {

			local_port = test->local_port_start;
			for (local_port_num = 0; local_port_num < num_local_ports; local_port_num++) {

				if (TEST_TYPE_ACTIVE == test->type) {
					num_foreign_addrs = test->num_foreign_ips;
					num_foreign_ports = test->num_foreign_ports;

					foreign_addr = inet_addr(test->foreign_ip_start);

					for (foreign_addr_num = 0; foreign_addr_num < num_foreign_addrs; foreign_addr_num++) {
						// xxx need to create separate sockets..... refactor....
						foreign_port = test->foreign_port_start;
						for (foreign_port_num = 0; foreign_port_num < num_foreign_ports; foreign_port_num++) {

							so = create_test_socket(TEST_TYPE_ACTIVE, test->fib, test->local_mac, test->foreign_mac, NULL);
							if (NULL == so)
								goto out;

							socket_count++;

							inaddr.s_addr = local_addr;
							printf("Binding active socket to %s:%u \n", inet_ntoa(inaddr), local_port);
							if ((error = dobind(so, local_addr, local_port)))
								goto out;

							inaddr.s_addr = foreign_addr;
							printf("Connecting to %s:%u \n", inet_ntoa(inaddr), foreign_port);
							if ((error = doconnect(so, foreign_addr, foreign_port)))
								goto out;

							foreign_port++;
						}

						incr_in_addr_t(&foreign_addr);
					}
				} else {
					so = create_test_socket(TEST_TYPE_PASSIVE, test->fib, NULL, NULL, test->syn_filter_name);
					if (NULL == so)
						goto out;

					socket_count++;					

					inaddr.s_addr = local_addr;
					printf("Binding passive socket to %s:%u \n", inet_ntoa(inaddr), local_port);
					if ((error = dobind(so, local_addr, local_port)))
						goto out;

					if ((error = solisten(so, SOMAXCONN, td))) {
						printf("Promisc socket listen failed (%d)\n", error);
						goto out;
					}
				}

				local_port++;
			}

			incr_in_addr_t(&local_addr);
		}

		printf("created %u sockets\n", socket_count);
	}

	so = NULL;
 out:
	if (so) 
		soclose(so);

	return (error);
}


extern int maxfiles;

int main(int argc, char **argv)
{
	char *ifname;
	struct thread *td;

	ifname = getenv("UINETIF");
	if (NULL == ifname) {
		printf("UINETIF is not set\n");
		return (1);
	}

	uinet_config_if(ifname, 0, 1);

	/*
	 * Take care not to do to anything that requires any of the
	 * user-kernel facilities before this point (such as referring to
	 * curthread).
	 */
	uinet_init(1, 128*1024);

	printf("maxusers=%d\n", maxusers);
	printf("maxfiles=%d\n", maxfiles);
	printf("maxsockets=%d\n", maxsockets);
	printf("nmbclusters=%d\n", nmbclusters);

	td = curthread;

	if (uinet_interface_up(ifname, 0)) {
		printf("Failed to bring up interface %s\n", ifname);
		return (1);
	}


	if (0 == test_promisc()) {
		printf("Promiscuous socket test passed\n");
	}


	while (1) {
		pause("slp", hz);
	}

	return (0);
}
