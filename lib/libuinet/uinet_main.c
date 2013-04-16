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



typedef enum { SC_INIT, SC_CONNECTED, SC_DONE } conn_state_t;

struct server_conn {
	struct socket *so;
	struct sockaddr_in sin;
	conn_state_t conn_state;
	unsigned int go;
	struct mtx go_lock;
	uint8_t copybuf[2048];
};



extern int get_kernel_stack_if_params(const char *ifname,
				      struct sockaddr_in *addr,
				      struct sockaddr_in *baddr,
				      struct sockaddr_in *netmask);

extern int uinet_init(void);



static int
bring_up_interface(const char *ifname, struct sockaddr_in *ks_addr)
{
	struct socket *cfg_so;
	struct thread *td = curthread;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	struct sockaddr_in ks_baddr;
	struct sockaddr_in ks_netmask;
	int error;

	/* 
	 * Get the parameters from the named interface attached to the
	 * kernel stack and use them for the user stack interface.
	 */

	if (get_kernel_stack_if_params(ifname, ks_addr, &ks_baddr, &ks_netmask)) {
		printf("Failed to get interface parameters from kernel stack\n");
		return (1);
	}

	error = socreate(PF_INET, &cfg_so, SOCK_DGRAM, 0, td->td_ucred, td);
	if (0 != error) {
		printf("Socket creation failed (%d)\n", error);
		return (1);
	}

	strcpy(ifr.ifr_name, ifname);

	sin = (struct sockaddr_in *)&ifr.ifr_addr;

	memcpy(sin, ks_addr, sizeof(struct sockaddr_in));
	error = ifioctl(cfg_so, SIOCSIFADDR, (caddr_t)&ifr, td);
	if (0 != error) {
		printf("SIOCSIFADDR failed %d\n", error);
		return (1);
	}

	memcpy(sin, &ks_baddr, sizeof(struct sockaddr_in));
	error = ifioctl(cfg_so, SIOCSIFBRDADDR, (caddr_t)&ifr, td);
	if (0 != error) {
		printf("SIOCSIFBRDADDR failed %d\n", error);
		return (1);
	}

	memcpy(sin, &ks_netmask, sizeof(struct sockaddr_in));
	error = ifioctl(cfg_so, SIOCSIFNETMASK, (caddr_t)&ifr, td);
	if (0 != error) {
		printf("SIOCSIFNETMASK failed %d\n", error);
		return (1);
	}

	
	/* set interface to UP */

	error = ifioctl(cfg_so, SIOCGIFFLAGS, (caddr_t)&ifr, td);
	if (0 != error) {
		printf("SSIOCGIFFLAGS failed %d\n", error);
		return (1);
	}

	printf("interface flags: 0x%08x\n", ((unsigned int)ifr.ifr_flags << 16) | ifr.ifr_flagshigh);

	ifr.ifr_flags |= IFF_UP;
	error = ifioctl(cfg_so, SIOCSIFFLAGS, (caddr_t)&ifr, td);
	if (0 != error) {
		printf("SSIOCSIFFLAGS failed %d\n", error);
		return (1);
	}

	soclose(cfg_so);

	return (0);
}



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

	printf("loopback_thread: connection established from %s:%u\n",
	       inet_ntoa(sc->sin.sin_addr), ntohs(sc->sin.sin_port));
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
			continue;
		}

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
		} else if (SBS_CANTRCVMORE & so->so_rcv.sb_state) {
			printf("loopback_thread: connection closed      from %s:%u\n",
			       inet_ntoa(sc->sin.sin_addr), ntohs(sc->sin.sin_port));
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
		memcpy(&sc->sin, sin, sizeof(struct sockaddr_in));
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
	memset(&sc->sin, 0, sizeof(struct sockaddr_in));
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



int main(int argc, char **argv)
{
	char *ifname;
	struct sockaddr_in addr;
	struct thread *td;
	struct socket *server_so;
	struct sockaddr_in sin;
	int error;

	
	/* Take care not to do to anything that requires any of the
	 * user-kernel facilities before this point (such as referring to
	 * curthread).
	 */
	uinet_init();

	ifname = getenv("UINETIF");
	td = curthread;

	printf("uinet test\n");

	if (bring_up_interface(ifname, &addr)) {
		printf("Failed to bring up interface %s\n", ifname);
		return (1);
	}

	
	error = socreate(PF_INET, &server_so, SOCK_STREAM, 0, td->td_ucred, td);
	if (0 != error) {
		printf("Server socket creation failed (%d)\n", error);
		return (1);
	}

	SOCKBUF_LOCK(&server_so->so_rcv);
	soupcall_set(server_so, SO_RCV, server_upcall, NULL);
	SOCKBUF_UNLOCK(&server_so->so_rcv);

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	memcpy(&sin.sin_addr, &addr.sin_addr, sizeof(sin.sin_addr));
	sin.sin_port = htons(2222);
	printf("Server binding to %s:%u \n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
	error = sobind(server_so, (struct sockaddr *)&sin, td);
	if (0 != error) {
		printf("Server bind to %s:%u failed (%d)\n", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), error);
		return (1);
	}
	
	error = solisten(server_so, SOMAXCONN, td);
	if (0 != error) {
		printf("Server listen failed (%d)\n", error);
		return (1);
	}

	while (1) {
		pause("slp", hz);
	}

	soclose(server_so);

	return (0);
}
