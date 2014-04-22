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
#include <ev.h>

struct passive_context;
struct interface_config;

struct connection_context {
	char label[64];
	ev_uinet watcher;
	struct passive_context *server;
	uint64_t bytes_read;
};


struct passive_context {
	struct ev_loop *loop;
	struct uinet_socket *listener;
	ev_uinet listen_watcher;
	int verbose;
	struct interface_config *interface;
};

struct interface_config {
	char *ifname;
	char alias[UINET_IF_NAMESIZE];
	unsigned int cdom;
	int thread_create_result;
	pthread_t thread;
	struct ev_loop *loop;
	int promisc;
	int type;
	int instance;
	char *alias_prefix;
	int do_tcpstats;
	uint64_t num_sockets;
	uint64_t max_accept_batch;
};

struct server_config {
	char *listen_addr;
	int listen_port;
	struct interface_config *interface;
	int verbose;
	struct passive_context *passive;
	int addrany;
};


static __inline int imin(int a, int b) { return (a < b ? a : b); }


static void
print_tcp_state(struct uinet_socket *so, const char *label)
{
	struct uinet_tcp_info info;
	unsigned int optlen;
	int error;

	memset(&info, 0, sizeof(info));
	optlen = sizeof(info);

	if ((error = uinet_sogetsockopt(so, UINET_IPPROTO_TCP, UINET_TCP_INFO, &info, &optlen))) {
		printf("%s: could not get TCP state (%d)\n", label, error);
		return;
	}

	printf("========================================================================================\n");
	printf("%s: fsm_state=%u rtt_us=%u rttvar_us=%u\n", label, info.tcpi_state, info.tcpi_rtt, info.tcpi_rttvar);
	printf("%s: snd mss=%u wscale=%u wnd=%u seq_nxt=%u retrans=%u zerowin=%u\n", label,
	       info.tcpi_snd_mss, info.tcpi_snd_wscale, info.tcpi_snd_wnd, info.tcpi_snd_nxt, info.tcpi_snd_rexmitpack, info.tcpi_snd_zerowin);
	printf("%s: snd ssthresh=%u cwnd=%u\n", label, info.tcpi_snd_ssthresh, info.tcpi_snd_cwnd);
	printf("%s: rcv mss=%u wscale=%u wnd=%u seq_nxt=%u ooo=%u\n", label,
	       info.tcpi_rcv_mss, info.tcpi_rcv_wscale, info.tcpi_rcv_space, info.tcpi_rcv_nxt, info.tcpi_rcv_ooopack);
	printf("========================================================================================\n");
}


static void
passive_receive_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct connection_context *conn = (struct connection_context *)w->data;
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
		if (conn->server->verbose)
			printf("%s: can't read, closing\n", conn->label);
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
			printf("%s: read error (%d), closing\n", conn->label, error);
			goto err;
		}

		bytes_read = read_size - uio.uio_resid;

		conn->bytes_read += bytes_read;

		if (conn->server->verbose > 2)
			print_tcp_state(w->so, conn->label);

		if (conn->server->verbose > 1) {

			printf("========================================================================================\n");
		}

		if (conn->server->verbose)
			printf("To %s (%u bytes, %llu total, %s)\n", conn->label, bytes_read,
			       (unsigned long long)conn->bytes_read, flags & UINET_MSG_HOLE_BREAK ? "HOLE" : "normal");
		
		if (conn->server->verbose > 1) {
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
	ev_uinet_stop(loop, w);
	ev_uinet_detach(w->ctx);
	uinet_soclose(w->so);
	conn->server->interface->num_sockets--;
	free(conn);
}


static void
accept_cb(struct ev_loop *loop, ev_uinet *w, int revents)
{
	struct passive_context *passive = w->data;
	struct uinet_socket *newso = NULL;
	struct uinet_socket *newpeerso = NULL;
	struct connection_context *conn = NULL;
	struct connection_context *peerconn = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct ev_uinet_ctx *peersoctx = NULL;
	struct uinet_sockaddr_in *sin1, *sin2;
	char buf1[32], buf2[32];
	int error;
	int batch_limit = 32;
	int processed = 0;

	while ((processed < batch_limit) &&
	       (UINET_EWOULDBLOCK != (error = uinet_soaccept(w->so, NULL, &newso)))) {
		processed++;

		if (0 == error) {
			newpeerso = NULL;
			conn = NULL;
			peerconn = NULL;
			soctx = NULL;
			peersoctx = NULL;

			if (passive->verbose)
				printf("accept succeeded\n");
		
			soctx = ev_uinet_attach(newso);
			if (NULL == soctx) {
				printf("Failed to alloc libev context for new connection socket\n");
				goto fail;
			}

			newpeerso = uinet_sogetpassivepeer(newso);
			peersoctx = ev_uinet_attach(newpeerso);
			if (NULL == peersoctx) {
				printf("Failed to alloc libev context for new passive peer connection socket\n");
				goto fail;
			}

			conn = calloc(1, sizeof(*conn));
			if (NULL == conn) {
				printf("Failed to alloc connection context for new connection\n");
				goto fail;
			}

			peerconn = calloc(1, sizeof(*peerconn));
			if (NULL == conn) {
				printf("Failed to alloc connection context for new passive peer connection\n");
				goto fail;
			}


			uinet_sogetsockaddr(newso, (struct uinet_sockaddr **)&sin1);
			uinet_sogetpeeraddr(newso, (struct uinet_sockaddr **)&sin2);
			snprintf(conn->label, sizeof(conn->label), "SERVER (%s:%u <- %s:%u)",
				 uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
				 uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
			uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
			uinet_free_sockaddr((struct uinet_sockaddr *)sin2);

			conn->server = passive;
			ev_init(&conn->watcher, passive_receive_cb);
			ev_uinet_set(&conn->watcher, soctx, EV_READ);
			conn->watcher.data = conn;
			ev_uinet_start(loop, &conn->watcher);

			uinet_sogetsockaddr(newpeerso, (struct uinet_sockaddr **)&sin1);
			uinet_sogetpeeraddr(newpeerso, (struct uinet_sockaddr **)&sin2);
			snprintf(peerconn->label, sizeof(peerconn->label), "CLIENT (%s:%u <- %s:%u)",
				 uinet_inet_ntoa(sin1->sin_addr, buf1, sizeof(buf1)), ntohs(sin1->sin_port),
				 uinet_inet_ntoa(sin2->sin_addr, buf2, sizeof(buf2)), ntohs(sin2->sin_port));
			uinet_free_sockaddr((struct uinet_sockaddr *)sin1);
			uinet_free_sockaddr((struct uinet_sockaddr *)sin2);

			peerconn->server = passive;
			ev_init(&peerconn->watcher, passive_receive_cb);
			ev_uinet_set(&peerconn->watcher, peersoctx, EV_READ);
			peerconn->watcher.data = peerconn;
			ev_uinet_start(loop, &peerconn->watcher);

			passive->interface->num_sockets += 2;

			continue;
		fail:
			if (conn) free(conn);
			if (peerconn) free(peerconn);
			if (soctx) ev_uinet_detach(soctx);
			if (peersoctx) ev_uinet_detach(peersoctx);
			if (newso) uinet_soclose(newso);
			if (newpeerso) uinet_soclose(newpeerso);

		}

		newso = NULL;
	}

	if (processed > passive->interface->max_accept_batch)
		passive->interface->max_accept_batch = processed;
}


static struct passive_context *
create_passive(struct ev_loop *loop, struct server_config *cfg)
{
	struct passive_context *passive = NULL;
	struct uinet_socket *listener = NULL;
	struct ev_uinet_ctx *soctx = NULL;
	struct uinet_in_addr addr;
	int optlen, optval;
	int error;
	struct uinet_sockaddr_in sin;

	if (uinet_inet_pton(UINET_AF_INET, cfg->listen_addr, &addr) <= 0) {
		printf("Malformed address %s\n", cfg->listen_addr);
		goto fail;
	}

	error = uinet_socreate(UINET_PF_INET, &listener, UINET_SOCK_STREAM, 0);
	if (0 != error) {
		printf("Listen socket creation failed (%d)\n", error);
		goto fail;
	}

	soctx = ev_uinet_attach(listener);
	if (NULL == soctx) {
		printf("Failed to alloc libev socket context\n");
		goto fail;
	}
	
	if ((error = uinet_make_socket_passive(listener))) {
		printf("Failed to make listen socket passive (%d)\n", error);
		goto fail;
	}

	if (cfg->interface->promisc) {
		if ((error = uinet_make_socket_promiscuous(listener, cfg->interface->cdom))) {
			printf("Failed to make listen socket promiscuous (%d)\n", error);
			goto fail;
		}
	}

	/* 
	 * The following settings will be inherited by all sockets created
	 * by this listen socket.
	 */
	uinet_sosetnonblocking(listener, 1);

	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_NODELAY, &optval, optlen)))
		goto fail;

	/* Wait 5 seconds for connections to complete */
	optlen = sizeof(optval);
	optval = 5;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPINIT, &optval, optlen)))
		goto fail;

	/* Begin counting down to close after 10 seconds of idle */
	optlen = sizeof(optval);
	optval = 10;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPIDLE, &optval, optlen)))
		goto fail;

	/* Count down to close once per second */
	optlen = sizeof(optval);
	optval = 1;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPINTVL, &optval, optlen)))
		goto fail;

	/* Close after idle for 3 counts */
	optlen = sizeof(optval);
	optval = 3;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_KEEPCNT, &optval, optlen)))
		goto fail;

	/* Wait 100 milliseconds for missing TCP segments */
	optlen = sizeof(optval);
	optval = 100;
	if ((error = uinet_sosetsockopt(listener, UINET_IPPROTO_TCP, UINET_TCP_REASSDL, &optval, optlen)))
		goto fail;



	passive = calloc(1, sizeof(struct passive_context));
	if (NULL == passive) {
		goto fail;
	}

	passive->loop = loop;
	passive->listener = listener;
	passive->verbose = cfg->verbose;
	passive->interface = cfg->interface;

	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr = addr;
	sin.sin_port = htons(cfg->listen_port);
	error = uinet_sobind(listener, (struct uinet_sockaddr *)&sin);
	if (0 != error) {
		printf("bind failed\n");
		goto fail;
	}
	
	error = uinet_solisten(passive->listener, -1);
	if (0 != error)
		goto fail;

	if (passive->verbose) {
		char buf[32];

		printf("Listening on %s:%u\n", uinet_inet_ntoa(addr, buf, sizeof(buf)), cfg->listen_port);
	}

	ev_init(&passive->listen_watcher, accept_cb);
	ev_uinet_set(&passive->listen_watcher, soctx, EV_READ);
	passive->listen_watcher.data = passive;
	ev_uinet_start(loop, &passive->listen_watcher);

	return (passive);

fail:
	if (soctx) ev_uinet_detach(soctx);
	if (listener) uinet_soclose(listener);
	if (passive) free(passive);

	return (NULL);
}


static void
dump_ifstat(const char *name)
{
	struct uinet_ifstat stat;
	int perline = 3;
	int index = 1;

#define PRINT_IFSTAT(s) printf("%-26s= %-10lu%s", #s, stat.s, (index % perline == 0) ? "\n" : "  "); index++ 

	uinet_getifstat(name, &stat);

	printf("========================================================================\n");
	printf("%s:\n", name);

	PRINT_IFSTAT(ifi_ipackets);
	PRINT_IFSTAT(ifi_ierrors);
	PRINT_IFSTAT(ifi_opackets);
	PRINT_IFSTAT(ifi_oerrors);
	PRINT_IFSTAT(ifi_collisions);
	PRINT_IFSTAT(ifi_ibytes);
	PRINT_IFSTAT(ifi_obytes);
	PRINT_IFSTAT(ifi_imcasts);
	PRINT_IFSTAT(ifi_omcasts);
	PRINT_IFSTAT(ifi_iqdrops);
	PRINT_IFSTAT(ifi_noproto);
	PRINT_IFSTAT(ifi_hwassist);
	PRINT_IFSTAT(ifi_epoch);

	printf("\n");
	printf("========================================================================\n");


#undef PRINT_IFSTAT
}


static void
dump_tcpstat()
{
	struct uinet_tcpstat stat;
	int perline = 3;
	int index = 1;

#define PRINT_TCPSTAT(s) printf("%-26s= %-10lu%s", #s, stat.s, (index % perline == 0) ? "\n" : "  "); index++ 

	uinet_gettcpstat(&stat);

	printf("========================================================================\n");

	PRINT_TCPSTAT(tcps_connattempt);
	PRINT_TCPSTAT(tcps_accepts);
	PRINT_TCPSTAT(tcps_connects);
	PRINT_TCPSTAT(tcps_drops);
	PRINT_TCPSTAT(tcps_conndrops);
	PRINT_TCPSTAT(tcps_minmssdrops);
	PRINT_TCPSTAT(tcps_closed);
	PRINT_TCPSTAT(tcps_segstimed);
	PRINT_TCPSTAT(tcps_rttupdated);
	PRINT_TCPSTAT(tcps_delack);
	PRINT_TCPSTAT(tcps_timeoutdrop);
	PRINT_TCPSTAT(tcps_rexmttimeo);
	PRINT_TCPSTAT(tcps_persisttimeo);
	PRINT_TCPSTAT(tcps_keeptimeo);
	PRINT_TCPSTAT(tcps_keepprobe);
	PRINT_TCPSTAT(tcps_keepdrops);

	PRINT_TCPSTAT(tcps_sndtotal);
	PRINT_TCPSTAT(tcps_sndpack);
	PRINT_TCPSTAT(tcps_sndbyte);
	PRINT_TCPSTAT(tcps_sndrexmitpack);
	PRINT_TCPSTAT(tcps_sndrexmitbyte);
	PRINT_TCPSTAT(tcps_sndrexmitbad);
	PRINT_TCPSTAT(tcps_sndacks);
	PRINT_TCPSTAT(tcps_sndprobe);
	PRINT_TCPSTAT(tcps_sndurg);
	PRINT_TCPSTAT(tcps_sndwinup);
	PRINT_TCPSTAT(tcps_sndctrl);

	PRINT_TCPSTAT(tcps_rcvtotal);
	PRINT_TCPSTAT(tcps_rcvpack);
	PRINT_TCPSTAT(tcps_rcvbyte);
	PRINT_TCPSTAT(tcps_rcvbadsum);
	PRINT_TCPSTAT(tcps_rcvbadoff);
	PRINT_TCPSTAT(tcps_rcvmemdrop);
	PRINT_TCPSTAT(tcps_rcvshort);
	PRINT_TCPSTAT(tcps_rcvduppack);
	PRINT_TCPSTAT(tcps_rcvdupbyte);
	PRINT_TCPSTAT(tcps_rcvpartduppack);
	PRINT_TCPSTAT(tcps_rcvpartdupbyte);
	PRINT_TCPSTAT(tcps_rcvoopack);
	PRINT_TCPSTAT(tcps_rcvoobyte);
	PRINT_TCPSTAT(tcps_rcvpackafterwin);
	PRINT_TCPSTAT(tcps_rcvbyteafterwin);
	PRINT_TCPSTAT(tcps_rcvafterclose);
	PRINT_TCPSTAT(tcps_rcvwinprobe);
	PRINT_TCPSTAT(tcps_rcvdupack);
	PRINT_TCPSTAT(tcps_rcvacktoomuch);
	PRINT_TCPSTAT(tcps_rcvackpack);
	PRINT_TCPSTAT(tcps_rcvackbyte);
	PRINT_TCPSTAT(tcps_rcvwinupd);
	PRINT_TCPSTAT(tcps_pawsdrop);
	PRINT_TCPSTAT(tcps_predack);
	PRINT_TCPSTAT(tcps_preddat);
	PRINT_TCPSTAT(tcps_pcbcachemiss);
	PRINT_TCPSTAT(tcps_cachedrtt);
	PRINT_TCPSTAT(tcps_cachedrttvar);
	PRINT_TCPSTAT(tcps_cachedssthresh);
	PRINT_TCPSTAT(tcps_usedrtt);
	PRINT_TCPSTAT(tcps_usedrttvar);
	PRINT_TCPSTAT(tcps_usedssthresh);
	PRINT_TCPSTAT(tcps_persistdrop);
	PRINT_TCPSTAT(tcps_badsyn);
	PRINT_TCPSTAT(tcps_mturesent);
	PRINT_TCPSTAT(tcps_listendrop);
	PRINT_TCPSTAT(tcps_badrst);

	PRINT_TCPSTAT(tcps_sc_added);
	PRINT_TCPSTAT(tcps_sc_retransmitted);
	PRINT_TCPSTAT(tcps_sc_dupsyn);
	PRINT_TCPSTAT(tcps_sc_dropped);
	PRINT_TCPSTAT(tcps_sc_completed);
	PRINT_TCPSTAT(tcps_sc_bucketoverflow);
	PRINT_TCPSTAT(tcps_sc_cacheoverflow);
	PRINT_TCPSTAT(tcps_sc_reset);
	PRINT_TCPSTAT(tcps_sc_stale);
	PRINT_TCPSTAT(tcps_sc_aborted);
	PRINT_TCPSTAT(tcps_sc_badack);
	PRINT_TCPSTAT(tcps_sc_unreach);
	PRINT_TCPSTAT(tcps_sc_zonefail);
	PRINT_TCPSTAT(tcps_sc_sendcookie);
	PRINT_TCPSTAT(tcps_sc_recvcookie);

	PRINT_TCPSTAT(tcps_hc_added);
	PRINT_TCPSTAT(tcps_hc_bucketoverflow);

	PRINT_TCPSTAT(tcps_finwait2_drops);

	PRINT_TCPSTAT(tcps_sack_recovery_episode);
	PRINT_TCPSTAT(tcps_sack_rexmits);
	PRINT_TCPSTAT(tcps_sack_rexmit_bytes);
	PRINT_TCPSTAT(tcps_sack_rcv_blocks);
	PRINT_TCPSTAT(tcps_sack_send_blocks);
	PRINT_TCPSTAT(tcps_sack_sboverflow);
	
	PRINT_TCPSTAT(tcps_ecn_ce);
	PRINT_TCPSTAT(tcps_ecn_ect0);
	PRINT_TCPSTAT(tcps_ecn_ect1);
	PRINT_TCPSTAT(tcps_ecn_shs);
	PRINT_TCPSTAT(tcps_ecn_rcwnd);

	PRINT_TCPSTAT(tcps_sig_rcvgoodsig);
	PRINT_TCPSTAT(tcps_sig_rcvbadsig);
	PRINT_TCPSTAT(tcps_sig_err_buildsig);
	PRINT_TCPSTAT(tcps_sig_err_sigopt);
	PRINT_TCPSTAT(tcps_sig_err_nosigopt);

#undef PRINT_TCPSTAT

	printf("\n");
	printf("========================================================================\n");
}


static void
if_stats_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct interface_config *cfg = w->data;

	dump_ifstat(cfg->alias);
	printf("num_sockets=%llu  max_accept_batch=%llu\n", (unsigned long long)cfg->num_sockets, (unsigned long long)cfg->max_accept_batch);
	if (cfg->do_tcpstats) {
		dump_tcpstat();
	}
}


void *interface_thread_start(void *arg)
{
	struct interface_config *cfg = arg;
	ev_timer if_stats_timer;

	uinet_initialize_thread();

	ev_init(&if_stats_timer, if_stats_timer_cb);
	ev_timer_set(&if_stats_timer, 1.0, 2.0);
	if_stats_timer.data = cfg;
	ev_timer_start(cfg->loop, &if_stats_timer);

	ev_run(cfg->loop, 0);

	return (NULL);
}


static void
usage(const char *progname)
{

	printf("Usage: %s [options]\n", progname);
	printf("    -h                   show usage\n");
	printf("    -i ifname            specify network interface\n");
	printf("    -l inaddr            listen address\n");
	printf("    -P                   put interface into Promiscuous INET mode\n");
	printf("    -p port              listen port [0, 65535]\n");
	printf("    -t iftype            interface type [netmap, pcap]\n");
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
	int iftype = UINET_IFTYPE_NETMAP;
	unsigned int i;
	int error;
	struct uinet_in_addr tmpinaddr;
	int ifnetmap_count = 0;
	int ifpcap_count = 0;

	memset(interfaces, 0, sizeof(interfaces));
	memset(servers, 0, sizeof(servers));

	for (i = 0; i < MAX_INTERFACES; i++) {
		interfaces[i].loop = NULL;
		interfaces[i].thread = NULL;
		interfaces[i].promisc = 0;
		interfaces[i].type = UINET_IFTYPE_NETMAP;
		interfaces[i].do_tcpstats = (i == 0);
	}

	for (i = 0; i < MAX_SERVERS; i++) {
		servers[i].listen_addr = NULL;
		servers[i].addrany = 0;
		servers[i].listen_port = -1;
		servers[i].passive = NULL;
	}

	while ((ch = getopt(argc, argv, "hi:l:Pp:t:v")) != -1) {
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
		case 'P':
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else {
				interfaces[num_interfaces - 1].promisc = 1;
			}
		case 'p':
			if (0 == interface_server_count) {
				printf("No listen address specified\n");
				return (1);
			} else {
				servers[num_servers - 1].listen_port = strtoul(optarg, NULL, 10);
			}
			break;
		case 't':
			if (0 == num_interfaces) {
				printf("No interface specified\n");
				return (1);
			} else if (0 == strcmp(optarg, "netmap")) {
				interfaces[num_interfaces - 1].type = UINET_IFTYPE_NETMAP;
			} else if (0 == strcmp(optarg, "pcap")) {
				interfaces[num_interfaces - 1].type = UINET_IFTYPE_PCAP;
			} else {
				printf("Unknown interface type %s\n", optarg);
				return (1);
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

		if (0 == servers[i].listen_port)
			servers[i].interface->promisc = 1;

		if (uinet_inet_pton(UINET_AF_INET, servers[i].listen_addr, &tmpinaddr) <= 0) {
			printf("%s is not a valid listen address\n", servers[i].listen_addr);
			return (1);
		}

		if (tmpinaddr.s_addr == UINET_INADDR_ANY) {
			servers[i].addrany = 1;
			servers[i].interface->promisc = 1;
		}
	}
	
	
	uinet_init(1, 128*1024, 0);

	for (i = 0; i < num_interfaces; i++) {
		switch (interfaces[i].type) {
		case UINET_IFTYPE_NETMAP:
			interfaces[i].alias_prefix = "netmap";
			interfaces[i].instance = ifnetmap_count;
			ifnetmap_count++;
			break;
		case UINET_IFTYPE_PCAP:
			interfaces[i].alias_prefix = "pcap";
			interfaces[i].instance = ifpcap_count;
			ifpcap_count++;
			break;
		default:
			printf("Unknown interface type %d\n", interfaces[i].type);
			return (1);
			break;
		}

		snprintf(interfaces[i].alias, UINET_IF_NAMESIZE, "%s%d", interfaces[i].alias_prefix, interfaces[i].instance);

		if (verbose) {
			printf("Creating interface %s, Promiscuous INET %s, cdom=%u\n",
			       interfaces[i].alias, interfaces[i].promisc ? "enabled" : "disabled",
			       interfaces[i].promisc ? interfaces[i].cdom : 0);
		}

		error = uinet_ifcreate(iftype, interfaces[i].ifname, interfaces[i].alias,
				       interfaces[i].promisc ? interfaces[i].cdom : 0,
				       0, NULL);
		if (0 != error) {
			printf("Failed to create interface %s (%d)\n", interfaces[i].alias, error);
		}

		interfaces[i].loop = ev_loop_new(EVFLAG_AUTO);
		if (NULL == interfaces[i].loop) {
			printf("Failed to create event loop interface %s\n", interfaces[i].alias);
			break;
		}
		
	}
	
		
	for (i = 0; i < num_servers; i++) {
		if (!servers[i].addrany) {
			if (verbose) {
				printf("Adding address %s to interface %s\n", servers[i].listen_addr, servers[i].interface->alias);
			}
			
			error = uinet_interface_add_alias(servers[i].interface->alias, servers[i].listen_addr, "", "");
			if (error) {
				printf("Adding alias %s to interface %s failed (%d)\n", servers[i].listen_addr, servers[i].interface->alias, error);
			}
		}
	}


	for (i = 0; i < num_servers; i++) {
		if (verbose) {
			printf("Creating passive server at %s:%d on interface %s\n",
			       servers[i].listen_addr, servers[i].listen_port,
			       servers[i].interface->alias);
		}

		servers[i].verbose = verbose;

		servers[i].passive = create_passive(servers[i].interface->loop, &servers[i]);
		if (NULL == servers[i].passive) {
			printf("Failed to create passive server at %s:%d on interface %s\n",
			       servers[i].listen_addr, servers[i].listen_port,
			       servers[i].interface->alias);
			break;
		}
	}


	for (i = 0; i < num_interfaces; i++) {
		if (verbose) {
			printf("Bringing up interface %s\n", interfaces[i].alias);
		}

		error = uinet_interface_up(interfaces[i].alias, 1, interfaces[i].promisc);
		if (0 != error) {
			printf("Failed to bring up interface %s (%d)\n", interfaces[i].alias, error);
		}

		if (verbose)
			printf("Creating interface thread for interface %s\n", interfaces[i].alias);

		interfaces[i].thread_create_result = pthread_create(&interfaces[i].thread, NULL,
								    interface_thread_start, &interfaces[i]);
	}

	for (i = 0; i < num_interfaces; i++) {
		if (0 == interfaces[i].thread_create_result)
			pthread_join(interfaces[i].thread, NULL);
	}

	for (i = 0; i < num_interfaces; i++) {
		uinet_ifdestroy_byname(interfaces[i].alias);
	}

	return (0);
}
