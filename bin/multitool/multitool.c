/*
 * Copyright (c) 2015-2016 Patrick Kelsey. All rights reserved.
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

#if defined(__linux__)
/*
 * To expose:
 *     CPU_SET()
 *     CPU_ZERO()
 *
 *     pthread_setaffinity_np()
 */
#define _GNU_SOURCE
#endif /* __linux__ */

#include <assert.h>
#include <getopt.h>
#include <pthread.h>
#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif /* __FreeBSD__ */
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/thread_policy.h>
#endif

#if defined(__linux__)
typedef cpu_set_t cpuset_t;
#endif /* __linux__ */

#include "uinet_api.h"
#include "uinet_ev.h"
#include "uinet_demo_connscale.h"
#include "uinet_demo_echo.h"
#include "uinet_demo_nproxy.h"
#include "uinet_demo_passive.h"
#include "uinet_demo_passive_extract.h"


#define MAX_APPS 64
#define MAX_EVENT_LOOPS 64
#define MAX_STACKS 64
#define MAX_IFS 64

#define DEFAULT_GEN_LEN 758

struct stack_config;

struct event_loop_config {
	char name[UINET_NAME_BUF_LEN];
	unsigned int verbose;
	int cpu;
	int has_thread;
	pthread_t thread_id;
	ev_timer shutdown_watcher;
	ev_timer stats_watcher;
	unsigned int stats_interval;
	unsigned int first_stats;
	struct stack_config *scfgs[MAX_STACKS];
	unsigned int num_stacks;

	ev_loop_counters last_counters;

	struct ev_loop *loop;
};


struct interface_config;

struct stack_config {
	char name[UINET_NAME_BUF_LEN];
	unsigned int sts;
	unsigned int verbose;
	struct interface_config *ifcfgs[MAX_IFS];
	unsigned int num_ifs;
	struct uinet_demo_config *acfgs[MAX_APPS * UINET_NUM_DEMO_APPS];
	unsigned int num_apps;
	ev_timer stats_watcher;
	unsigned int stats_interval;
	unsigned int first_stats;
	ev_tstamp first_stats_time;
	unsigned int syncache_stats;

	struct event_loop_config *elcfg;
	uinet_instance_t uinst;
};


struct interface_config {
	struct uinet_if_cfg ucfg;
	const char *type_name;
	unsigned int verbose;
	int generate;
	unsigned int gen_len;
	ev_timer gen_watcher;
	const char *bridge_ifs;
	struct interface_config *bridge_to[MAX_IFS];
	unsigned int num_bridge_to;
	struct uinet_pd_list *pkts;
	unsigned int max_pkts;
	uint64_t counter;
	uint32_t trace_mask;
	struct uinet_ifstat last_stat;

	struct stack_config *scfg;
	uinet_if_t uif;
};


static pthread_mutex_t print_lock;
static volatile int shutting_down;


struct {
	uinet_if_timestamp_mode_t mode;
	const char *name;
	const char *desc;
} timestamp_mode_table[] = {
	{ UINET_IF_TIMESTAMP_NONE,	     "none",           "Timestamps are all zero" },
	{ UINET_IF_TIMESTAMP_HW,	     "hw",             "Supplied by driver" },
	{ UINET_IF_TIMESTAMP_COUNTER,	     "counter",        "Interface-local counter" },
	{ UINET_IF_TIMESTAMP_GLOBAL_COUNTER, "global-counter", "Global counter" },
	{ UINET_IF_TIMESTAMP_MONOTONIC,	     "monotonic",      "System CLOCK_MONOTONIC" },
	{ UINET_IF_TIMESTAMP_MONOTONIC_FAST, "monotonic-fast", "System CLOCK_MONOTONIC_FAST" }
};

enum multitool_opt_id {
	MIN_MT_OPT_VALUE = 1000, /* always first */

	MT_OPT_BASE_CONFIG,
	MT_OPT_MAXSOCKETS,
	MT_OPT_NETMAP_EXTRA_BUFS,
	MT_OPT_NMBCLUSTERS,
	MT_OPT_PCAP_TX_FILE_DIRBITS,
	MT_OPT_PCAP_TX_FILE_MODE,
	MT_OPT_SOMAXCONN,
	MT_OPT_SYNCACHE_BUCKETLIMIT,
	MT_OPT_SYNCACHE_CACHELIMIT,
	MT_OPT_SYNCACHE_HASHSIZE,
	MT_OPT_SYNCACHE_STATS,
	MT_OPT_TCBHASHSIZE,

	MAX_MT_OPT_VALUE /* always last */
};


static const struct option long_options[] = {
/* global options */
	{ "base-config",	required_argument,	NULL, MT_OPT_BASE_CONFIG },
	{ "config-only",	no_argument,		NULL, 'N' },
	{ "max-accept-queue",	required_argument,	NULL, MT_OPT_SOMAXCONN },
	{ "max-clusters",	required_argument,	NULL, MT_OPT_NMBCLUSTERS },
	{ "max-sockets",	required_argument,	NULL, MT_OPT_MAXSOCKETS },
	{ "netmap-extra-bufs",	required_argument,	NULL, MT_OPT_NETMAP_EXTRA_BUFS },
	{ "syncache-hash-size",  required_argument,	NULL, MT_OPT_SYNCACHE_HASHSIZE },
	{ "syncache-bucket-limit", required_argument,	NULL, MT_OPT_SYNCACHE_BUCKETLIMIT },
	{ "syncache-cache-limit", required_argument,	NULL, MT_OPT_SYNCACHE_CACHELIMIT },
	{ "tcb-hash-size",	required_argument,	NULL, MT_OPT_TCBHASHSIZE },

/* event loop options */
	{ "eloop",		optional_argument,	NULL, 'e' },
	{ "eloop-cpu",		required_argument,	NULL, 'c' },
	{ "stats",		optional_argument,	NULL, 'm' },

/* stack instance options */
	{ "brief-tcp-stats",	optional_argument,	NULL, 'J' },
	{ "stack",		optional_argument,	NULL, 's' },
	{ "sts",		no_argument,		NULL, 'S' },
	{ "syncache-stats",	no_argument,		NULL, MT_OPT_SYNCACHE_STATS },

/* interface types */
	{ "netmap",		required_argument,	NULL, 'n' },
	{ "pcap",		required_argument,	NULL, 'p' },

/* per-interface options */
	{ "bridge-to",		required_argument,	NULL, 'b' },
	{ "gen",		optional_argument, 	NULL, 'g' },
	{ "iqlen",		required_argument,	NULL, 'I' },
	{ "rxcpu",		required_argument,	NULL, 'r' },
	{ "pcap-tx-file-dirbits", required_argument,	NULL, MT_OPT_PCAP_TX_FILE_DIRBITS },
	{ "pcap-tx-file-mode",	required_argument,	NULL, MT_OPT_PCAP_TX_FILE_MODE },
	{ "txcpu",		required_argument,	NULL, 't' },
	{ "rxbatch",		required_argument,	NULL, 'R' },
	{ "timestamp-mode",	required_argument,	NULL, 'T' },
	{ "trace-mask",		required_argument,	NULL, 'Z' },

	{ "help",		no_argument,		NULL, 'h' },
	{ "verbose",		optional_argument,	NULL, 'v' },

/* demo app options */
	{ "connscale",		optional_argument,	NULL, 'C' },
	{ "echo",		optional_argument,	NULL, 'E' },
	{ "nproxy",		optional_argument,	NULL, 'O' },
	{ "passive",		optional_argument,	NULL, 'P' },
	{ "passive-extract",	optional_argument,	NULL, 'X' },

	{ 0, 0, 0, 0 }
};


static void
usage(const char *progname)
{
	unsigned int i;

	printf("\n");
	printf("Usage: %s [global] [default loop] [default stack] [[intf|app] ... ] [loop [stack [intf|app] ... ] ... ] ...\n", progname);
	printf("\n");
	printf("This is a tool for creating and arranging libev event loops, libuinet\n");
	printf("stack instances, libuinet network interfaces, and libuinet demo apps.\n");
	printf("The model is that an event loop contains stack instances, and a stack\n");
	printf("instance contains network interfaces and demo apps.  That is not the\n");
	printf("only way things can be arranged with libuinet, but it covers most of\n");
	printf("the sensible cases.\n");
	printf("\n");
	printf("Global options:\n");
	printf("\n");
	printf("  --base-config [small|medium|large]\n");
	printf("                          Choose base global config to use (default 'medium')\n");
	printf("  --config-only, -N       Print the configuration and exit (can be specified at any point)\n");
	printf("  --help, -h              Print this message (can be specified at any point)\n");
	printf("  --max-accept-queue <value>\n");
	printf("                          Set the maximum listen socket accept queue length\n");
	printf("  --max-clusters <value>  Set the upper limit on the global mbuf cluster pool size\n");
	printf("  --max-sockets <value>   Set the maximum number of sockets per stack instance\n");
	printf("  --netmap-extra-bufs <buffers>\n");
	printf("                          Size of process-wide netmap extra buffer pool shared by netmapped physical interfaces\n");
	printf("  --syncache-hash-size <value>\n");
	printf("                          Set the number of buckets in each stack instance's syncache hash\n");
	printf("  --syncache-bucket-limit <value>\n");
	printf("                          Set the maximum number of entries in each syncache hash bucket\n");
	printf("  --syncache-cache-limit <value>\n");
	printf("                          Set the maximum number of entries in each stack instance's syncache\n");
	printf("  --tcb-hash-size <value> Set the number of buckets in each stack instance's tcp connection hash\n");
	printf("  --verbose, -v [=level]  Increase baseline verbosity, or set to given level (can use multiple times)\n");
	printf("\n");
	printf("Event loop options:\n");
	printf("\n");
	printf("  --eloop, -e             Create a new event loop\n");
	printf("  --eloop-cpu, -c <cpu>   Bind the current event loop to the given CPU\n");
	printf("  --stats, -m [=interval] Print stats for event loop and all it contains every <interval> seconds (default 1)\n");
	printf("  --verbose, -v [=level]  Increase event loop verbosity above the baseline, or set to given level (can use multiple times)\n");
	printf("\n");
	printf("Stack instance options:\n");
	printf("\n");
	printf("  --brief-tcp-stats [=interval]\n");
	printf("                          Print brief TCP stats every <interval> seconds (default 1)\n");
	printf("  --stack, -s [=name]     Create a new stack instance in the current event loop, with optional name\n");
	printf("  --sts, -S               Run stack instance in single-thread-stack mode\n");
	printf("  --syncache-stats        Print syncache stats for this stack instance when event loop stats are enabled\n");
	printf("\n");
	printf("Interface creation options:\n");
	printf("\n");
	printf("  --netmap, -n <config>   Create a new netmap interface in the current stack using the given config string\n");
	printf("  --pcap, -p <config>     Create a new pcap interface in the current stack using the given config string\n");
	printf("\n");
	printf("General interface configuration options:\n");
	printf("\n");
	printf("  --bridge-to, -b <intf_list>\n");
	printf("                          Transmit all inbound packets on this interface from each of the given list of interfaces\n");
	printf("  --gen, -g [=packet_len] Generate transmit packets of the given size (default %u)\n", DEFAULT_GEN_LEN);
	printf("  --iqlen, -I <value>     Set max transmit inject queue length\n");
	printf("  --pcap-tx-file-dirbits <n>\n");
	printf("                          Set number of bits of flow serial number to use for choosing subdirectories in pcap file-per-flow transmit-to-file mode (default 10)\n");
	printf("  --pcap-tx-file-mode <mode>\n");
	printf("                          Set pcap transmit-to-file mode to one of [single-file, file-per-flow] (default single-file)\n");
	printf("  --rxbatch, -R <value>   Set receive processing batch size limit\n");
	printf("  --rxcpu, -r <cpu>       Bind interface receive thread to the given CPU (ignored in STS mode)\n");
	printf("  --txcpu, -t <cpu>       Bind interface transmit thread to the given CPU (ignored in STS mode)\n");
	printf("  --timestamp-mode, -T <mode>\n");
	printf("                          Set interface timestamp mode to one of:\n");
	for (i = 0; i < sizeof(timestamp_mode_table) / sizeof(timestamp_mode_table[0]); i++) {
		printf("                            %16s  %s\n",  timestamp_mode_table[i].name, timestamp_mode_table[i].desc);
	}
	printf("  --trace-mask, -Z <mask> Mask of driver trace message enables (see driver source)\n");
	printf("\n");
	printf("Demo app creation options:\n");
	printf("\n");
	printf("  --connscale, -C [=name] Create a connscale client or server in the current stack, with optional name\n");
	printf("  --echo, -E [=name]      Create an echo server in the current stack, with optional name\n");
	printf("  --nproxy, -O [=name]    Create a non-transparent proxy server in the current stack, with optional name\n");
	printf("  --passive, -P [=name]   Create a passive reassembly server in the current stack, with optional name\n");
	printf("  --passive-extract, -X [=name]\n");
	printf("                          Create a passive reassembly server that extracts http payloads in the current stack, with optional name\n");
	printf("\n");
	for (i = 0; i < UINET_NUM_DEMO_APPS; i++) {
		printf("Options for configuring %s instances:\n", uinet_demo_name(i));
		printf("\n");
		uinet_demo_print_usage(i);
		printf("\n");
	}
}


/* XXX copied from uinet_host_interface.c ... should probably just export uhi routines as part of the API */
static void
uhi_thread_bind(unsigned int cpu)
{
#if defined(__APPLE__)
	mach_port_t mach_thread = pthread_mach_thread_np(pthread_self());
	thread_affinity_policy_data_t policy_data = { cpu + 1 };   /* cpu + 1 to avoid using THREAD_AFFINITY_TAG_NULL */
	thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy_data, THREAD_AFFINITY_POLICY_COUNT);
#else
	cpuset_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu % CPU_SETSIZE, &cpuset);
	pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t), &cpuset);
#endif /* __APPLE__ */
}


int
get_timestamp_mode(const char *name, uinet_if_timestamp_mode_t *mode)
{
	unsigned int i;

	for (i = 0; i < sizeof(timestamp_mode_table) / sizeof(timestamp_mode_table[0]); i++) {
		if (0 == strcmp(name, timestamp_mode_table[i].name)) {
			*mode = timestamp_mode_table[i].mode;
			return (0);
		}
	}
	
	return (1);
}

static void
first_look_handler(void *arg, struct uinet_pd_list *pkts)
{
	struct interface_config *ifcfg;
	unsigned int i;
	uint16_t flags;
#define FREE_GROUP_MAX	32
	struct uinet_pd_ctx *free_group[FREE_GROUP_MAX];
	unsigned int free_group_count;
	unsigned int to_stack;
	unsigned int num_extra_refs;

	ifcfg = (struct interface_config *)arg;
	to_stack = ifcfg->scfg->num_apps ? 1 : 0;

	if ((ifcfg->verbose > 1) && to_stack)
		printf("%s (%s): First-look handler sending %d packets to the stack\n",
		       ifcfg->ucfg.alias, ifcfg->ucfg.configstr, pkts->num_descs);

	if (ifcfg->num_bridge_to > 0) {
		if (ifcfg->verbose > 1)
			printf("%s (%s): First-look handler bridging to %u interface%s\n",
			       ifcfg->ucfg.alias, ifcfg->ucfg.configstr,
			       ifcfg->num_bridge_to, (ifcfg->num_bridge_to == 1) ? "" : "s"); 

		num_extra_refs = ifcfg->num_bridge_to - 1;

		/*
		 * Mark the packets that we want to inject, and add extra
		 * refs if there is more than one bridge_to destination.
		 */
		flags = (num_extra_refs > 0) ? UINET_PD_INJECT | UINET_PD_EXTRA_REFS : UINET_PD_INJECT;
		for (i = 0; i < pkts->num_descs; i++) {
			/*
			 * Packets from from the interface marked with
			 * UINET_PD_TO_STACK by default, so clear it if we
			 * don't want that behavior.
			 */
			if (!to_stack)
				pkts->descs[i].flags &= ~UINET_PD_TO_STACK;
			pkts->descs[i].flags |= flags;
		}

		/*
		 * Adjust the refcounts if need be based on the descriptor
		 * flags and number of requested extra refs.
		 */
		uinet_pd_ref_acquire(pkts, num_extra_refs);

		for (i = 0; i < ifcfg->num_bridge_to; i++)
			uinet_if_inject_tx_packets(ifcfg->bridge_to[i]->uif, pkts);
	} else if (!to_stack) {
		if (ifcfg->verbose > 1)
			printf("%s (%s): First-look handler discarding packets\n",
			       ifcfg->ucfg.alias, ifcfg->ucfg.configstr);

		free_group_count = 0;
		for (i = 0; i < pkts->num_descs; i++) {
			pkts->descs[i].flags &= ~UINET_PD_TO_STACK;
			free_group[free_group_count++] = pkts->descs[i].ctx;
			if (free_group_count == FREE_GROUP_MAX) {
				uinet_pd_ref_release(free_group, free_group_count);
				free_group_count = 0;
			}
		}
		if (free_group_count)
				uinet_pd_ref_release(free_group, free_group_count);
	}
	/* else the driver will send them to the stack upon return */
}


static void
init_ifcfg(struct interface_config *ifcfg, unsigned int ifno, uinet_iftype_t type,
	   const char *configstr)
{
	char namebuf[UINET_NAME_BUF_LEN];

	memset(ifcfg, 0, sizeof(struct interface_config));

	uinet_if_default_config(type, &ifcfg->ucfg);
	ifcfg->ucfg.configstr = configstr;
	snprintf(namebuf, UINET_NAME_BUF_LEN, "if%u", ifno);
	ifcfg->ucfg.alias = strdup(namebuf);
	ifcfg->ucfg.first_look_handler = first_look_handler;
	ifcfg->ucfg.first_look_handler_arg = ifcfg;
	ifcfg->gen_len = DEFAULT_GEN_LEN;
	ifcfg->bridge_ifs = "";

	/* XXX need to detect vale and set accordingly */
	if (type == UINET_IFTYPE_NETMAP) {
		ifcfg->ucfg.type_cfg.netmap.vale_num_extra_bufs = 8192;
		ifcfg->ucfg.type_cfg.netmap.trace_mask = 0;
	}
}


static struct interface_config *
get_ifcfg(struct interface_config *ifcfgs, unsigned int num_ifs, const char *configstr)
{
	unsigned int i;
	
	for (i = 0; i < num_ifs; i++) {
		if (strcmp(configstr, ifcfgs[i].ucfg.configstr) == 0)
			return (&ifcfgs[i]);
	}

	for (i = 0; i < num_ifs; i++) {
		if (strcmp(configstr, ifcfgs[i].ucfg.alias) == 0)
			return (&ifcfgs[i]);
	}

	return (NULL);
}


static int
configure_bridging(struct interface_config *ifcfgs, unsigned int num_ifs, unsigned int which)
{
	struct interface_config *ifcfg;
	int if_index;
	const char *p, *comma;
	int to_copy;
	char ifnamebuf[256];
	const char *ifname;
	struct interface_config *bridge_to;

	/*
	 * Resolve comma-separated list of interface names to an array of
	 * interface config pointers. 
	 */
	ifcfg = &ifcfgs[which];
	p = ifcfg->bridge_ifs;
	while (p && (*p != '\0')) {
		comma = strchr(p, ',');
		if (comma != NULL) {
			to_copy = comma - p;
			if (to_copy == 0)
				continue;
			if (to_copy > sizeof(ifnamebuf) - 1)
				to_copy = sizeof(ifnamebuf) - 1;
			memcpy(ifnamebuf, p, to_copy);
			p = comma + 1;
			ifnamebuf[to_copy] = '\0';
			ifname = ifnamebuf;
		} else {
			ifname = p;
			p = NULL;
		}
		bridge_to = get_ifcfg(ifcfgs, num_ifs, ifname);
		if (bridge_to == NULL) {
			printf("%s (%s): Invalid bridge-to interface \"%s\"\n",
			       ifcfg->ucfg.alias, ifcfg->ucfg.configstr, ifname);
			return (-1);
		}
		ifcfg->bridge_to[ifcfg->num_bridge_to++] = bridge_to;
	}

	return (0);
}


static void
print_cpu(const char *label, int cpu)
{
	if (cpu < 0)
		printf("%s=auto", label);
	else
		printf("%s=%d", label, cpu);
}


static void
print_timestamp_mode(const char *label, uinet_if_timestamp_mode_t mode)
{
	unsigned int i;

	for (i = 0; i < sizeof(timestamp_mode_table) / sizeof(timestamp_mode_table[0]); i++) {
		if (timestamp_mode_table[i].mode == mode) {
			printf("%s=%s", label, timestamp_mode_table[i].name);
			return;
		}
	}
	printf("%s=<unknown>", label);
}


static void
print_cfg(struct event_loop_config *elcfgs, unsigned int num_event_loops)
{
	unsigned int i, j;
	unsigned int bridge_tos;
	struct event_loop_config *curloopcfg;
	struct stack_config *curstackcfg;
	struct interface_config *curifcfg;
	struct uinet_demo_config *curappcfg;
	unsigned int stack_index;
	unsigned int if_index;
	unsigned int app_index;
	int rxcpu, txcpu;

	for (i = 0; i < num_event_loops; i++) {
		curloopcfg = &elcfgs[i];
		printf("Event loop [%s]: cpu=", curloopcfg->name);
		if (curloopcfg->cpu < 0)
			printf("auto");
		else
			printf("%u", curloopcfg->cpu);
		printf("\n");

		for (stack_index = 0; stack_index < curloopcfg->num_stacks; stack_index++) {
			curstackcfg = curloopcfg->scfgs[stack_index];
			printf("  Stack instance [%s]: sts-mode=%s\n",
			       curstackcfg->name, curstackcfg->sts ? "yes" : "no");

			for (if_index = 0; if_index < curstackcfg->num_ifs; if_index++) {
				curifcfg = curstackcfg->ifcfgs[if_index];
				printf("    Interface [%s (%s)]: type=%s rxbatch=%u txiqlen=%u gen=%s len=%u",
				       curifcfg->ucfg.alias, curifcfg->ucfg.configstr,
				       curifcfg->type_name,
				       curifcfg->ucfg.rx_batch_size,
				       curifcfg->ucfg.tx_inject_queue_len,
				       curifcfg->generate ? "yes" : "no",
				       curifcfg->generate ? curifcfg->gen_len : 0);

				printf(" bridge_to=");
				if (curifcfg->num_bridge_to) {
					for (j = 0; j < curifcfg->num_bridge_to; j++) {
						printf("%s%s (%s)", (j > 0) ? "," : "",
						       curifcfg->bridge_to[j]->ucfg.alias,
						       curifcfg->bridge_to[j]->ucfg.configstr);
					}
				} else 
					printf("<none>");

				if (curstackcfg->sts)
					txcpu = rxcpu = curloopcfg->cpu;
				else {
					txcpu = curifcfg->ucfg.tx_cpu;
					rxcpu = curifcfg->ucfg.rx_cpu;
				}

				print_cpu(" rxcpu", txcpu);
				print_cpu(" txcpu", txcpu);

				print_timestamp_mode(" tstamp", curifcfg->ucfg.timestamp_mode);

				switch (curifcfg->ucfg.type) {
				case UINET_IFTYPE_NETMAP:
					printf(" trace=0x%08x", curifcfg->ucfg.type_cfg.netmap.trace_mask);
					printf(" valebufs=%u", curifcfg->ucfg.type_cfg.netmap.vale_num_extra_bufs);
					break;
				case UINET_IFTYPE_PCAP:
					printf(" txio=%s", curifcfg->ucfg.type_cfg.pcap.use_file_io_thread ? "remote" : "local");
					printf(" txsnaplen=%u", curifcfg->ucfg.type_cfg.pcap.file_snapshot_length);
					printf(" txfiles=%s", curifcfg->ucfg.type_cfg.pcap.file_per_flow ? "per-flow" : "single");
					printf(" txmaxfds=%u", curifcfg->ucfg.type_cfg.pcap.max_concurrent_files);
					printf(" txdirbits=%u", curifcfg->ucfg.type_cfg.pcap.dir_bits);
					break;
				default:
					break;
				}

				printf("\n");
			}
			if (if_index == 0)
				printf("    <no interfaces>\n");

			for (app_index = 0; app_index < curstackcfg->num_apps; app_index++) {
				curappcfg = curstackcfg->acfgs[app_index];
				printf("    %s [%s]: ", uinet_demo_name(curappcfg->which), curappcfg->name);
				uinet_demo_print_cfg(curappcfg);
				printf("\n");
			}
			if (app_index == 0)
				printf("    <no apps>\n");

		}
		if (stack_index == 0)
			printf("  <no stacks>\n");
	}
}


static void
stack_stats_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct stack_config *scfg = w->data;
	struct uinet_tcpstat stat;
	int num_open_sockets = 0;
	size_t len;
	ev_tstamp timestamp;

	if (scfg->first_stats) {
		scfg->first_stats_time = ev_now(loop);
		scfg->first_stats = 0;
	}

	uinet_gettcpstat(scfg->uinst, &stat);

	len = sizeof(num_open_sockets);
	uinet_sysctlbyname(scfg->uinst, "kern.ipc.numopensockets", (char *)&num_open_sockets,
			   &len, NULL, 0, NULL, 0);

	timestamp = ev_now(loop) - scfg->first_stats_time;

#define PRINT_TCPSTAT(s)	printf("%.6f %s = %llu\n", timestamp, #s, (unsigned long long)stat.s)

	printf("%.6f num_sockets = %u\n", timestamp, num_open_sockets);
	PRINT_TCPSTAT(tcps_connects);
	PRINT_TCPSTAT(tcps_closed);

#undef PRINT_TCPSTAT
}


static void
stats_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct event_loop_config *elcfg = w->data;
	struct stack_config *scfg;
	struct interface_config *ifcfg;
	struct uinet_tcpstat tcpstat;
	struct uinet_ifstat stat;
	unsigned int i, j;
	char tmpbuf[32];
	ev_loop_counters *loop_counters;

	pthread_mutex_lock(&print_lock);
	loop_counters = ev_loop_counters_get(elcfg->loop);
	if (elcfg->first_stats)
		printf("[%s] iterations:%11llu ips: %11s\n", elcfg->name,
		       (unsigned long long)loop_counters->iterations, "--");
	else
		printf("[%s] iterations:%11llu ips: %11.1f\n", elcfg->name,
		       (unsigned long long)loop_counters->iterations,
		       (double)(loop_counters->iterations - elcfg->last_counters.iterations) / elcfg->stats_interval);
	elcfg->last_counters = *loop_counters;
	for (i = 0; i < elcfg->num_stacks; i++) {
		scfg = elcfg->scfgs[i];
		snprintf(tmpbuf, sizeof(tmpbuf), "  [%s]", scfg->name);
		if (scfg->syncache_stats) {
			uinet_gettcpstat(scfg->uinst, &tcpstat);
			printf("%s  syncache stats\n", tmpbuf);
#define PRINT_SYNCACHE_ROW(a,b,c) printf("    %14s=%11lu   %14s=%11lu   %14s=%11lu\n", \
					 #a, tcpstat.tcps_sc_##a,	\
					 #b, tcpstat.tcps_sc_##b,	\
					 #c, tcpstat.tcps_sc_##c)
			PRINT_SYNCACHE_ROW(added, retransmitted, dupsyn);
			PRINT_SYNCACHE_ROW(dropped, completed, bucketoverflow);
			PRINT_SYNCACHE_ROW(cacheoverflow, reset, stale);
			PRINT_SYNCACHE_ROW(aborted, badack, unreach);
			PRINT_SYNCACHE_ROW(zonefail, sendcookie, recvcookie);
#undef PRINT_SYNCACHE_ROW
		}
		printf("%-16s %11s %11s %11s %11s %11s %11s %8s %8s %8s %8s\n", tmpbuf,
		       "in_copy", "in_zcopy", "in_drop", "out_copy", "out_zcopy", "out_drop",
		       "in_Kpps", "in_MBps", "out_Kpps", "out_MBps");
		for (j = 0; j < scfg->num_ifs; j++) {
			ifcfg = scfg->ifcfgs[j];

			uinet_getifstat(ifcfg->uif, &stat);
			snprintf(tmpbuf, sizeof(tmpbuf), "%s (%s)", ifcfg->ucfg.alias, ifcfg->ucfg.configstr);
			printf("%16s %11lu %11lu %11lu %11lu %11lu %11lu",
			       tmpbuf,
			       stat.ifi_icopies, stat.ifi_izcopies, stat.ifi_iqdrops,
			       stat.ifi_ocopies, stat.ifi_ozcopies, stat.ifi_oerrors);
			if (elcfg->first_stats) {
				printf(" %8s %8s %8s %8s\n", "--", "--", "--", "--");
			} else {
				printf(" %8.1f %8.1f %8.1f %8.1f\n",
				       (stat.ifi_ipackets - ifcfg->last_stat.ifi_ipackets) / 1000. / elcfg->stats_interval,
				       (stat.ifi_ibytes - ifcfg->last_stat.ifi_ibytes) / 1000000. / elcfg->stats_interval,
				       (stat.ifi_opackets - ifcfg->last_stat.ifi_opackets) / 1000. / elcfg->stats_interval,
				       (stat.ifi_obytes - ifcfg->last_stat.ifi_obytes) / 1000000. / elcfg->stats_interval);
			}
			ifcfg->last_stat = stat;
		}
	}
	elcfg->first_stats = 0;

	pthread_mutex_unlock(&print_lock);
}


static void
shutdown_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	if (shutting_down)
		ev_break(loop, EVBREAK_ALL);
}


static void
generate_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct interface_config *ifcfg = w->data;
	struct uinet_pd *cur_pd;
	uint32_t i;

	if (ifcfg->max_pkts > 0) {
		ifcfg->pkts->num_descs = ifcfg->max_pkts;
		uinet_if_pd_alloc(ifcfg->uif, ifcfg->pkts);
		if (ifcfg->pkts->num_descs > 0) {
			for (i = 0; i < ifcfg->pkts->num_descs; i++) {
				ifcfg->counter++;
				cur_pd = &ifcfg->pkts->descs[i];
				cur_pd->data[0] = htonl(0x02000000);
				cur_pd->data[1] = htonl(0x00010200);
				cur_pd->data[2] = htonl(0x00000002);
				cur_pd->data[3] = htonl(0x08000000);
				cur_pd->data[4] = htonl(ifcfg->counter >> 32);
				cur_pd->data[5] = htonl(ifcfg->counter);
				cur_pd->length = ifcfg->gen_len - 4;
				cur_pd->flags |= UINET_PD_INJECT;
			}
			uinet_if_inject_tx_packets(ifcfg->uif, ifcfg->pkts);
		} else 
			printf("%s (%s): 0 pds alloced\n", ifcfg->ucfg.alias, ifcfg->ucfg.configstr);
	}
}


static void *
loop_thread(void *arg)
{
	struct event_loop_config *elcfg;
	struct stack_config *curstackcfg;
	struct uinet_demo_config *curappcfg;
	struct uinet_pd_list *pkts = NULL;
	struct uinet_pd *cur_pd;
	uint32_t max_pkts;
	uint64_t counter;
	unsigned int i, j;

	elcfg = arg;
	if (elcfg->cpu >= 0)
		uhi_thread_bind(elcfg->cpu);

	uinet_initialize_thread(elcfg->name);

	if (elcfg->verbose)
		printf("Event loop %s started on cpu %d\n", elcfg->name, elcfg->cpu);

	/*
	 * Time has passed, perhaps a lot of it, since this loop was
	 * initialized.  Updating its current time here prevents newly
	 * created timers from firing immediately due to the (irrelevant)
	 * time that has passed between loop initialization and now.
	 */
	ev_now_update(elcfg->loop);

	for (i = 0; i < elcfg->num_stacks; i++) {
		curstackcfg = elcfg->scfgs[i];

		/* start stats watchers */
		if (curstackcfg->stats_interval > 0) {
			ev_timer_init(&curstackcfg->stats_watcher, stack_stats_cb,
				      curstackcfg->stats_interval, curstackcfg->stats_interval);
			curstackcfg->stats_watcher.data = curstackcfg;
			ev_timer_start(curstackcfg->elcfg->loop, &curstackcfg->stats_watcher);
		}

		/* start apps */
		for (j = 0; j < curstackcfg->num_apps; j++) {
			curappcfg = curstackcfg->acfgs[j];
			if (0 != uinet_demo_start(curappcfg, curstackcfg->uinst,
						  elcfg->loop))
				printf("%s: %s: Failed to start %s %s\n",
				       elcfg->name,
				       curstackcfg->name,
				       uinet_demo_name(curappcfg->which),
				       curappcfg->name);
		}
	}

	ev_run(elcfg->loop, 0);

	if (elcfg->verbose)
		printf("Event loop %s exiting\n", elcfg->name);

	uinet_finalize_thread();

	return (NULL);
}


static void
cleanup_handler(int signo, siginfo_t *info, void *uap)
{
	shutting_down = 1;
}


int main(int argc, char **argv)
{
	int opt;
	struct event_loop_config elcfgs[MAX_EVENT_LOOPS];
	struct stack_config scfgs[MAX_STACKS];
	struct interface_config ifcfgs[MAX_IFS];
	struct uinet_demo_connscale connscalecfgs[MAX_APPS];
	struct uinet_demo_echo echocfgs[MAX_APPS];
	struct uinet_demo_nproxy nproxycfgs[MAX_APPS];
	struct uinet_demo_passive passivecfgs[MAX_APPS];
	struct uinet_demo_passive_extract passivexcfgs[MAX_APPS];
	struct event_loop_config *curloopcfg;
	struct stack_config *curstackcfg;
	struct interface_config *curifcfg;
	struct uinet_demo_config *curappcfg;
	struct uinet_demo_connscale *curconnscalecfg;
	struct uinet_demo_echo *curechocfg;
	struct uinet_demo_nproxy *curnproxycfg;
	struct uinet_demo_passive *curpassivecfg;
	struct uinet_demo_passive_extract *curpassivexcfg;
	struct ev_loop *curloop;
	unsigned int num_event_loops;
	unsigned int num_stacks;
	unsigned int num_ifs;
	unsigned int num_apps;
	unsigned int num_connscale_servers;
	unsigned int num_echo_servers;
	unsigned int num_nproxy_servers;
	unsigned int num_passive_servers;
	unsigned int num_passivex_servers;
	unsigned int exit_after_config;
	unsigned int i, j;
	int error;
	unsigned int baseline_verbose;
	unsigned int option_set_flags[MAX_MT_OPT_VALUE - MIN_MT_OPT_VALUE - 1];
	unsigned int option_values[MAX_MT_OPT_VALUE - MIN_MT_OPT_VALUE - 1];
	enum {
		CONFIGURING_GLOBALS = 0x01,
		CONFIGURING_LOOP    = 0x02,
		CONFIGURING_STACK   = 0x04,
		CONFIGURING_IF      = 0x08,
		CONFIGURING_APP	    = 0x10
	} config_state;
	
#define OPTION_SET(opt) option_set_flags[opt - MIN_MT_OPT_VALUE - 1]
#define OPTION_VALUE(opt) option_values[opt - MIN_MT_OPT_VALUE - 1]
#define TRANSFER_OPTION(opt, cfgmember)				\
	do {							\
		if (OPTION_SET(opt))				\
			gcfg.cfgmember = OPTION_VALUE(opt);	\
	} while (0)

#define REQUIRE_STATE(mask_, intro_)					\
	do {								\
		if (!((mask_) & config_state)) {			\
			printf(intro_ " is not valid while configuring %s\n", \
			       config_state == CONFIGURING_GLOBALS ? "global options" : \
			       config_state == CONFIGURING_LOOP   ? "event loop options" : \
			       config_state == CONFIGURING_STACK   ? "stack options" : \
			       config_state == CONFIGURING_IF      ? "interface options" : \
			       "app options");				\
			return (EXIT_FAILURE);				\
		}							\
	} while (0)
#define LIMIT_OBJECTS(label_, count_, max_)				\
	do {								\
		if ((count_) == (max_)) {				\
			printf("Cannot create more than %u %s\n", (max_), (label_)); \
			return (EXIT_FAILURE);				\
		}							\
	} while (0)


	uinet_demo_init();

	error = pthread_mutex_init(&print_lock, NULL);
	if (error != 0) {
		printf("Failed to initialize print lock (%d)\n", error);
		return (EXIT_FAILURE);
	}

	memset(option_set_flags, 0, sizeof(option_set_flags));
	memset(option_values, 0, sizeof(option_values));

	memset(elcfgs, 0, sizeof(elcfgs));
	for(i = 0; i < MAX_EVENT_LOOPS; i++) {
		elcfgs[i].cpu = -1;
		elcfgs[i].first_stats = 1;
	}
	
	memset(scfgs, 0, sizeof(scfgs));
	for(i = 0; i < MAX_STACKS; i++) {
		scfgs[i].first_stats = 1;
	}

	memset(ifcfgs, 0, sizeof(ifcfgs));

	snprintf(elcfgs[0].name, UINET_NAME_BUF_LEN, "default loop");
	elcfgs[0].loop = ev_default_loop(EVFLAG_AUTO);
	elcfgs[0].scfgs[0] = &scfgs[0];
	elcfgs[0].num_stacks = 1;

	snprintf(scfgs[0].name, UINET_NAME_BUF_LEN, "default stack");
	scfgs[0].elcfg = &elcfgs[0];
	scfgs[0].uinst = NULL;  /* set after uinet_init() */

	curloopcfg = &elcfgs[0];
	curstackcfg = &scfgs[0];
	curifcfg = NULL;
	curappcfg = NULL;
	curconnscalecfg = NULL;
	curechocfg = NULL;
	curnproxycfg = NULL;
	curpassivecfg = NULL;
	curpassivexcfg = NULL;

	num_event_loops = 1;
	num_stacks = 1;
	num_ifs = 0;
	num_apps = 0;
	num_connscale_servers = 0;
	num_echo_servers = 0;
	num_nproxy_servers = 0;
	num_passive_servers = 0;
	num_passivex_servers = 0;

	exit_after_config = 0;
	baseline_verbose = 0;
	config_state = CONFIGURING_GLOBALS;

	while ((opt = getopt_long(argc, argv, "b:c:C:e::E::g::hI:J::m::n:NO:p:P::r:R:s::St:vX:Z:",
				    long_options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			REQUIRE_STATE(CONFIGURING_IF, "Specifying a bridge-to list");
			curifcfg->bridge_ifs = optarg;
			break;
		case 'c':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_LOOP, "Specifying event loop cpu");
			curloopcfg->cpu = strtol(optarg, NULL, 10);
			if (curloopcfg->cpu < 0)
				curloopcfg->cpu = -1;
			break;
		case 'e':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_LOOP|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP, "Creating a new event loop");
			LIMIT_OBJECTS("event loops", num_event_loops, MAX_EVENT_LOOPS);

			curloopcfg = &elcfgs[num_event_loops];
			if (optarg)
				snprintf(curloopcfg->name, UINET_NAME_BUF_LEN, "%s", optarg);
			else
				snprintf(curloopcfg->name, UINET_NAME_BUF_LEN, "event loop %u", num_event_loops);
			num_event_loops++;
			
			curloopcfg->verbose = baseline_verbose;

			config_state = CONFIGURING_LOOP;
			break;
		case 'C':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP, "Creating a new connscale client/server");
			LIMIT_OBJECTS("connscale clients/servers", num_connscale_servers, MAX_APPS);

			curconnscalecfg = &connscalecfgs[num_connscale_servers];
			curappcfg = (struct uinet_demo_config *)curconnscalecfg;
			if (0 != uinet_demo_init_cfg(&curconnscalecfg->cfg, UINET_DEMO_CONNSCALE, num_connscale_servers, optarg,
						     baseline_verbose)) {
				printf("Error initializing configuration for new connscale client/server\n");
				return (EXIT_FAILURE);
			}
			num_apps++;
			num_connscale_servers++;
			
			curstackcfg->acfgs[curstackcfg->num_apps++] = curappcfg;
			
			if (-1 == uinet_demo_process_args(curappcfg, argc, argv))
				return (EXIT_FAILURE);

			config_state = CONFIGURING_APP;
			break;
		case 'E':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP, "Creating a new echo server");
			LIMIT_OBJECTS("echo servers", num_echo_servers, MAX_APPS);

			curechocfg = &echocfgs[num_echo_servers];
			curappcfg = (struct uinet_demo_config *)curechocfg;
			if (0 != uinet_demo_init_cfg(&curechocfg->cfg, UINET_DEMO_ECHO, num_echo_servers, optarg,
						     baseline_verbose)) {
				printf("Error initializing configuration for new echo server\n");
				return (EXIT_FAILURE);
			}
			num_apps++;
			num_echo_servers++;
			
			curstackcfg->acfgs[curstackcfg->num_apps++] = curappcfg;
			
			if (-1 == uinet_demo_process_args(curappcfg, argc, argv))
				return (EXIT_FAILURE);

			config_state = CONFIGURING_APP;
			break;
		case 'g':
			REQUIRE_STATE(CONFIGURING_IF, "Enabling packet generation");
			curifcfg->generate = 1;
			if (optarg) {
				curifcfg->gen_len = strtoul(optarg, NULL, 10);
				if (curifcfg->gen_len < 64 || curifcfg->gen_len > 1518) {
					printf("Transmit length must be in the range [64, 1518]\n");
					return (EXIT_FAILURE);
				}
			}
			break;
		case 'h':
			usage(argv[0]);
			return (EXIT_SUCCESS);
		case 'I':
			REQUIRE_STATE(CONFIGURING_IF, "Specifying transmit injection queue length");
			curifcfg->ucfg.tx_inject_queue_len = strtoul(optarg, NULL, 10);
			break;
		case 'J':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK, "Enabling brief tcp stats");
			if (optarg)
				curstackcfg->stats_interval = strtoul(optarg, NULL, 10);
			else
				curstackcfg->stats_interval = 1;
			break;
		case 'm':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_LOOP, "Enabling stats output");
			if (optarg)
				curloopcfg->stats_interval = strtoul(optarg, NULL, 10);
			else
				curloopcfg->stats_interval = 1;
			break;
		case 'n':
		case 'p':
		{
			uinet_iftype_t type;
			const char *type_name;

			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP,
				      "Creating a new network interface");
			LIMIT_OBJECTS("interfaces", num_ifs, MAX_IFS);

			switch(opt) {
			case 'n': type = UINET_IFTYPE_NETMAP; type_name = "netmap"; break;
			case 'p': type = UINET_IFTYPE_PCAP;   type_name = "pcap"; break;
			default:
				printf("Unhandled network interface type\n");
				return (EXIT_FAILURE);
			}

			curifcfg = &ifcfgs[num_ifs];
			init_ifcfg(curifcfg, num_ifs, type, optarg);

			num_ifs++;
			
			curifcfg->scfg = curstackcfg;
			curifcfg->type_name = type_name;
			curifcfg->verbose = baseline_verbose;

			curstackcfg->ifcfgs[curstackcfg->num_ifs++] = curifcfg;
			config_state = CONFIGURING_IF;
			break;
		}
		case 'N':
			exit_after_config = 1;
			break;
		case 'O':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP, "Creating a new nproxy server");
			LIMIT_OBJECTS("nproxy servers", num_nproxy_servers, MAX_APPS);

			curnproxycfg = &nproxycfgs[num_nproxy_servers];
			curappcfg = (struct uinet_demo_config *)curnproxycfg;
			if (0 != uinet_demo_init_cfg(&curnproxycfg->cfg, UINET_DEMO_NPROXY, num_nproxy_servers, optarg,
						     baseline_verbose)) {
				printf("Error initializing configuration for new nproxy server\n");
				return (EXIT_FAILURE);
			}
			num_apps++;
			num_nproxy_servers++;
			
			curstackcfg->acfgs[curstackcfg->num_apps++] = curappcfg;
			
			if (-1 == uinet_demo_process_args(curappcfg, argc, argv))
				return (EXIT_FAILURE);

			config_state = CONFIGURING_APP;
			break;
		case 'P':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP, "Creating a new passive server");
			LIMIT_OBJECTS("passive servers", num_passive_servers, MAX_APPS);

			curpassivecfg = &passivecfgs[num_passive_servers];
			curappcfg = (struct uinet_demo_config *)curpassivecfg;
			if (0 != uinet_demo_init_cfg(&curpassivecfg->cfg, UINET_DEMO_PASSIVE, num_passive_servers, optarg,
						     baseline_verbose)) {
				printf("Error initializing configuration for new passive server\n");
				return (EXIT_FAILURE);
			}
			num_apps++;
			num_passive_servers++;
			
			curstackcfg->acfgs[curstackcfg->num_apps++] = curappcfg;
			
			if (-1 == uinet_demo_process_args(curappcfg, argc, argv))
				return (EXIT_FAILURE);

			config_state = CONFIGURING_APP;
			break;
		case 'r':
			REQUIRE_STATE(CONFIGURING_IF, "Specifying interface rx cpu");
			curifcfg->ucfg.rx_cpu = strtol(optarg, NULL, 10);
			if (curifcfg->ucfg.rx_cpu < 0)
				curifcfg->ucfg.rx_cpu = -1;
			break;
		case 'R':
			REQUIRE_STATE(CONFIGURING_IF, "Specifying rx batch size");
			curifcfg->ucfg.rx_batch_size = strtoul(optarg, NULL, 10);
			break;
		case 's':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_LOOP|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP, "Creating a new stack instance");
			LIMIT_OBJECTS("stack instances", num_stacks, MAX_STACKS);

			curstackcfg = &scfgs[num_stacks];
			if (optarg)
				snprintf(curstackcfg->name, UINET_NAME_BUF_LEN, "%s", optarg);
			else
				snprintf(curstackcfg->name, UINET_NAME_BUF_LEN, "stack %u", num_stacks);
			num_stacks++;
			curstackcfg->elcfg = curloopcfg;
			curstackcfg->verbose = baseline_verbose;
			
			curloopcfg->scfgs[curloopcfg->num_stacks++] = curstackcfg;

			config_state = CONFIGURING_STACK;
			break;
		case 'S':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK, "Specifying single-thread-stack mode");
			curstackcfg->sts = 1;
			break;
		case 't':
			REQUIRE_STATE(CONFIGURING_IF, "Specifying interface tx cpu");
			curifcfg->ucfg.tx_cpu = strtol(optarg, NULL, 10);
			if (curifcfg->ucfg.tx_cpu < 0)
				curifcfg->ucfg.tx_cpu = -1;
			break;
		case 'T':
			REQUIRE_STATE(CONFIGURING_IF, "Specifying a timestamp mode");
			if (0 != get_timestamp_mode(optarg, &curifcfg->ucfg.timestamp_mode)) {
				printf("%s is not a valid timestamp mode\n", optarg);
				return (EXIT_FAILURE);
			}
			break;
		case 'v':
		{
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK|CONFIGURING_IF, "Increasing verbosity");
			unsigned int *verbose = NULL;
			
			if (config_state == CONFIGURING_GLOBALS)
				verbose = &baseline_verbose;
			else if (config_state == CONFIGURING_STACK)
				verbose = &curstackcfg->verbose;
			else if (config_state == CONFIGURING_IF)
				verbose = &curifcfg->verbose;
			/* apps handle processing --verbose/-v themselves */

			if (verbose) {
				if (optarg)
					*verbose = strtol(optarg, NULL, 10);
				else
					(*verbose)++;
			}
			break;
		}
		case 'X':
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK|CONFIGURING_IF|CONFIGURING_APP, "Creating a new passive extract server");
			LIMIT_OBJECTS("passive extract servers", num_passivex_servers, MAX_APPS);

			curpassivexcfg = &passivexcfgs[num_passivex_servers];
			curappcfg = (struct uinet_demo_config *)curpassivexcfg;
			if (0 != uinet_demo_init_cfg(&curpassivexcfg->cfg, UINET_DEMO_PASSIVE_EXTRACT, num_passivex_servers, optarg,
						     baseline_verbose)) {
				printf("Error initializing configuration for new passive extract server\n");
				return (EXIT_FAILURE);
			}
			num_apps++;
			num_passivex_servers++;
			
			curstackcfg->acfgs[curstackcfg->num_apps++] = curappcfg;
			
			if (-1 == uinet_demo_process_args(curappcfg, argc, argv))
				return (EXIT_FAILURE);

			config_state = CONFIGURING_APP;
			break;
		case 'Z':
			REQUIRE_STATE(CONFIGURING_IF, "Specifying a trace mask");
			if (curifcfg->ucfg.type == UINET_IFTYPE_NETMAP)
				curifcfg->ucfg.type_cfg.netmap.trace_mask = strtoul(optarg, NULL, 16);
			else {
				printf("Interface type %s (%s) does not support the trace mask option\n",
				       curifcfg->type_name, curifcfg->ucfg.configstr);
			}
			break;
		case MT_OPT_BASE_CONFIG:
		{
			enum uinet_global_cfg_type which;
			REQUIRE_STATE(CONFIGURING_GLOBALS, "Specifying the base global config");
			if (strcmp(optarg, "small") == 0) {
				which = UINET_GLOBAL_CFG_SMALL;
			} else if (strcmp(optarg, "medium") == 0) {
				which = UINET_GLOBAL_CFG_MEDIUM;
			} else if (strcmp(optarg, "large") == 0) {
				which = UINET_GLOBAL_CFG_LARGE;
			} else {
				printf("Invalid global config base type\n");
				return (EXIT_FAILURE);
			}

			OPTION_SET(MT_OPT_BASE_CONFIG) = 1;
			OPTION_VALUE(MT_OPT_BASE_CONFIG) = which;
			break;
		}
		case MT_OPT_MAXSOCKETS:
		case MT_OPT_NETMAP_EXTRA_BUFS:
		case MT_OPT_NMBCLUSTERS:
		case MT_OPT_SOMAXCONN:
		case MT_OPT_SYNCACHE_BUCKETLIMIT:
		case MT_OPT_SYNCACHE_CACHELIMIT:
		case MT_OPT_SYNCACHE_HASHSIZE:
		case MT_OPT_TCBHASHSIZE:
			REQUIRE_STATE(CONFIGURING_GLOBALS, "Specifying a global option");
			OPTION_SET(opt) = 1;
			OPTION_VALUE(opt) = strtoul(optarg, NULL, 10);
			break;
		case MT_OPT_PCAP_TX_FILE_DIRBITS:
			REQUIRE_STATE(CONFIGURING_IF, "Specifying directory bits for pcap file-per-flow transmit-to-file mode");
			if (curifcfg->ucfg.type == UINET_IFTYPE_PCAP)
				curifcfg->ucfg.type_cfg.pcap.dir_bits = strtoul(optarg, NULL, 10);
			else {
				printf("Interface type %s (%s) does not support the pcap tx file dirbits option\n",
				       curifcfg->type_name, curifcfg->ucfg.configstr);
			}
			break;
		case MT_OPT_PCAP_TX_FILE_MODE:
			REQUIRE_STATE(CONFIGURING_IF, "Specifying pcap transmit-to-file mode");
			if (curifcfg->ucfg.type == UINET_IFTYPE_PCAP)
				if (0 == strcmp(optarg, "file-per-flow"))
					curifcfg->ucfg.type_cfg.pcap.file_per_flow = 1;
				else if (0 == strcmp(optarg, "single-file"))
					curifcfg->ucfg.type_cfg.pcap.file_per_flow = 0;
				else {
					printf("Invalid pcap transmit-to-file mode\n");
					return (EXIT_FAILURE);
				}
			else {
				printf("Interface type %s (%s) does not support the pcap transmit-to-file mode option\n",
				       curifcfg->type_name, curifcfg->ucfg.configstr);
			}
			break;
		case MT_OPT_SYNCACHE_STATS:
			REQUIRE_STATE(CONFIGURING_GLOBALS|CONFIGURING_STACK, "Enabling syncache stats");
			curstackcfg->syncache_stats = 1;
			break;
		default: 
			printf("Unknown argument %s\n", argv[optind]);
			usage(argv[0]);
			return (EXIT_FAILURE);
		}
	}
	
	scfgs[0].verbose = baseline_verbose;
	elcfgs[0].verbose = baseline_verbose;

	if (baseline_verbose)
		printf("Configuring bridging for %u interface%s", num_ifs,
		       num_ifs == 1 ? "" : "s");

	for (i = 0; i < num_ifs; i++) {
		if (-1 == configure_bridging(ifcfgs, num_ifs, i)) {
			printf("Failed to configure bridging for interface %s (%s)\n",
			       ifcfgs[i].ucfg.alias, ifcfgs[i].ucfg.configstr);
			return (EXIT_FAILURE);
		}
	}

	print_cfg(elcfgs, num_event_loops);

	if (exit_after_config) {
		printf("Exit after printing configuration requested.\n");
		return (EXIT_SUCCESS);
	}

	if (baseline_verbose)
		printf("Creating %u event loop%s\n", num_event_loops, 
		       num_event_loops == 1 ? "" : "s");

	for (i = 1; i < num_event_loops; i++) {
		curloopcfg = &elcfgs[i];

		curloopcfg->loop = ev_loop_new(EVFLAG_AUTO);
		if (NULL == curloopcfg->loop) {
			printf("Failed to create event loop (%s)\n", curloopcfg->name);
			return (EXIT_FAILURE);
		}
	}


	struct uinet_global_cfg gcfg;
	struct uinet_instance_cfg icfg;
	enum uinet_global_cfg_type which;

	which = OPTION_SET(MT_OPT_BASE_CONFIG) ? OPTION_VALUE(MT_OPT_BASE_CONFIG) : UINET_GLOBAL_CFG_MEDIUM;

	uinet_default_cfg(&gcfg, which);
	TRANSFER_OPTION(MT_OPT_MAXSOCKETS, kern.ipc.maxsockets);
	TRANSFER_OPTION(MT_OPT_NETMAP_EXTRA_BUFS, netmap_extra_bufs);
	TRANSFER_OPTION(MT_OPT_NMBCLUSTERS, kern.ipc.nmbclusters);
	TRANSFER_OPTION(MT_OPT_SOMAXCONN, kern.ipc.somaxconn);
	TRANSFER_OPTION(MT_OPT_SYNCACHE_HASHSIZE, net.inet.tcp.syncache.hashsize);
	TRANSFER_OPTION(MT_OPT_SYNCACHE_BUCKETLIMIT, net.inet.tcp.syncache.bucketlimit);
	TRANSFER_OPTION(MT_OPT_SYNCACHE_CACHELIMIT, net.inet.tcp.syncache.cachelimit);
	TRANSFER_OPTION(MT_OPT_TCBHASHSIZE, net.inet.tcp.tcbhashsize);

	uinet_instance_default_cfg(&icfg);
	if (scfgs[0].sts)
		ev_loop_enable_uinet_sts(scfgs[0].elcfg->loop, &icfg.sts);

	uinet_init(&gcfg, &icfg);
	uinet_install_sighandlers();

	scfgs[0].uinst = uinet_instance_default();

	if (baseline_verbose)
		printf("Creating %u stack instance%s\n", num_stacks, 
		       num_stacks == 1 ? "" : "s");

	for (i = 1; i < num_stacks; i++) {
		curstackcfg = &scfgs[i];

		uinet_instance_default_cfg(&icfg);
		if (curstackcfg->sts)
			ev_loop_enable_uinet_sts(scfgs[i].elcfg->loop, &icfg.sts);
		curstackcfg->uinst = uinet_instance_create(&icfg);
		if (curstackcfg->uinst == NULL) {
			printf("Failed to create stack instance (%s)\n", curstackcfg->name);
			return (EXIT_FAILURE);
		}
	}


	if (baseline_verbose)
		printf("Creating %u network interface%s\n", num_ifs, 
		       num_ifs == 1 ? "" : "s");

	for (i = 0; i < num_ifs; i++) {
		curifcfg = &ifcfgs[i];

		if (curifcfg->generate) {
			/* XXX currently *very* quick and dirty.  need pps option and halfway reasonable regulation for given rate */
			curifcfg->max_pkts = 512;
			curifcfg->pkts = uinet_pd_list_alloc(curifcfg->max_pkts);
			if (curifcfg->pkts == NULL) {
				printf("%s (%s): Failed to allocate packet descriptor list\n",
				       curifcfg->ucfg.alias, curifcfg->ucfg.configstr);
				curifcfg->max_pkts = 0;
			}

			/* XXX arbitrary and fixed 2s initial wait and 1ms repeat */
			ev_timer_init(&curifcfg->gen_watcher, generate_cb, 2.0, 0.001);
			curifcfg->gen_watcher.data = curifcfg;
			ev_timer_start(curifcfg->scfg->elcfg->loop, &curifcfg->gen_watcher);
		}

		error = uinet_ifcreate(curifcfg->scfg->uinst, &curifcfg->ucfg, &curifcfg->uif);
		if (0 != error) {
			printf("%s (%s): Failed to create interface (%d)\n", curifcfg->ucfg.alias,
			       curifcfg->ucfg.configstr, error);
		}
	}

	if (baseline_verbose)
		printf("Starting %u app%s\n", num_apps, num_apps == 1 ? "" : "s");

	for (i = 0; i < num_ifs; i++) {
		curifcfg = &ifcfgs[i];
		error = uinet_interface_up(curifcfg->scfg->uinst, curifcfg->ucfg.alias, 1, 1);
		if (0 != error) {
			printf("%s (%s): Failed to bring up interface (%d)\n", curifcfg->ucfg.alias,
			       curifcfg->ucfg.configstr, error);
		}
	}

	printf("Waiting 2 seconds for interfaces to settle\n");
	sleep(2);

	/*
	 * Override SIGINT handler with one that will stop the threads that
	 * are about to be created.
	 */
	struct sigaction sa;
	sa.sa_sigaction = cleanup_handler;
	sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
	sigfillset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

	for (i = 0; i < num_event_loops; i++) {
		curloopcfg = &elcfgs[i];

		ev_timer_init(&curloopcfg->shutdown_watcher, shutdown_cb, 0.5, 0.5);
		ev_timer_start(curloopcfg->loop, &curloopcfg->shutdown_watcher);

		if (curloopcfg->stats_interval > 0) {
			ev_timer_init(&curloopcfg->stats_watcher, stats_cb,
				      curloopcfg->stats_interval, curloopcfg->stats_interval);
			curloopcfg->stats_watcher.data = curloopcfg;
			ev_timer_start(curloopcfg->loop, &curloopcfg->stats_watcher);
		}

		if (pthread_create(&curloopcfg->thread_id, NULL, loop_thread, curloopcfg))
			curloopcfg->has_thread = 0;
		else
			curloopcfg->has_thread = 1;
	}
	
	while (!shutting_down)
		sleep(1);

	printf("Waiting for event loops to stop\n");
	for (i = 0; i < num_event_loops; i++) {
		curloopcfg = &elcfgs[i];
		if (curloopcfg->has_thread)
			pthread_join(curloopcfg->thread_id, NULL);
	}

	uinet_shutdown(0);

	pthread_mutex_destroy(&print_lock);

	return (EXIT_SUCCESS);
}
