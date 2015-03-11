/*
 * Copyright (c) 2015 Patrick Kelsey. All rights reserved.
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

#include "uinet_api.h"

#define EV_STANDALONE 1
#define EV_UINET_ENABLE 1
#include <ev.h>

#define MAX_IFS 32

struct interface_config {
	struct uinet_if_cfg ucfg;
	const char *type_name;
	int generate;
	unsigned int gen_len;
	const char *bridge_ifs;
	struct interface_config *bridge_to[MAX_IFS];
	unsigned int num_bridge_to;
	int verbose;
	int has_thread;
	pthread_t thread_id;

	uinet_instance_t uinst;
	uinet_if_t uif;
};


/*
 * This is a test program for the libuinet packet descriptor innards,
 * currently supporting raw packet sinking, sourcing, and multi-way
 * bridging.
 */

static const struct option long_options[] = {
	{ "netmap",	required_argument,	0, 'n' },
	{ "gpool",	required_argument,	0, 'G' },
	{ "pcap",	required_argument,	0, 'p' },

	{ "bridge",	required_argument,	0, 'b' },
	{ "gen",	no_argument, 		0, 'g' },
	{ "len",	required_argument,	0, 'l' },
	{ "iqlen",	required_argument,	0, 'I' },
	{ "rxcpu",	required_argument,	0, 'r' },
	{ "txcpu",	required_argument,	0, 't' },

	{ "help",	no_argument,		0, 'h' },
	{ "verbose",	no_argument,		0, 'v' },
	{ 0, 0, 0, 0 }
};


static void
usage(const char *progname)
{
	printf("Usage: %s\n", progname);
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


static void
first_look_handler(void *arg, struct uinet_pd_list *pkts)
{
	struct interface_config *ifcfg;
	unsigned int i;
	uint16_t flags;
#define FREE_GROUP_MAX	32
	struct uinet_pd_ctx *free_group[FREE_GROUP_MAX];
	unsigned int free_group_count;

	ifcfg = (struct interface_config *)arg;

	if (ifcfg->num_bridge_to > 0) {
		if (ifcfg->verbose > 1)
			printf("%s (%s): First-look handler bridging to %u interface%s\n",
			       ifcfg->ucfg.alias, ifcfg->ucfg.configstr,
			       ifcfg->num_bridge_to, (ifcfg->num_bridge_to == 1) ? "" : "s"); 

		/*
		 * Mark the packets that we want to inject, and if bridging
		 * multiple ways, that we need to add extra refs to
		 */
		flags = (ifcfg->num_bridge_to > 1) ? UINET_PD_INJECT | UINET_PD_EXTRA_REFS : UINET_PD_INJECT;
		for (i = 0; i < pkts->num_descs; i++)
			pkts->descs[i].flags |= flags;

		/*
		 *  We own one reference to the packets already, so if we
		 *  are bridging N ways, we need to acquire N - 1 additional
		 *  refs.
		 */
		if (ifcfg->num_bridge_to > 1)
			uinet_pd_ref_acquire(pkts, ifcfg->num_bridge_to - 1);

		for (i = 0; i < ifcfg->num_bridge_to; i++)
			uinet_if_inject_tx_packets(ifcfg->bridge_to[i]->uif, pkts);
	} else {
		if (ifcfg->verbose > 1)
			printf("%s (%s): First-look handler discarding packets\n",
			       ifcfg->ucfg.alias, ifcfg->ucfg.configstr);

		free_group_count = 0;
		for (i = 0; i < pkts->num_descs; i++) {
			free_group[free_group_count++] = pkts->descs[i].ctx;
			if (free_group_count == FREE_GROUP_MAX) {
				uinet_pd_ref_release(free_group, free_group_count);
				free_group_count = 0;
			}
		}
		if (free_group_count)
				uinet_pd_ref_release(free_group, free_group_count);
	}
}


static void
init_ifcfg(struct interface_config *ifcfg, unsigned int ifno, uinet_iftype_t type,
	   const char *configstr)
{
	char namebuf[32];

	memset(ifcfg, 0, sizeof(struct interface_config));

	uinet_if_default_config(type, &ifcfg->ucfg);
	ifcfg->ucfg.configstr = configstr;
	snprintf(namebuf, 32, "if%u", ifno);
	ifcfg->ucfg.alias = strdup(namebuf);
	ifcfg->ucfg.first_look_handler = first_look_handler;
	ifcfg->ucfg.first_look_handler_arg = ifcfg;
	ifcfg->gen_len = 758;
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
print_ifcfgs(struct interface_config *ifcfgs, unsigned int num_ifs)
{
	unsigned int i, j;
	unsigned int bridge_tos;
	struct interface_config *curifcfg;
	
	for (i = 0; i < num_ifs; i++) {
		curifcfg = &ifcfgs[i];
		printf("%s (%s) type=%s gen=%s len=%u", curifcfg->ucfg.alias,
		       curifcfg->ucfg.configstr, curifcfg->type_name,
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

		if (curifcfg->ucfg.tx_cpu < 0)
			printf(" txcpu=auto");
		else
			printf(" txcpu=%u", curifcfg->ucfg.tx_cpu);

		if (curifcfg->ucfg.rx_cpu < 0)
			printf(" rxcpu=auto");
		else
			printf(" rxcpu=%u", curifcfg->ucfg.rx_cpu);

		printf("\n");
	}
}


static void *
interface_thread(void *arg)
{
	struct interface_config *ifcfg;
	struct uinet_pd_list *pkts = NULL;
	struct uinet_pd *cur_pd;
	uint32_t max_pkts;
	uint64_t counter;
	uint32_t i;

	ifcfg = arg;

	if (ifcfg->ucfg.tx_cpu >= 0)
		uhi_thread_bind(ifcfg->ucfg.tx_cpu);

	if (ifcfg->verbose)
		printf("%s (%s): Interface thread started on cpu %d\n", ifcfg->ucfg.alias, ifcfg->ucfg.configstr, ifcfg->ucfg.tx_cpu);

	if (ifcfg->generate) {
		/* XXX currenty *very* quick and dirty.  need pps option and halfway reasonable regulation loop for given rate */
		max_pkts = 1000;
		pkts = uinet_pd_list_alloc(max_pkts);
		if (pkts == NULL) {
			printf("%s (%s): Failed to allocate packet descriptor list\n", ifcfg->ucfg.alias, ifcfg->ucfg.configstr);
			goto out;
		}

		counter = 0;
		while (1) {
			pkts->num_descs = max_pkts;
			uinet_if_pd_alloc(ifcfg->uif, pkts);
			if (pkts->num_descs > 0) {
				for (i = 0; i < pkts->num_descs; i++) {
					counter++;
					cur_pd = &pkts->descs[i];
					cur_pd->data[0] = htonl(0x02000000);
					cur_pd->data[1] = htonl(0x00010200);
					cur_pd->data[2] = htonl(0x00000002);
					cur_pd->data[3] = htonl(0x08000000);
					cur_pd->data[4] = htonl(counter >> 32);
					cur_pd->data[5] = htonl(counter);
					cur_pd->length = ifcfg->gen_len - 4;
					cur_pd->flags |= UINET_PD_INJECT;
				}
				uinet_if_inject_tx_packets(ifcfg->uif, pkts);
			}
			usleep(1000);
		}
	}

 out:
	if (ifcfg->verbose)
		printf("%s (%s): Interface thread exiting\n", ifcfg->ucfg.alias, ifcfg->ucfg.configstr);

	if (pkts)
		uinet_pd_list_free(pkts);

	return (NULL);
}


int main (int argc, char **argv)
{
	int opt;
	struct interface_config ifcfgs[MAX_IFS];
	struct interface_config *curifcfg;
	unsigned int num_ifs;
	unsigned int i;
	int error;
	int baseline_verbose;
	unsigned int global_pool_size = 10000;

	memset(ifcfgs, 0, sizeof(ifcfgs));

	num_ifs = 0;
	curifcfg = NULL;
	baseline_verbose = 0;
	while ((opt = getopt_long(argc, argv, "b:gG:hI:l:n:p:r:t:v",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			if (curifcfg == NULL) {
				printf("No interface specified\n");
				return (EXIT_FAILURE);
			}
			curifcfg->bridge_ifs = optarg;
			break;
		case 'g':
			if (curifcfg == NULL) {
				printf("No interface specified\n");
				return (EXIT_FAILURE);
			}
			curifcfg->generate = 1;
			break;
		case 'G':
			if (curifcfg != NULL) {
				printf("Global pool size must be specified before any interfaces\n");
				return (EXIT_FAILURE);
			}
			global_pool_size = strtoul(optarg, NULL, 10);
			break;
		case 'h':
			usage(argv[0]);
			return (EXIT_SUCCESS);
		case 'I':
			if (curifcfg == NULL) {
				printf("No interface specified\n");
				return (EXIT_FAILURE);
			}
			curifcfg->ucfg.tx_inject_queue_len = strtoul(optarg, NULL, 10);
			break;
		case 'l':
			if (curifcfg == NULL) {
				printf("No interface specified\n");
				return (EXIT_FAILURE);
			}
			if (!curifcfg->generate) {
				printf("Interface not in generate mode\n");
				return (EXIT_FAILURE);
			}
			curifcfg->gen_len = strtoul(optarg, NULL, 10);
			if (curifcfg->gen_len < 64 || curifcfg->gen_len > 1518) {
				printf("Transmit length must be in the range [64, 1518]\n");
				return (EXIT_FAILURE);
			}
			break;
		case 'n':
			if (num_ifs == MAX_IFS) {
				printf("Exceeded the maximum of %u interfaces\n", MAX_IFS);
				return (EXIT_FAILURE);
			}
			curifcfg = &ifcfgs[num_ifs];
			init_ifcfg(curifcfg, num_ifs, UINET_IFTYPE_NETMAP, optarg);
			curifcfg->type_name = "netmap";
			curifcfg->verbose = baseline_verbose;
			num_ifs++;
			break;
		case 'p':
			if (num_ifs == MAX_IFS) {
				printf("Exceeded the maximum of %u interfaces\n", MAX_IFS);
				return (EXIT_FAILURE);
			}
			curifcfg = &ifcfgs[num_ifs];
			init_ifcfg(curifcfg, num_ifs, UINET_IFTYPE_PCAP, optarg);
			curifcfg->type_name = "pcap";
			num_ifs++;
			break;
		case 'r':
			if (curifcfg == NULL) {
				printf("No interface specified\n");
				return (EXIT_FAILURE);
			}
			curifcfg->ucfg.rx_cpu = strtol(optarg, NULL, 10);
			if (curifcfg->ucfg.rx_cpu < 0)
				curifcfg->ucfg.rx_cpu = -1;
			break;
		case 't':
			if (curifcfg == NULL) {
				printf("No interface specified\n");
				return (EXIT_FAILURE);
			}
			curifcfg->ucfg.tx_cpu = strtol(optarg, NULL, 10);
			if (curifcfg->ucfg.tx_cpu < 0)
				curifcfg->ucfg.tx_cpu = -1;
			break;
		case 'v':
			if (curifcfg == NULL)
				baseline_verbose++;
			else
				curifcfg->verbose++;
			break;
		default: 
			usage(argv[0]);
			return (EXIT_FAILURE);
		}
	}
	
	if (curifcfg == NULL) {
		printf("No interfaces specified\n");
		usage(argv[0]);
		return (EXIT_FAILURE);
	}

	for (i = 0; i < num_ifs; i++) {
		if (-1 == configure_bridging(ifcfgs, num_ifs, i))
			return (EXIT_FAILURE);
	}
	
	print_ifcfgs(ifcfgs, num_ifs);

	struct uinet_global_cfg cfg;
	uinet_default_cfg(&cfg);
	cfg.nmbclusters = 1024*1024;
	cfg.netmap_extra_bufs = global_pool_size;
	uinet_init(&cfg, NULL);
	uinet_install_sighandlers();

	for (i = 0; i < num_ifs; i++) {
		curifcfg = &ifcfgs[i];
		curifcfg->uinst = uinet_instance_default();
		error = uinet_ifcreate(curifcfg->uinst, &curifcfg->ucfg, &curifcfg->uif);
		if (0 != error) {
			printf("%s (%s): Failed to create interface (%d)\n", curifcfg->ucfg.alias,
			       curifcfg->ucfg.configstr, error);
		}
	}

	for (i = 0; i < num_ifs; i++) {
		curifcfg = &ifcfgs[i];
		error = uinet_interface_up(curifcfg->uinst, curifcfg->ucfg.alias, 1, 1);
		if (0 != error) {
			printf("%s (%s): Failed to bring up interface (%d)\n", curifcfg->ucfg.alias,
			       curifcfg->ucfg.configstr, error);
		}
	}


	for (i = 0; i < num_ifs; i++) {
		curifcfg = &ifcfgs[i];
		if (curifcfg->generate) {
			if (pthread_create(&curifcfg->thread_id, NULL, interface_thread, curifcfg)) {
				curifcfg->has_thread = 0;
			} else {
				curifcfg->has_thread = 1;
			}
		}
	}
	
	while (1) {
		sleep(1);
		printf("==============================================================================================================================\n");
		for (i = 0; i < num_ifs; i++) {
			struct uinet_ifstat stat;

			curifcfg = &ifcfgs[i];
			uinet_getifstat(curifcfg->uif, &stat);
			printf("%s (%s): icopies:%10lu izcopies:%10lu idrops:%10lu ocopies:%10lu ozcopies:%10lu odrops:%10lu\n",
			       curifcfg->ucfg.alias, curifcfg->ucfg.configstr,
			       stat.ifi_icopies, stat.ifi_izcopies, stat.ifi_iqdrops,
			       stat.ifi_ocopies, stat.ifi_ozcopies, stat.ifi_oerrors);
		}
	}


	for (i = 0; i < num_ifs; i++) {
		curifcfg = &ifcfgs[i];
		if (curifcfg->has_thread)
			pthread_join(curifcfg->thread_id, NULL);
	}

	uinet_shutdown(0);

	return (EXIT_SUCCESS);
}
