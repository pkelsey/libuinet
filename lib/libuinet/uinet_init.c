/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Derived in part from libplebnet's pn_init.c.
 *
 */

#include "opt_param.h"

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/pcpu.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/lock.h>
#include <sys/sx.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include "uinet_api.h"
#include "uinet_config.h"


pid_t     getpid(void);
char *strndup(const char *str, size_t len);
unsigned int     sleep(unsigned int seconds);



extern void mi_startup(void);

extern void uinet_init_thread0(void);
extern void mutex_init(void);

#if 0
pthread_mutex_t init_lock;
pthread_cond_t init_cond;
#endif

int
uinet_init(unsigned int ncpus, unsigned int nmbclusters, unsigned int loopback)
{
	struct thread *td;
	char tmpbuf[32];
	int boot_pages;
	int num_hash_buckets;
	caddr_t v;

	if (ncpus > MAXCPU) {
		printf("Limiting number of CPUs to %u\n", MAXCPU);
		ncpus = MAXCPU;
	} else if (0 == ncpus) {
		printf("Setting number of CPUs to 1\n");
		ncpus = 1;
	}

	printf("uinet starting: cpus=%u, nmbclusters=%u\n", ncpus, nmbclusters);

	snprintf(tmpbuf, sizeof(tmpbuf), "%u", nmbclusters);
	setenv("kern.ipc.nmbclusters", tmpbuf);

	/* The env var kern.ncallout will get read in proc0_init(), but
	 * that's after we init the callwheel below.  So we set it here for
	 * consistency, but the operative setting is the direct assignment
	 * below.
	 */
        ncallout = HZ * 3600;
	snprintf(tmpbuf, sizeof(tmpbuf), "%u", ncallout);
	setenv("kern.ncallout", tmpbuf);

	/* Assuming maxsockets will be set to nmbclusters, the following
	 * sets the TCP tcbhash size so that perfectly uniform hashing would
	 * result in a maximum bucket depth of about 16.
	 */
	num_hash_buckets = 1;
	while (num_hash_buckets < nmbclusters / 16)
		num_hash_buckets <<= 1;
	snprintf(tmpbuf, sizeof(tmpbuf), "%u", num_hash_buckets);	
	setenv("net.inet.tcp.tcbhashsize", tmpbuf);

	boot_pages = 16;  /* number of pages made available for uma to bootstrap itself */

	mp_ncpus = ncpus;
	mp_maxid = mp_ncpus - 1;

        /* vm_init bits */
	
        pcpup = malloc(sizeof(struct pcpu), M_DEVBUF, M_ZERO);
        pcpu_init(pcpup, 0, sizeof(struct pcpu));

	
	/* first get size required, then alloc memory, then give that memory to the second call */
	v = 0;
        v = kern_timeout_callwheel_alloc(v);
	kern_timeout_callwheel_alloc(malloc(round_page((vm_offset_t)v), M_DEVBUF, M_ZERO));
        kern_timeout_callwheel_init();

	uinet_init_thread0();

        uma_startup(malloc(boot_pages*PAGE_SIZE, M_DEVBUF, M_ZERO), boot_pages);
	uma_startup2();

	/* XXX any need to tune this? */
	num_hash_buckets = 8192;  /* power of 2.  32 bytes per bucket on a 64-bit system, so no need to skimp */
	uma_page_slab_hash = malloc(sizeof(struct uma_page)*num_hash_buckets, M_DEVBUF, M_ZERO);
	uma_page_mask = num_hash_buckets - 1;

#if 0
	pthread_mutex_init(&init_lock, NULL);
	pthread_cond_init(&init_cond, NULL);
#endif
	mutex_init();
        mi_startup();
	sx_init(&proctree_lock, "proctree");
	td = curthread;

	/* XXX - would very much like to do better than this */
	/* give all configuration threads time to complete initialization
	 * before continuing
	 */
	sleep(1);

	/*
	 * Don't respond with a reset to TCP segments that the stack will
	 * not claim nor with an ICMP port unreachable message to UDP
	 * datagrams that the stack will not claim.
	 */
	uinet_config_blackhole(UINET_BLACKHOLE_TCP_ALL);
	uinet_config_blackhole(UINET_BLACKHOLE_UDP_ALL);

	if (loopback) {
		int error;

		uinet_interface_up("lo0", 0);

		if (0 != (error = uinet_interface_add_alias("lo0", "127.0.0.1", "0.0.0.0", "255.0.0.0"))) {
			printf("Loopback alias add failed %d\n", error);
		}
	}

	return (0);
}
