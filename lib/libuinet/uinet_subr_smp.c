/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
 * Copyright (c) 2013 Patrick Kelsey. All rights reserved.
 *
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
 * Derived in part from libplebnet's pn_glue.c.
 *
 */


#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/systm.h>
#include <sys/sysctl.h>


/* This is used in modules that need to work in both SMP and UP. */
cpuset_t all_cpus;

int mp_ncpus;
/* export this for libkvm consumers. */
int mp_maxcpus = MAXCPU;

volatile int smp_started;
u_int mp_maxid;

SYSCTL_NODE(_kern, OID_AUTO, smp, CTLFLAG_RD|CTLFLAG_CAPRD, NULL, "Kernel SMP");
SYSCTL_INT(_kern_smp, OID_AUTO, maxid, CTLFLAG_RD|CTLFLAG_CAPRD, &mp_maxid, 0,
    "Max CPU ID.");
SYSCTL_INT(_kern_smp, OID_AUTO, maxcpus, CTLFLAG_RD|CTLFLAG_CAPRD, &mp_maxcpus,
    0, "Max number of CPUs that the system was compiled for.");

/* XXX temporary until final pcpu approach is determined */
struct mtx uinet_pcpu_locks[MAXCPU];

static void
mp_start(void *dummy)
{
	int i;
	void *dpcpu;
	
	uinet_dpcpu_init();

        pcpup = malloc(sizeof(struct pcpu) * mp_ncpus, M_DEVBUF, M_ZERO);
	if (NULL == pcpup)
		panic("Failed to allocate PCPU space for %d cpus\n", mp_ncpus);

	for (i = 0; i < mp_ncpus; i++) {
		CPU_SET(i, &all_cpus);

		pcpu_init(&pcpup[i], i, sizeof(struct pcpu));

		dpcpu = malloc(DPCPU_SIZE, M_DEVBUF, M_WAITOK);
		if (NULL == dpcpu)
			panic("Failed to allocate DPCPU area for cpu %d\n", i);

		dpcpu_init(dpcpu, i);

		mtx_init(&uinet_pcpu_locks[i], "uipcpu", NULL, MTX_DEF | MTX_RECURSE);
	}

	printf("UINET multiprocessor subsystem configured with %d CPUs\n", mp_ncpus);
}
SYSINIT(cpu_mp, SI_SUB_CPU, SI_ORDER_THIRD, mp_start, NULL);

