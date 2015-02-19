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
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/systm.h>


struct dpcpu_definition dpcpu_definitions[DPCPU_MAX_DEFINITIONS];
unsigned int dpcpu_num_definitions;
unsigned int dpcpu_total_size;
unsigned char *dpcpu_init_area;


void
uinet_dpcpu_init(void)
{
	unsigned int i;
	struct dpcpu_definition *def;

	/*
	 * Copy all of the registered data structures to a continguous area,
	 * as the implementation in subr_pcpu.c expects.
	 */
	dpcpu_init_area = malloc(dpcpu_total_size, M_DEVBUF, M_ZERO | M_WAITOK);
	if (NULL == dpcpu_init_area)
		panic("Could not allocate DPCPU init area\n");

	for (i = 0; i < dpcpu_num_definitions; i++) {
		def = &dpcpu_definitions[i];
		memcpy(&dpcpu_init_area[def->copyoffset], def->addr, def->copysize);
	}
}


struct pcpu *
uinet_pcpu_get(void)
{
	KASSERT(curthread->td_oncpu < mp_ncpus, ("curthread->td_oncpu >= mp_ncpus"));
	return (&pcpup[curthread->td_oncpu]);
}
