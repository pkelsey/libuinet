/*
 * Copyright (c) 2016 Patrick Kelsey. All rights reserved.
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

#include "opt_param.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/timetc.h>

#include "uinet_host_interface.h"


/*
 * Time updates work as follows:
 *
 *   - The libuinet timer interrupt emulation thread (see
 *     uinet_kern_timeout.c) ticks at 'hz', on average.
 *
 *   - Each emulated timer tick calls uinet_hardclock() (see
 *     uinet_kern_clock.c)
 *
 *   - uinet_hardclock() calls tc_ticktock(), which will retrieve the
 *     current timecounter count and will update the kernel time tracking
 *     state.
 *
 *
 *  This timecounter implementation retrieves the current host time and
 *  reports it as the equivalent number of counts from a counter
 *  incrementing at 'hz'.
 */


static unsigned int
uinet_tc_get_timecount(struct timecounter *tc)
{
	uint64_t ns;

	ns = uhi_clock_gettime_ns(UHI_CLOCK_MONOTONIC);
	return ((ns * HZ) / UHI_NSEC_PER_SEC);
}

static struct timecounter uinet_timecounter = {
	uinet_tc_get_timecount, 0, ~0u, HZ, "uinet clock", 1
};

static void
uinet_tc_init(void)
{
	tc_init(&uinet_timecounter);
}
SYSINIT(uinet_tc, SI_SUB_SMP, SI_ORDER_ANY, uinet_tc_init, NULL);

