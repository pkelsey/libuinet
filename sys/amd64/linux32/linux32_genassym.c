#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.1.0/sys/amd64/linux32/linux32_genassym.c 219364 2011-03-07 08:12:07Z dchagin $");

#include <sys/param.h>
#include <sys/assym.h>
#include <sys/systm.h>

#include <amd64/linux32/linux.h>

ASSYM(LINUX_SIGF_HANDLER, offsetof(struct l_sigframe, sf_handler));
ASSYM(LINUX_SIGF_SC, offsetof(struct l_sigframe, sf_sc));
ASSYM(LINUX_RT_SIGF_HANDLER, offsetof(struct l_rt_sigframe, sf_handler));
ASSYM(LINUX_RT_SIGF_UC, offsetof(struct l_rt_sigframe, sf_sc));
ASSYM(LINUX_RT_SIGF_SC, offsetof(struct l_ucontext, uc_mcontext));
