/*-
 * Copyright (c) 2010 Kip Macy
 * All rights reserved.
 * Copyright (c) 2014 Patrick Kelsey. All rights reserved.
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
 */

#ifndef	_UINET_SYS_PCPU_H_
#define _UINET_SYS_PCPU_H_


#include_next <sys/pcpu.h>

/*
 * Normally, the way the DPCPU (dynamic per-CPU) data facility works is that
 * DPCPU_DECLARE() is used to allocate an instance of a (possibly
 * statically-initialized) data structure in a particular linker section
 * (aka, 'the linker set').  At runtime, the total size of that linker set
 * is known, based on the linker-generated symbols at the start and end
 * addresses of the section.  When each CPU initializes, it allocates memory
 * in that amount (technically, rounded up to the next PAGE_SIZE),
 * initializes it by copying the contents of the linker section described
 * above into it, and attaches it to the PCPU (per-CPU) data structure for
 * that CPU.  A given instance of a dynamic per-cpu data structure is then
 * accessed via a pointer, whose address is computed by taking the offset
 * between the symbol created by DPCPU_DECLARE() and the start of the linker
 * section and adding that offset to the address of the per-CPU memory area
 * allocated at CPU-initialization time.
 *
 * We reimplement this in UINET because we wish to not use linker sets, as
 * they represent an obstacle to portability (for example, to systems using
 * Mach-O, which restricts section names to 16 characters).  In this
 * alternate implementation, the data structures allocated via
 * DPCPU_DECLARE() are not placed in any special section.  Instead,
 * automatically generated constructor functions are used to store context
 * for each data structure, including its address, its size, and an assigned
 * offset within the dynamic per-CPU memory areas, as well as track the
 * total size of all of the so-declared data structures.
 *
 * During startup, this array and summary information created by the
 * constructors during the runtime environment initialization is used to
 * synthesize the equivalent to a linker set in memory.  With this, and the
 * DPCPU_*() macro implementations adjusted where necessary to use this
 * information, the entire existing implementation in subr_pcpu.c can be
 * used without modification.
 */


/*
 * Convenience defines.
 */
#undef DPCPU_START
#undef DPCPU_STOP
#undef DPCPU_BYTES
#undef DPCPU_SIZE
#define	DPCPU_START		((uintptr_t)dpcpu_init_area)
#define	DPCPU_STOP		((uintptr_t)dpcpu_init_area + dpcpu_total_size)
#define	DPCPU_BYTES		(DPCPU_STOP - DPCPU_START)
#define	DPCPU_SIZE		roundup2(DPCPU_BYTES, PAGE_SIZE)


struct dpcpu_definition {
	void *addr;
	size_t copysize;
	uintptr_t copyoffset;
};

#define DPCPU_MAX_DEFINITIONS	64
extern struct dpcpu_definition dpcpu_definitions[DPCPU_MAX_DEFINITIONS];
extern unsigned int dpcpu_num_definitions;
extern unsigned int dpcpu_total_size;
extern unsigned char *dpcpu_init_area;

void uinet_dpcpu_init(void);
struct pcpu *uinet_pcpu_get(void);

#define DPCPU_ALIGN	(ALIGNBYTES + 1)

/*
 * This is a bit of a hack when you consider that 'n' can be an array name,
 * for example, 'modspace[DPCPU_MODMIN]'.  In that case, the result of
 * DPCPU_DEFADDR_NAME() will also be an array name, and the subsequent
 * definition of the defaddr var using this name will result in an array of
 * struct dpcpu_definition * instead of just a single pointer.  It works,
 * but it wastes space in the array name case.
 *
 * XXX This hackishness could all be avoided if the upstream sources are
 * modified to handle arrays through separate DCPU_DECLARE_ARRAY() and
 * DCPU_DEFINE_ARRAY() macros.
 */
#define DPCPU_DEFADDR_NAME(n) __CONCAT(dpcpu_registration_defaddr_for_, DPCPU_NAME(n))

/*
 * The name 'n' may or may not be an array name.  DPCPU_DEF_GET()
 * returns an lvalue within the allocated defaddr var with the name
 * DPCPU_DEFADDR_NAME(n) in either case.
 *
 * XXX This hackishness could all be avoided if the upstream sources are
 * modified to handle arrays through separate DCPU_DECLARE_ARRAY() and
 * DCPU_DEFINE_ARRAY() macros.
 */
#define DPCPU_DEF_GET(n) (&DPCPU_DEFADDR_NAME(n))[sizeof(struct { int n; }) > sizeof(int) ? -(sizeof(struct { int n; })/sizeof(int)) : 0]

#define _DPCPU_REGISTER_DEFINITION(t, n, uniquifier)			\
	static void dpcpu_registration_ ## uniquifier (void) __attribute__((__constructor__)); \
	static void dpcpu_registration_ ## uniquifier (void) {		\
		typedef struct { t DPCPU_NAME(n); } sizer;		\
									\
		if (dpcpu_num_definitions >= DPCPU_MAX_DEFINITIONS)	\
			panic("Too many DPCPU definitions\n");		\
									\
		dpcpu_definitions[dpcpu_num_definitions].addr = &DPCPU_NAME(n);	\
		dpcpu_definitions[dpcpu_num_definitions].copysize = sizeof(sizer); \
		dpcpu_definitions[dpcpu_num_definitions].copyoffset = dpcpu_total_size; \
		DPCPU_DEF_GET(n) = &dpcpu_definitions[dpcpu_num_definitions]; \
		dpcpu_total_size += roundup(dpcpu_definitions[dpcpu_num_definitions].copysize, DPCPU_ALIGN); \
		dpcpu_num_definitions++;				\
	}

/* The indirection is so macro unquifiers such as __LINE__ are expanded. */
#define DPCPU_REGISTER_DEFINITION(t, n, uniquifier)	_DPCPU_REGISTER_DEFINITION(t, n, uniquifier)

/*
 * Declaration and definition.
 */
#undef DPCPU_DECLARE
#undef DPCPU_DEFINE
#define	DPCPU_DECLARE(t, n)						\
	extern t DPCPU_NAME(n);						\
	extern struct dpcpu_definition *DPCPU_DEFADDR_NAME(n)

/*
 * The use of __LINE__ below as a uniquifier can of course fail to provide
 * the required uniqueness, but in practice this has worked well enough.
 */
#define	DPCPU_DEFINE(t, n)						\
	t DPCPU_NAME(n);						\
	struct dpcpu_definition *DPCPU_DEFADDR_NAME(n);			\
	DPCPU_REGISTER_DEFINITION(t, n, __LINE__)

/*
 * Accessors with a given base.
 */

/*
 * DPCPU_START is added in the address computation below because of the way
 * the base (pcpup->dynamic) is computed (see dpcpu_init() in subr_pcpu.c).
 */
#undef _DPCPU_PTR
#define	_DPCPU_PTR(b, n)					\
	(__typeof(DPCPU_NAME(n))*)((b) + DPCPU_DEF_GET(n)->copyoffset + DPCPU_START)


#include "uinet_host_interface.h"

extern uhi_tls_key_t kthread_tls_key;
#undef curthread


#ifdef HAS_NATIVE_TLS
extern __thread struct uinet_thread uinet_curthread;
#define curthread ((struct thread *)(&uinet_curthread))
#else
#define curthread ((struct thread *)uhi_tls_get(kthread_tls_key))
#endif

#endif	/* _UINET_SYS_PCPU_H_ */
