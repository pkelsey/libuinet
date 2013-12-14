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


#ifndef	_UINET_SYS_LINKER_SET_H_
#define _UINET_SYS_LINKER_SET_H_


/*
 * Linker sets are trouble because platforms that use Mach-O binary format
 * have a 16-character limit to section names, and the names used in FreeBSD
 * linker sets are not close to working with that.  Instead of using actual
 * linker sets, each data set is a fixed-size array of pointers to data set
 * elements.
 *
 * This works, although it requires -Wredundant-decls to not be used when
 * building.
 *
 */

#include <sys/systm.h>

#define LINKER_SET_MAX_SIZE	1024

#define DATA_SET(set, sym)						\
	extern __typeof__(__typeof__(sym) *) __CONCAT(__set_,set)[LINKER_SET_MAX_SIZE]; \
	extern unsigned int __CONCAT(__size_of_set_,set);		\
	static void __set_ ## set ## _register_ ## sym (void) __attribute__((__constructor__)); \
	static void __set_ ## set ## _register_ ## sym (void) {		\
		if (__CONCAT(__size_of_set_,set) >= LINKER_SET_MAX_SIZE) \
			panic("Too many entries in DATA_SET %s\n", #set); \
		__CONCAT(__set_,set)[__CONCAT(__size_of_set_,set)] = &sym; \
		__CONCAT(__size_of_set_,set)++;				\
	}
	
#define SET_DECLARE(set, ptype)						\
	ptype *__CONCAT(__set_,set)[LINKER_SET_MAX_SIZE];		\
	unsigned int __CONCAT(__size_of_set_,set)

#define SET_BEGIN(set)							\
	(&__CONCAT(__set_,set)[0])

#define SET_LIMIT(set)							\
	(&__CONCAT(__set_,set)[__CONCAT(__size_of_set_,set)])

/*
 * Iterate over all the elements of a set.
 *
 * Sets always contain addresses of things, and "pvar" points to words
 * containing those addresses.  Thus is must be declared as "type **pvar",
 * and the address of each set item is obtained inside the loop by "*pvar".
 */
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)

#endif	/* _UINET_SYS_LINKER_SET_H_ */
