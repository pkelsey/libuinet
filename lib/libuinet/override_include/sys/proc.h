/*-
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

#ifndef	_UINET_SYS_PROC_H_
#define _UINET_SYS_PROC_H_

#include "uinet_host_interface.h"
#include_next <sys/proc.h>

struct uinet_thread {
	/*
	 * td must be the first member in this structure so that it can be
	 * retrieved given a uinet_thread * without having the definition of
	 * struct uinet_thread, otherwise there is a circular dependency
	 * where sys/proc.h needs to know what a struct uinet_thread, but it
	 * cannot as it defines struct thread, which is a part of struct
	 * uinet_thread.
	 */
	struct thread td;
	struct mtx lock;
	struct cv cond;
	/* other uinet thread local data goes here */
};

#define thread0 (*((struct thread *)uinet_thread0))

extern struct uinet_thread *uinet_thread0;
extern uhi_tls_key_t kthread_tls_key;

void uinet_thread_init(void);
struct uinet_thread *uinet_thread_alloc(struct proc *p);
void uinet_thread_free(struct uinet_thread *utd);

#endif	/* _UINET_SYS_PROC_H_ */
