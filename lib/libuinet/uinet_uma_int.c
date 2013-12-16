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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/uma_int.h>


/*
 * XXX this should really be handled by SYSINIT I think.  Although it works
 * out with the current port, calling mtx_init() before mutex_init() is
 * called is technically wrong.
 */
static void thread_bucket_lock_init(void) __attribute__((constructor));
static void uma_page_slab_hash_lock_init(void) __attribute__((constructor));


struct mtx bucket_lock;
struct mtx page_slab_hash_lock;
int uma_page_mask;
struct uma_page_head *uma_page_slab_hash;


static void
thread_bucket_lock_init(void)
{
	mtx_init(&bucket_lock, "bucket lock", NULL, MTX_DEF);
}

void
thread_bucket_lock(void)
{

        mtx_lock(&bucket_lock);
}

void
thread_bucket_unlock(void)
{

        mtx_unlock(&bucket_lock);
}


static void
uma_page_slab_hash_lock_init(void)
{
	mtx_init(&page_slab_hash_lock, "uma page slab hash lock", NULL, MTX_DEF);
}

void
uma_page_slab_hash_lock(void)
{

        mtx_lock(&page_slab_hash_lock);
}

void
uma_page_slab_hash_unlock(void)
{

        mtx_unlock(&page_slab_hash_lock);
}
