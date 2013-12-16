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
 */

#ifndef	_UINET_VM_UMA_INT_H_
#define _UINET_VM_UMA_INT_H_
#define vtoslab		vtoslab_native
#define vsetslab	vsetslab_native
#define vsetobj		vsetobj_native
#include_next <vm/uma_int.h>
#undef	vtoslab
#undef	vsetslab
#undef	vsetobj

#define vsetobj(a, b)	panic("vsetobj() not implemented\n")

#undef UMA_MD_SMALL_ALLOC
#define NO_OBJ_ALLOC


void thread_bucket_lock(void);
void thread_bucket_unlock(void);
void uma_page_slab_hash_lock(void);
void uma_page_slab_hash_unlock(void);

#define critical_enter()        thread_bucket_lock()
#define critical_exit()         thread_bucket_unlock()

extern int uma_page_mask;


#define UMA_PAGE_HASH(pgno) ((pgno) & uma_page_mask)

typedef struct uma_page {
        LIST_ENTRY(uma_page)    list_entry;
	unsigned long		up_pageno;
        uma_slab_t              up_slab;
} *uma_page_t;

LIST_HEAD(uma_page_head, uma_page);
extern struct uma_page_head *uma_page_slab_hash;

static __inline uma_slab_t
vtoslab(vm_offset_t va)
{       
        struct uma_page_head *hash_list;
        uma_page_t up;
	uma_slab_t slab = NULL;
	unsigned long pageno = atop(va);

        hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(pageno)];

 	uma_page_slab_hash_lock();
	LIST_FOREACH(up, hash_list, list_entry)
	    if (up->up_pageno == pageno) {
		    slab = up->up_slab;
		    break;
	    }
	uma_page_slab_hash_unlock();
	
        return (slab);
}

static __inline void
vsetslab(vm_offset_t va, uma_slab_t slab)
{
        struct uma_page_head *hash_list;
        uma_page_t up;
	unsigned long pageno = atop(va);
	
        hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(pageno)];

 	uma_page_slab_hash_lock();
	
	LIST_FOREACH(up, hash_list, list_entry)
                if (up->up_pageno == pageno)
                        break;

        if (up != NULL) {
                up->up_slab = slab;
        } else {
		up = malloc(sizeof(*up), M_DEVBUF, M_WAITOK);
		up->up_pageno = pageno;
		up->up_slab = slab;
		LIST_INSERT_HEAD(hash_list, up, list_entry);
	}

	uma_page_slab_hash_unlock();
}

#endif	/* _UINET_VM_UMA_INT_H_ */
