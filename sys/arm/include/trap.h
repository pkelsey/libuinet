/*	$NetBSD: trap.h,v 1.1 2001/02/23 03:48:19 ichiro Exp $	*/
/* $FreeBSD: release/9.1.0/sys/arm/include/trap.h 140001 2005-01-10 22:43:16Z cognet $ */

#ifndef _MACHINE_TRAP_H_
#define _MACHINE_TRAP_H_
#define GDB_BREAKPOINT		0xe6000011
#define GDB5_BREAKPOINT		0xe7ffdefe
#define PTRACE_BREAKPOINT	0xe7fffff0
#define KERNEL_BREAKPOINT	0xe7ffffff
#endif /* _MACHINE_TRAP_H_ */
