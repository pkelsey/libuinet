#	@(#)Makefile	8.2 (Berkeley) 3/21/94
# $FreeBSD: release/9.1.0/sys/kern/Makefile 219131 2011-03-01 13:28:27Z rwatson $

# Makefile for init_sysent

all:
	@echo "make sysent only"

sysent: init_sysent.c syscalls.c ../sys/syscall.h ../sys/syscall.mk \
../sys/sysproto.h

init_sysent.c syscalls.c systrace_args.c ../sys/syscall.h \
../sys/syscall.mk ../sys/sysproto.h: makesyscalls.sh syscalls.master \
capabilities.conf
	-mv -f init_sysent.c init_sysent.c.bak
	-mv -f syscalls.c syscalls.c.bak
	-mv -f systrace_args.c systrace_args.c.bak
	-mv -f ../sys/syscall.h ../sys/syscall.h.bak
	-mv -f ../sys/syscall.mk ../sys/syscall.mk.bak
	-mv -f ../sys/sysproto.h ../sys/sysproto.h.bak
	sh makesyscalls.sh syscalls.master
