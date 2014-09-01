#ifndef	__U_SYSCTL_H__
#define	__U_SYSCTL_H__

extern	int u_sysctlbyname(int ns, const char *name, void *oldp,
	    size_t *oldlenp, const void *newp, size_t newlen);

extern	int u_sysctl(int ns, int *oid, u_int namelen, void *oldp,
	size_t *oldlenp, const void *newp, size_t newlen);

extern	int u_sysctl_open(void);

#endif	/* __U_SYSCTL_H__ */
