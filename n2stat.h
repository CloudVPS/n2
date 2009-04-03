#ifndef _N2STAT_H
#define _N2STAT_H 1

#include "datatypes.h"
#include "tproc.h"

#define MY_HWTYPE HW_IA32
#define MY_OSTYPE OS_LINUX

#define MAX_NTOP 12

typedef unsigned short portlist[65536][3];

portlist	*getports		(void);
procrun		*getprocs		(void);
void		 gather_init	(void);
void		 gather_io		(netload_info *);
void		 gather_hostdat (netload_info *);
void		 gather_load 	(netload_info *);
void		 gather_meminfo (netload_info *);
void		 gather_netinfo (netload_info *);
void		 gather_mounts 	(netload_info *);
void		 sample_tprocs	(netload_info *);
void		 gather_tprocs	(netload_info *);
void		 gather_ports	(netload_info *);
void		 gather_ttys	(netload_info *);
int			 cpu_count		(void);

extern int interface_configures (const char *);

#endif
