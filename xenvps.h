#ifndef _XENVPS_H
#define _XENVPS_H 1

#include "datatypes.h"

typedef struct xenvps_struc
{
	char			id[16];
	unsigned int	memory;
	unsigned int	pcpu;
	unsigned int	iops;
	short			active;
} xenvps;

typedef struct vplist_struc
{
	int				 arraysz;
	int				 count;
	xenvps			*array;
	
	time_t			 lastround;
} vpslist;

void vpslist_init     (vpslist *);
void vpslist_setvps   (vpslist *, const char *, unsigned short,
					   unsigned int, unsigned int);
int  vpslist_findvps  (vpslist *, const char *);
int  vpslist_alloc    (vpslist *);
void vpslist_sweep     (vpslist *, int);

extern vpslist *VPS;

void init_xenvps      (void);
void gather_xenvps    (netload_info *inf);

#endif
