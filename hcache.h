#ifndef _HCACHE_H
#define _HCACHE_H 1
#include "datatypes.h"

/* ------------------------------------------------------------------------- *\
 * Hostcache, keep track of some host specific data in a one-level hashed    *
 * table (using the low octet of the ip address as a hash.                   *
\* ------------------------------------------------------------------------- */
typedef struct hcache_log_struc
{
	time_t 					 when;
	status_t				 status;
} hcache_log;

typedef struct hcachenode_struc
{
	struct hcachenode_struc	*next;
	unsigned long			 addr; /* ip address */
	unsigned int			 lasttime; /* last reported host time */
	time_t					 lastseen; /* local time of last packet */
	unsigned int			 uptime; /* machine's recorded uptime */
	hcache_log				 events[8]; /* past events to stop wobble */
	unsigned char			 evpos; /* position in the events[] array */
	status_t				 status;
	oflag_t					 oflags;
	unsigned int			 services;
	unsigned int			 alertlevel;
	time_t					 ctime;
	unsigned int			 netin;
	unsigned int			 netout;
	unsigned short			 ping10;
	unsigned short			 loss;
	unsigned char			 cpu;
	unsigned short			 load1;
	unsigned int			 diskio;
	unsigned char			 isfresh;
} hcache_node;

typedef struct hcache_struc
{
	hcache_node	*hash[256];
	hcache_node *resultcache;
} hcache;

typedef struct hstat_struc
{
	unsigned long addr;
	status_t status;
	oflag_t oflags;
	unsigned int netin;
	unsigned int netout;
	unsigned short ping10;
	unsigned short loss;
	unsigned char cpu;
	unsigned short load1;
	unsigned int diskio;
} hstat;

hcache_node 	*hcache_resolve (hcache *, unsigned long);
unsigned int	 hcache_getlast (hcache *, unsigned long);
status_t		 hcache_getstatus (hcache *, unsigned long);
unsigned int	 hcache_getuptime (hcache *, unsigned long);
unsigned int	 hcache_getservices (hcache *, unsigned long);
oflag_t			 hcache_getoflags (hcache *, unsigned long);
void			 hcache_setlast (hcache *, unsigned long, unsigned int);
void			 hcache_setstatus (hcache *, unsigned long, status_t);
void			 hcache_setuptime (hcache *, unsigned long, unsigned int);
void			 hcache_setservices (hcache *, unsigned long, unsigned int);
void			 hcache_setoflags (hcache *, unsigned long, oflag_t);
void			 hcache_setdata (hcache *, unsigned long,
								 unsigned int, unsigned int,
								 unsigned short, unsigned short,
								 unsigned short, unsigned char,
								 unsigned int);

#endif
