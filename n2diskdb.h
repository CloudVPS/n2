#ifndef N2DISKDB_H
#define N2DISKDB_H 1

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "datatypes.h"

typedef struct n2statitem_struc
{
	unsigned short		load;
	unsigned short		cpuusage;
	int					kmemfree;
	unsigned short		netin;
	unsigned short		netout;
	unsigned short		ping;
	status_t			worststatus;
} n2statitem;

typedef struct n2stat_struc
{
	unsigned long	host;
	unsigned int	date;
	int				count;
	int				starttime;
	int				endtime;
	n2statitem		data[0];
} n2stat;

unsigned int  tdate_sub			(unsigned int, int);
void		  diskdb_setlck		(netload_rec *rec);
void		  diskdb_clrlck		(netload_rec *rec);
int			  diskdb_locked     (netload_rec *rec);
int		 	  diskdb_open		(unsigned long host, unsigned int date);
void		  diskdb_now		(unsigned int *, int *);

void		  diskdb_setcurrent (unsigned long host,
								 netload_rec *rec);

void		  diskdb_store      (unsigned long host,
								 netload_rec *rec,
								 unsigned int date,
								 int index);
						  
netload_rec  *diskdb_get        (unsigned long host,
								 unsigned int date,
								 int index);

netload_rec	 *diskdb_get_current(unsigned long host);
								
netload_rec **diskdb_get_range  (unsigned long host,
								 unsigned int date,
								 int first,
								 int last);
										
n2stat		 *diskdb_stats		(unsigned long host,
								 unsigned int date,
								 int numberofrecords,
								 int first,
								 int last);

#endif
