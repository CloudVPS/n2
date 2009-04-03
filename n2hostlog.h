#ifndef _N2HOSTLOG_H
#define _N2HOSTLOG_H 1

#include <sys/types.h>
#include <time.h>

#include "datatypes.h"
#include "n2encoding.h"

typedef struct n2logentry_struc
{
	time_t			ts;
	status_t		ostatus;
	status_t		nstatus;
	char			len;
	char			text[117];
	oflag_t			oflags;
} n2logentry;

typedef struct n2hostlog_struc
{
	unsigned short	pos;
	n2logentry		entries[64];
} n2hostlog;

n2hostlog *load_hostlog (unsigned int);
void save_hostlog (unsigned int, n2hostlog *);
void hostlog (unsigned int, status_t o, status_t n, oflag_t, const char *);
void print_hostlog (unsigned int);
void print_hostlog_xml (unsigned int);

#endif
