#ifndef _N2PING_H
#define _N2PING_H 1

/* -------------------------------------------------------------------------- *\
 * Includes                                                                   *
\* -------------------------------------------------------------------------- */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <netdb.h>

/* -------------------------------------------------------------------------- *\
 * Constants                                                                  *
\* -------------------------------------------------------------------------- */

#define  MAXPACKET  65535
#define  PKTSIZE    64 
#define  HDRLEN     ICMP_MINLEN
#define  DATALEN    (PKTSIZE-HDRLEN)
#define  MAXDATA    (MAXPKT-HDRLEN-TIMLEN)

/* -------------------------------------------------------------------------- *\
 * Type definitions                                                           *
\* -------------------------------------------------------------------------- */

typedef struct ping_log_struc
{
	unsigned short	times[256];
	unsigned short	pos;
} ping_log;

struct ping_rec_struc
{
	struct ping_rec_struc	*next;
	unsigned long			 addr;
	unsigned int			 seq;
	struct timeval			 tsent;
	unsigned short			 rtt;
	unsigned short			 active;
	ping_log				 log;
};

typedef struct ping_rec_struc ping_rec;

typedef struct ping_rec_array_struc
{
	ping_rec	*first;
	int			 count;
} ping_rec_array;

/* -------------------------------------------------------------------------- *\
 * Globals                                                                    *
\* -------------------------------------------------------------------------- */

extern ping_rec_array PINGDB;

/* -------------------------------------------------------------------------- *\
 * Prototypes for external functions                                          *
\* -------------------------------------------------------------------------- */

ping_log		*read_ping_data (unsigned long);
unsigned short	 calc_ping10 (ping_log *);
unsigned short	 calc_loss (ping_log *);

#endif
