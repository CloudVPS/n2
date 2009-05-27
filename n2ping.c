#include "n2ping.h"
#include "n2malloc.h"

#include <dirent.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <syslog.h>

int icmp_ping_socket;
uid_t runas_uid;
gid_t runas_gid;

/* ------------------------------------------------------------------------- *\
 * Prototypes for internal functions                                         *
\* ------------------------------------------------------------------------- */
int				 in_checksum (u_short *, int);
void			 ping_init (void);
void			 send_ping_pkt (unsigned long, unsigned int);
void			 musleep (int);
unsigned short	 calc_rtt (struct timeval *, struct timeval *);
void 			*ping_send_thread (void *);
void 			*ping_recv_thread (void *);
void			 ping_main_thread (void);
ping_rec 		*find_host_rec (unsigned long);
ping_rec 		*create_host_rec (unsigned long);
unsigned int	 generate_icmp_seq (void);
void			 daemonize (void);

ping_rec_array	 PINGDB;

/* ------------------------------------------------------------------------- *\
 * FUNCTION in_checksum (data, length)                                       *
 * -----------------------------------                                       *
 * Calculates the checksum for a bunch of data.                              *
\* ------------------------------------------------------------------------- */
int in_checksum (unsigned short *buf, int len)
{
	register long sum = 0;
	unsigned short answer = 0;
	
	while (len>1)
	{
		sum+= *buf++;
		len -=2;
	}
	
	if (len==1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)buf;
		sum+= answer;
	}
	sum = (sum>>16) + (sum &0xffff);
	sum += (sum>>16);
	answer = ~sum;
	return answer;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION ping_init (void)                                                 *
 * -------------------------                                                 *
 * Attempts to create the socket needed to send and receive the icmp packets *
 * and initializes the PINGDB linked list global.                            *
\* ------------------------------------------------------------------------- */
void ping_init (void)
{
	struct protoent	*proto;
	if ( (proto = getprotobyname ("icmp")) == NULL)
	{
		fprintf (stderr, "%% Could not resolve protocol: icmp\n");
		exit (1);
	}
	
	icmp_ping_socket = socket (AF_INET, SOCK_RAW, proto->p_proto);
	if (icmp_ping_socket < 0)
	{
		fprintf (stderr, "%% Could not open raw socket for icmp\n");
		if (getuid())
			fprintf (stderr, "  This is probably because the daemon is not set "
							   "to run as user root.\n");
		exit (1);
	}
	
	PINGDB.count = 0;
	PINGDB.first = NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION send_ping_pkt (address, seq)                                     *
 * -------------------------------------                                     *
 * Assembles and sends an icmp echo request packet with the provided         *
 * sequence number to the provided address.                                  *
\* ------------------------------------------------------------------------- */
void send_ping_pkt (unsigned long ip, unsigned int seq)
{
	struct sockaddr_in taddr;
	unsigned char buf[HDRLEN+DATALEN];
	struct icmp *icp;
	int rsize;
	
	taddr.sin_addr.s_addr = htonl (ip);
	taddr.sin_port = 0;
	taddr.sin_family = AF_INET;
	
	icp 			= (struct icmp *) buf;
	
	icp->icmp_type	= ICMP_ECHO;
	icp->icmp_code	= 0;
	icp->icmp_cksum	= 0;
	icp->icmp_id	= (seq & 0xffff0000) >> 16;
	icp->icmp_seq	= (seq & 0x0000ffff);
	icp->icmp_cksum	= in_checksum ((unsigned short *) icp, HDRLEN+DATALEN);
	
	printf ("sending ping to %08x seq=%04x\n", ip, seq & 0xffff);
	
	rsize = sendto (icmp_ping_socket, buf, sizeof (buf), 0,
					(struct sockaddr *) &taddr, sizeof (taddr));
	
	if (rsize < 0)
	{
		/* FIXME: don't just stand there... Do something! */
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION musleep (milliseconds)                                           *
 * -------------------------------                                           *
 * Takes micro-naps.                                                         *
\* ------------------------------------------------------------------------- */
void musleep (int msec)
{
	struct timeval tv;
	int sec, usec;
	
 	sec = msec / 1000;
	usec = 1000 * (msec - (1000 * sec));
	
	tv.tv_sec = sec;
	tv.tv_usec = usec;
	
	select (0, NULL, NULL, NULL, &tv);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION calc_rtt (timesent, timereceived)                                *
 * ------------------------------------------                                *
 * Calculates the roundtrip-time in tenths of milliseconds between the two   *
 * provided timeval structures.                                              *
\* ------------------------------------------------------------------------- */
unsigned short calc_rtt (struct timeval *sent, struct timeval *received)
{
	unsigned long tsent, trecv;
	
	/* calculate the delta time */
	tsent  = sent->tv_usec / 100;
	trecv  = (received->tv_sec - sent->tv_sec) * 10000;
	trecv += (received->tv_usec) / 100;
	
	//printf ("rtt %d %d\n", tsent, trecv);
	
	/* rtt out of bounds, return unreachable */
	if ((trecv - tsent) > 65000) return 0;
	
	if ((trecv - tsent) == 0) return 1;
	
	/* return calculated result */
	return ((trecv - tsent) & 0xffff);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION ping_send_thread (nihil)                                         *
 * ---------------------------------                                         *
 * Implements the threads that pings all configured hosts and processes the  *
 * round-trip times measured by the ping_receive_thread.                     *
\* ------------------------------------------------------------------------- */
void *ping_send_thread (void *nop)
{
	ping_rec 	*host;
	unsigned int roundcount = 0;
	int			 i = 0;

	while (1)
	{
		host = PINGDB.first;
		if (roundcount < 10) roundcount++;
		
		/* For each and every host */
		while (host)
		{
			if (host->active)
			{
				/* Clean up the results from the previous round */
				if (! host->rtt)
				{
					if (roundcount < 10) host->rtt = 1;
				}
				host->log.times[host->log.pos] = host->rtt;
				host->log.pos = (host->log.pos +1) & 0xff;
				
				/* Start a new round */
				host->seq = generate_icmp_seq();
				gettimeofday (&host->tsent, NULL);
				host->rtt = 0;
				
				/* Send the packet */
				send_ping_pkt (host->addr, host->seq);
				//printf ("sent ping\n");
			}
			
			/* Move on */
			host = host->next;
			
			i++;
			if (i&1)
			{
				/* Take a nap */
				musleep (2900 / PINGDB.count);
			}
		}
	}
}

struct ippkt
{
	struct iphdr ip;
	struct icmp  icp;
	char   buffer[1500];
};

/* ------------------------------------------------------------------------- *\
 * FUNCTION ping_recv_thread (nihil)                                         *
 * ---------------------------------                                         *
 * Implementation of the thread that receives icmp echo reply packets and    *
 * processes them in the hostrec table by setting the proper rtt value.      *
\* ------------------------------------------------------------------------- */
void *ping_recv_thread (void *nop)
{
	unsigned char		 buf[HDRLEN+DATALEN];
	struct icmp			*icp;
	struct timeval		 tv;
	struct sockaddr_in	 faddr;
	int					 rsz;
	int					 from;
	ping_rec			*host;
	unsigned long		 ipaddr;
	unsigned int		 inseq;
	unsigned short		 rtt;
	struct ippkt		 pkt;
	FILE				*fseq;
	
	openlog ("n2ping", LOG_PID, LOG_DAEMON);
	
	while (1)
	{
		/* Receive ICMP packet from the raw socket */
		rsz = read (icmp_ping_socket, &pkt, 1500);

		/* Store the time immediately for highest accuracy */
		gettimeofday (&tv, NULL);

		/* See if we are looking out for a reply packet from this ip */
		ipaddr	= ntohl (pkt.ip.saddr);
		host	= find_host_rec (ipaddr);
	
		if (host) /* Found one */
		{
			/* Extract the 16-bit sequence */
			icp 	= &pkt.icp;
			inseq	= icp->icmp_seq;
			
			printf ("icmp from %08x seq=%04x", ipaddr, inseq);
	
			/* the icmp id for echo replies is not guaranteed to be
			   echoed from the echo request packet, grsecurity for
			   instance randomizes it */
			   
			if ( (icp->icmp_type == ICMP_ECHOREPLY) &&
				 (inseq == (host->seq & 0xffff)) )
			{
				/* Calculate the roundtrip-time */
				rtt = calc_rtt (&host->tsent, &tv);
				
				//printf ("rtt %d\n", rtt);
				
				/* Which is only valid if the sequence didn't change while
				   we were calculating it */
				   
				if (inseq == (host->seq & 0xffff))
				{
					/* If the packet is older than 4 seconds, chances are tha
					   we are in the "naughty zone" of sequence-overlap. A 4
					   second ping reply is late enough to declare a host
					   unreachable. If you want to adapt this program for
					   interplanetary IP, you will have to start using
					   pthread_mutexen, making the timing less accurate. */
					   
					if (rtt < 40000)
					{
						printf (" rtt=%i\n", rtt);
						host->rtt = rtt;
					}
					else
					{
						printf (" !!!! rtt=%i\n", rtt);
					}
				}
			}
			else
			{
				if (icp->icmp_type != ICMP_ECHOREPLY)
				{
					printf (": wrong icmp type\n");
				}
				else
				{
					syslog (LOG_ERROR, "ICMP from %08x seq %04x != %04x",
							ipaddr, inseq, host->seq & 0xffff);
				}
			}
		}
		else
		{
			printf ("icmp from unknown host %08x\n", ipaddr);
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION ping_main_thread (void)                                          *
 * --------------------------------                                          *
 * Implementation of the main thread, which does bookkeeping on the file-    *
 * system: The list of hosts-to-ping is synced with /var/state/n2/current    *
 * and the files in /var/state/n2/ping are written at a regular interval.    *
\* ------------------------------------------------------------------------- */
void ping_main_thread (void)
{
	DIR *d;
	struct dirent *de;
	unsigned int addr;
	ping_rec *host;
	struct timeval tv;
	char fname[256];
	char newname[256];
	FILE *F;
	int stres;
	struct stat st;
	
	while (1)
	{
		d = opendir ("/var/state/n2/current");
		while ( (de = readdir (d)) )
		{
			addr = ntohl (inet_addr (de->d_name));
			if (addr != 0xffffffff)
			{
				host = find_host_rec (addr);
				if (! host)
				{
					create_host_rec (addr);
				}
			}
		}
		closedir (d);

		host = PINGDB.first;
		while (host)
		{
			sprintf (fname, "/var/state/n2/current/%d.%d.%d.%d",
							 (host->addr & 0xff000000) >> 24,
							 (host->addr & 0x00ff0000) >> 16,
							 (host->addr & 0x0000ff00) >> 8,
							 (host->addr & 0x000000ff));
			
			stres = stat (fname, &st);

			sprintf (fname, "/var/state/n2/ping/%d.%d.%d.%d",
							 (host->addr & 0xff000000) >> 24,
							 (host->addr & 0x00ff0000) >> 16,
							 (host->addr & 0x0000ff00) >> 8,
							 (host->addr & 0x000000ff));

			if (stres != 0)
			{
				unlink (fname);
				host->active = 0;
			}
			else
			{
				strcpy (newname, fname);
				strcat (fname, ".new");
	
				F = fopen (fname, "w");
				if (F)
				{
					fwrite (&host->log, sizeof (ping_log), 1, F);
					fclose (F);
					rename (fname, newname);
				}
			}

			host = host->next;
			musleep (5000 / PINGDB.count);
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION find_host_rec (address)                                          *
 * --------------------------------                                          *
 * Looks up a host record in the PINGDB list by its ip address.              *
\* ------------------------------------------------------------------------- */
ping_rec *find_host_rec (unsigned long addr)
{
	ping_rec *crsr = PINGDB.first;
	while (crsr)
	{
		if (crsr->addr == addr)
			return crsr;
		crsr = crsr->next;
	}
	return crsr;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION create_host_rec (address)                                        *
 * ----------------------------------                                        *
 * Creates a new host record for an ip address and adds it to PINGDB.        *
\* ------------------------------------------------------------------------- */
ping_rec *create_host_rec (unsigned long addr)
{
	ping_rec *host;
	ping_rec *crsr;
	int i;
	
	/* Allocate memory */
	host = (ping_rec *) pool_alloc (sizeof (ping_rec));
	
	/* Initialize structure */
	host->addr = addr;
	host->seq = 0;
	host->active = 1;
	gettimeofday (&host->tsent, NULL);
	host->rtt = 1;
	bzero (&(host->log), sizeof (short[257]));
	for (i=0; i<256; ++i) host->log.times[i] = 1;
	
	host->next = NULL;
	
	/* If there are no records yet, insert as first element */
	if (! PINGDB.first)
	{
		PINGDB.first = host;
		PINGDB.count = 1;
		return host;
	}
	
	PINGDB.count++;
	
	/* Otherwise, add to the tail */
	crsr = PINGDB.first;
	while (crsr->next) crsr = crsr->next;
	crsr->next = host;
	return host;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION generate_icmp_seq (void)                                         *
 * ---------------------------------                                         *
 * Creates a new random icmp id and sequence number.                         *
\* ------------------------------------------------------------------------- */
unsigned int generate_icmp_seq (void)
{
	struct timeval tv;
	unsigned int seed;
	
	gettimeofday (&tv, NULL);
	
	seed = tv.tv_usec;
	seed ^= tv.tv_sec;
	
	srandom (seed);
	return random();
}

int main (int argc, char *argv[])
{
	pthread_attr_t	 myattr;
	pthread_t		 mythr;
	
	pool_init ();
	ping_init ();
	daemonize ();
	
	pthread_attr_init (&myattr);
	pthread_create (&mythr, &myattr, ping_send_thread, NULL);
	pthread_detach (mythr);
	
	pthread_create (&mythr, &myattr, ping_recv_thread, NULL);
	pthread_detach (mythr);
	
	pthread_create (&mythr, &myattr, ping_recv_thread, NULL);
	pthread_detach (mythr);
	
	pthread_create (&mythr, &myattr, ping_recv_thread, NULL);
	pthread_detach (mythr);
	
	ping_main_thread();
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION daemonize (void)                                                 *
 * -------------------------                                                 *
 * Change userid/groupid and fork into the background.                       *
\* ------------------------------------------------------------------------- */
void daemonize (void)
{
	pid_t pid1;
	pid_t pid2;
	FILE *pidfile;
	uid_t uid;
	gid_t gid;
	struct passwd *pwd;
	
	pidfile = fopen ("/var/run/n2ping.pid","w");
	
	pwd = getpwnam ("n2");
	if (! pwd) pwd = getpwnam ("nobody");
	if (! pwd)
	{
		fprintf (stderr, "%% No user n2 or nobody found\n");
		exit (1);
	}
	
	uid = pwd->pw_uid;
	gid = pwd->pw_gid;
	
	setregid (gid, gid);
	setreuid (uid, uid);

#ifdef DEBUG
	pid1 = getpid();
	fprintf (pidfile, "%u", pid1);
	fclose (pidfile);
	return;
#endif
	
	switch (pid1 = fork())
	{
		case -1:
			fprintf (stderr, "%% Fork failed\n");
			exit (1);
			
		case 0:
			close (0);
			close (1);
			close (2);
			pid2 = fork();
			if (pid2 < 0) exit (1);
			if (pid2)
			{
				fprintf (pidfile, "%u", pid2);
				fclose (pidfile);
				exit (0);
			}
			fclose (pidfile);
			break;
		
		default:
			exit (0);
	}
}
