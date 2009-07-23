#include "n2stat.h"
#include "n2config.h"
#include "n2args.h"
#include "n2encoding.h"
#include "tproc.h"
#include "datatypes.h"

#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>
#include <paths.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/vmmeter.h>
#include <sys/resource.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/errno.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>

/* --------------------------------------------------------------------------- *\
 * Internal datatypes                                                          *
\* --------------------------------------------------------------------------- */

typedef struct
{
	time_t				 lastrun;
	unsigned long long	 net_in;
	unsigned long long	 net_out;
	unsigned short 		 ports[65536][3];
	procrun				 procs;
	kvm_t				*kvm;
} darwingather_global;

/* --------------------------------------------------------------------------- *\
 * Internal globals                                                            *
\* --------------------------------------------------------------------------- */

darwingather_global GLOB;
int KMEMTOTAL;

portlist *getports (void)
{
	return &GLOB.ports;
}

procrun *getprocs (void)
{
	return &GLOB.procs;
}


/* --------------------------------------------------------------------------- *\
 * Internal function prototypes                                                *
\* --------------------------------------------------------------------------- */

void gather_mounts_getmount (const char *, const char *, unsigned short,
							 netload_info *, unsigned short *, int *);

/* =========================================================================== *\
 * gather_init                                                                 *
 * -----------                                                                 *
 * Initialize globals.                                                         *
\* =========================================================================== */

void gather_init (void)
{
	FILE *F;
	int mib[2];
	char buf[256];
	size_t len;
	int ncpu;
	GLOB.net_in = 0;
	GLOB.net_out = 0;
	GLOB.lastrun = time (NULL);
	
	procrun_init (&GLOB.procs);
	GLOB.procs.ncpu = 0;
	
	len = sizeof (int);
	mib[0] = CTL_HW;
	mib[1] = HW_NCPU;
	sysctl ((int *) mib, 2, &ncpu, &len, NULL, 0);
	GLOB.procs.ncpu = ncpu;
	
	GLOB.kvm = kvm_open (NULL, _PATH_DEVNULL, NULL, O_RDONLY, "n2stat");
}

/* =========================================================================== *\
 * gather_init                                                                 *
 * -----------                                                                 *
 * Initialize globals.                                                         *
\* =========================================================================== */
void gather_io (netload_info *inf)
{
	inf->diskio = 0;
}

/* =========================================================================== *\
 * gather_hostdat                                                              *
 * --------------                                                              *
 * Fill in host operating system data                                          *
\* =========================================================================== */

void gather_hostdat (netload_info *inf)
{
	FILE *F;
	int  mib[2];
	char  buf[256];
	struct timeval tv;
	time_t ti;
	size_t len;
	
	mib[0] = CTL_KERN;
	mib[1] = KERN_BOOTTIME;
	len = sizeof (struct timeval);
	sysctl ((int *) mib, 2, &tv, &len, NULL, 0);
	ti = time (NULL);
	
	strncpy (inf->hostname, CONF.hostname, 23);
	inf->hostname[23] = 0;
	inf->hosttime = ti;
	inf->ostype = OS_BSD;
	inf->hwtype = MY_HWTYPE;
	inf->uptime = ti - tv.tv_sec;
}

/* =========================================================================== *\
 * gather_load                                                                 *
 * -----------                                                                 *
 * Fill in load-average statistics.                                            *
\* =========================================================================== */

void gather_load (netload_info *inf)
{
	FILE 			*F;
	char 			 buf[256];
	int				 mib[2];
	size_t			 len;
	n2arglist		*arg;
	char			*slash;
	double			 td;
	struct loadavg	 load;
	struct vmtotal	 vmt;
	
	mib[0] = CTL_VM;
	mib[1] = VM_LOADAVG;
	len = sizeof (struct loadavg);
	sysctl ((int *) mib, 2, &load, &len, NULL, 0);
	inf->load1 = ( 100 * load.ldavg[0] ) / load.fscale;

	mib[0] = CTL_VM;
	mib[1] = VM_METER;
	len = sizeof (struct vmtotal);
	sysctl (mib, 2, &vmt, &len, NULL, 0);
	
	inf->nrun = vmt.t_rq;
	inf->nproc = 0;
}

void get_sysctl (const char *name, int *ptr, size_t len)
{
	size_t nlen = len;
	
	if (sysctlbyname (name, ptr, &nlen, NULL, 0) == -1)
	{
		fprintf (stderr, "fook: %s\n", strerror (errno));
		return;
	}
	
	if (nlen != len)
	{
		fprintf (stderr, "size fuuq: %lu != %lu\n",
				 len, nlen);
	}
}

/* =========================================================================== *\
 * gather_meminfo                                                              *
 * --------------                                                              *
 * Fill in memory/swap usage                                                   *
\* =========================================================================== */

void gather_meminfo (netload_info *inf)
{
	FILE 			*F;
	char 			 buf[256];
	size_t			 physmem;
	size_t			 len;
	int				 memstats[5];
	int				 psz;
	struct kvm_swap	 swaps[8];
	int				 scnt;
	int				 spages = 0;
	int				 i;
		
	psz = getpagesize();
	get_sysctl ("hw.availpages", &memstats[0], sizeof(int));
	get_sysctl ("hw.physmem", &memstats[1], sizeof(int));
	get_sysctl ("vm.stats.vm.v_active_count", &memstats[2], sizeof(int));
	
	// free physical pages
	get_sysctl ("vm.stats.vm.v_free_count", &memstats[3], sizeof(int));

	scnt = kvm_getswapinfo (GLOB.kvm, swaps, 8, 0);
	if (scnt>0)
	{
		for (i=0; i<scnt; ++i)
		{
			spages += (swaps[i].ksw_total - swaps[i].ksw_used);
		}
		spages = spages * (psz/1024);
	}
	
	KMEMTOTAL = memstats[1] / 1024;
	
	inf->kmemfree = memstats[3] * (psz/1024);
	inf->kswapfree = spages;
}

/* =========================================================================== *\
 * gather_netinfo                                                              *
 * --------------                                                              *
 * Set network interface statistics                                            *
\* =========================================================================== */

static int mib_net[] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };

void gather_netinfo (netload_info *inf)
{
	FILE				*F;
	char				 buffer[256];
	char				*buf;
	int					 alloc = 0;
	unsigned long long	 totalin;
	unsigned long long	 totalout;
	long long			 diffin;
	long long			 diffout;
	n2arglist			*args;
	char				*colon;
	time_t				 ti;
	int					 mib[6];
	struct if_msghdr	*ifm, *nextifm;
	struct sockaddr_dl	*sdl;
	char				*lim, *next;
	size_t				 needed;

	totalin = 0;
	totalout = 0;
	
	ti = time (NULL);

	if (sysctl (mib_net, 6, NULL, &needed, NULL, 0) < 0)
	{
		printf ("mib_net failure\n");
		return;
	}
	buf = (char *) malloc (needed);
	alloc = needed;
	if (! buf) return;
	
	if (sysctl (mib_net, 6, buf, &needed, NULL, 0) < 0)
		return;
		
	lim = buf + needed;
	next = buf;
	while (next < lim)
	{
		printf ("getting interface stuff\n");
		ifm = (struct if_msghdr *) next;
		if (ifm->ifm_type != RTM_IFINFO)
		{
			printf ("ifm_type != RTM_IFINFO: %i\n", ifm->ifm_type);
			free (buf);
			return;
		}
		
		next += ifm->ifm_msglen;
		while (next < lim)
		{
			nextifm = (struct if_msghdr *) next;
			if (nextifm->ifm_type != RTM_NEWADDR)
				break;
			
			next += nextifm->ifm_msglen;
		}
		if (ifm->ifm_flags & IFF_UP)
		{
			sdl = (struct sockaddr_dl *) (ifm+1);
			if (sdl->sdl_family != AF_LINK)
			{
				printf ("sdl_family != AF_LINK: %i\n", sdl->sdl_family);
				//continue;
			}
		
			totalin += ifm->ifm_data.ifi_ibytes;
			totalout += ifm->ifm_data.ifi_obytes;
			
			printf ("ifi_ibytes = %lu obytes = %lu\n",
					ifm->ifm_data.ifi_ibytes, ifm->ifm_data.ifi_obytes);
		}
	}
	free (buf);
	
	if (GLOB.net_in)
	{
		diffin = totalin - GLOB.net_in;
		if (diffin < 0) diffin = totalin;
		diffout = totalout - GLOB.net_out;
		if (diffout < 0) diffout = totalout;
		diffin = diffin / 128;
		diffout = diffout / 128;
		
		printf ("delta-t=%i\n", ti-GLOB.lastrun);
		printf ("diffin = %u\n", diffin);
		printf ("diffout = %u\n", diffout);
		
		inf->netin = (unsigned short) ((diffin / (ti - GLOB.lastrun)) & 0xffff);
		inf->netout = (unsigned short) ((diffout / (ti - GLOB.lastrun)) & 0xffff);

		#define DELTAT (ti - GLOB.lastrun)
		GLOB.lastrun = ti;
		GLOB.net_in = totalin;
		GLOB.net_out = totalout;
	}
	else
	{
		GLOB.net_in = totalin;
		GLOB.net_out = totalout;
		GLOB.lastrun = ti;
	}
}

/* =========================================================================== *\
 * gather_mounts                                                               *
 * -------------                                                               *
 * Get a list of mounts out of /proc/mtab and fill in the 4 most heavily used  *
 * to return into the netload_info structure.                                  *
\* =========================================================================== */

void gather_mounts (netload_info *inf)
{
	FILE			*F;
	struct statfs	 sfs;
	pid_t			 cpid;
	int				 retval;
	unsigned short	 usage;
	unsigned short	 lowusage;
	int				 lowusageidx;
	const char		*mountpoint;
	const char		*fstype;
	int				 nmounts;
	int				 i;
	n2arglist		*args;
	
	struct statfs	*stbuf;
	int				 stcount;
	size_t			 sz;
	
	lowusage = 1001;
	
	inf->nmounts = 0;
	
	stcount = getfsstat (NULL, 0, MNT_NOWAIT);
	if (stcount<1) return;
	sz = stcount * sizeof (struct statfs);
	stbuf = (struct statfs *) malloc (sz);
	if (! stbuf) return;
	stcount = getfsstat (stbuf, sz, MNT_NOWAIT);
	
	for (i=0; i<stcount; ++i)
	{
		if (strncmp (stbuf[i].f_fstypename, "proc", 4))
		{
			double dfree;
			dfree = ((double)(stbuf[i].f_blocks - stbuf[i].f_bavail)) / (double)stbuf[i].f_blocks;
			gather_mounts_getmount (stbuf[i].f_fstypename,
									stbuf[i].f_mntonname,
									(int) (dfree * 1000),
									inf, &lowusage, &lowusageidx);
		}
	}
	free (stbuf);
}

						
/* =========================================================================== *\
 * gather_mounts_getmount                                                      *
 * ----------------------                                                      *
 * Checks out a specific mount and determines whether it is suitable for       *
 * including into the mountlist.                                               *
\* =========================================================================== */

void gather_mounts_getmount (const char *fstype, const char *mountpoint,
							 unsigned short usage, netload_info *inf,
							 unsigned short *lowusage, int *lowusageidx)
{
	int i;
	int	nmounts;

	if (strcmp (fstype, "proc") &&
		strncmp (fstype, "dev", 3)) /* not procfs or devfsen */
	{
		nmounts = inf->nmounts;

		if (nmounts < 4)
		{
			#define tmnt inf->mounts[nmounts]
			strncpy (tmnt.mountpoint, mountpoint, 31);
			tmnt.mountpoint[31] = 0;
			
			strncpy (tmnt.fstype, fstype, 7);
			tmnt.fstype[7] = 0;
			
			tmnt.usage = usage;

			if (usage < *lowusage)
			{
				*lowusage = usage;
				*lowusageidx = nmounts;
			}
			#undef tmnt

			inf->nmounts++;
		}
		else
		{
			if (usage > *lowusage)
			{
				#define tmnt inf->mounts[*lowusageidx]
				
				strncpy (tmnt.mountpoint, mountpoint, 31);
				tmnt.mountpoint[31] = 0;
				
				strncpy (tmnt.fstype, fstype, 7);
				tmnt.fstype[7] = 0;
				
				tmnt.usage = usage;

				*lowusage = 1001;

				for (i=0; i<4; ++i)
				{
					if (inf->mounts[i].usage < *lowusage)
					{
						*lowusage = inf->mounts[i].usage;
						*lowusageidx = i;
					}
				}
				#undef tmnt
			}
		}
	}
}

/* =========================================================================== *\
 * sample_tprocs                                                               *
 * -------------                                                               *
 * Does a single sample run of the processes found in /proc and lets the       *
 * administration go through the procrun_* functions. This function is ex-     *
 * pected to be run several times during a full stats-gathering round.         *
\* =========================================================================== */

static int mib_procs[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };

void sample_tprocs (netload_info *inf)
{
	struct kinfo_proc *result;
	kvm_t *kvm;
	int count;
	int length;
	int i;
	int err;
	char procnam[24];
	char **pargv;
	
	procrun_initsample (&GLOB.procs);
	
	length = 0;
	
	printf ("CLK_TCK=%i\n", CLK_TCK);
	
	kvm = GLOB.kvm;
	if (kvm)
	{
#ifdef FREEBSD5
		result = kvm_getprocs (kvm, KERN_PROC_PROC, 0, &length);
#else
		result = kvm_getprocs (kvm, KERN_PROC_ALL, 0, &length);
#endif
		if (result)
		{
			count = length;
			inf->nproc = count;
			for (i=0; i < count; ++i)
			{

#ifdef FREEBSD5
				pargv = kvm_getargv (kvm, result+i, 24);

				if (pargv)
				{
					strncpy (procnam, pargv[0], 23);
					procnam[23] = 0;
				}
				else continue;
				
				printf ("runtime=%i\n",result[i].ki_runtime);
				
				procrun_setproc (&GLOB.procs, result[i].ki_pid,
								 (result[i].ki_runtime*CLK_TCK)/1000000LL,
								 0,
								 result[i].ki_ruid,
								 result[i].ki_rgid,
								 procnam,
								 (result[i].ki_rssize*40000)/KMEMTOTAL);
				
#else
				#define KP result[i].kp_proc
			
				strncpy (procnam, KP.p_comm, 23);
				procnam[23] = 0;
				
				procrun_setproc (&GLOB.procs, result[i].kp_proc.p_pid,
								 KP.p_uticks,
								 KP.p_sticks + KP.p_iticks,
								 result[i].kp_eproc.e_pcred.p_ruid,
								 result[i].kp_eproc.e_pcred.p_rgid,
								 procnam,
								 (result[i].kp_eproc.e_xrssize*40000)/KMEMTOTAL
								 );
								 
				#undef KP
#endif
			}
		}
		else
		{
			printf ("foobar1 %s\n", strerror (errno));
		}
	}
}


/* =========================================================================== *\
 * make_top_hole                                                               *
 * -------------                                                               *
 * Internal subroutine to insert an entry into a specific slot of the          *
 * tprocs array.                                                               *
\* =========================================================================== */

void make_top_hole (netload_info *inf, int pos)
{
	int tailsz;
	
	if (pos>2) return;
	tailsz = (4 - pos);
	
	memmove (inf->tprocs + pos + 1,
			 inf->tprocs + pos,
			 tailsz * sizeof (netload_topentry));
	
	if (inf->ntop < 5) ++inf->ntop;
}

/* =========================================================================== *\
 * gather_tprocs                                                               *
 * -------------                                                               *
 * Gathers the statistics of the tprocs sample rounds and puts them into       *
 * the netload_info structure.                                                 *
\* =========================================================================== */

void gather_tprocs (netload_info *inf)
{
	int i;
	int j;
	int inserted;
	struct passwd *pwd;

	sample_tprocs (inf);
	procrun_calc  (&GLOB.procs);
	
	inf->ntop = 0;
	inf->cpu = GLOB.procs.pcpu;
	
	/* Walk through the process table */
	for (i=0; i<GLOB.procs.count; ++i)
	{
		inserted = 0;
		
		/* Skip reaped process slots */
		if (GLOB.procs.array[i].pid)
		{
			/* Find a suitable spot to insert */
			for (j=0; j<inf->ntop; ++j)
			{
				/* bloat(this) > bloat(that) ==> insert */
				if (inf->tprocs[j].pcpu < GLOB.procs.array[i].pcpu)
				{
					make_top_hole (inf, j);
					pwd = getpwuid (GLOB.procs.array[i].uid);
					if (pwd)
					{
						strncpy (inf->tprocs[j].username, pwd->pw_name, 8);
						inf->tprocs[j].username[8] = 0;
					}
					else
					{
						sprintf (inf->tprocs[j].username, "#%d",
								 GLOB.procs.array[i].uid);
					}
					inf->tprocs[j].pid = GLOB.procs.array[i].pid;
					inf->tprocs[j].pcpu = GLOB.procs.array[i].pcpu;
					inf->tprocs[j].pmem = 0;
					inf->tprocs[j].secrun = 0;
					strncpy (inf->tprocs[j].ptitle, 
							 GLOB.procs.array[i].ptitle, 30);
					inf->tprocs[j].ptitle[31] = 0;
					inserted = 1;
					j = inf->ntop;
				}
			}
			
			/* If no inserts have been done but there's still space, add
			   the entry to the bottom */
			if ((! inserted) && (inf->ntop < 5) && (GLOB.procs.array[i].pcpu))
			{
				j = inf->ntop;
				inf->ntop++;
				
				pwd = getpwuid (GLOB.procs.array[i].uid);
				if (pwd)
				{
					strncpy (inf->tprocs[j].username, pwd->pw_name, 8);
					inf->tprocs[j].username[8] = 0;
				}
				else
				{
					sprintf (inf->tprocs[j].username, "#%d",
							 GLOB.procs.array[i].uid);
				}
				inf->tprocs[j].pid = GLOB.procs.array[i].pid;
				inf->tprocs[j].pcpu = GLOB.procs.array[i].pcpu;
				inf->tprocs[j].pmem = 0;
				inf->tprocs[j].secrun = 0;
				strncpy (inf->tprocs[j].ptitle,
						 GLOB.procs.array[i].ptitle, 30);
				inf->tprocs[j].ptitle[31] = 0;
				inserted = 1;
			}
		}
	}
	procrun_newround (&GLOB.procs);
}

void gather_ports (netload_info *inf)
{
	int lowidx;
	int lowcnt;
	char *buf;
	char *c;
	unsigned int portno;
	unsigned int state;
	int sum;
	int i,j;
	FILE *F;
	size_t len;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct xinpgen *xig, *oxig;
	struct xsocket *so;
	
	if (sysctlbyname ("net.inet.tcp.pcblist", 0, &len, 0, 0) < 0)
	{
		printf ("gather_ports: %s\n", strerror (errno));
		return;
	}
		
	buf = (char *) malloc (len);
	if (! buf) return;
	
	sysctlbyname ("net.inet.tcp.pcblist", buf, &len, 0, 0);

	inf->nports = 0;
	bzero (&GLOB.ports, sizeof (GLOB.ports));

	oxig = xig = (struct xinpgen *) buf;

	for (xig = (struct xinpgen *) (((char *)xig) + xig->xig_len);
		 xig->xig_len > sizeof(struct xinpgen);
		 xig = (struct xinpgen *) (((char *)xig) + xig->xig_len))
	{
		tp = &((struct xtcpcb *)xig)->xt_tp;
		inp = &((struct xtcpcb *)xig)->xt_inp;
		so = &((struct xtcpcb *)xig)->xt_socket;
		if (so->xso_protocol != IPPROTO_TCP) continue;
		if (! inp->inp_fport)
		{
			portno = ntohs (inp->inp_lport);
			if (tp->t_state == TCPS_LISTEN)
			{
				GLOB.ports[portno][0] = 1;
			}
			else if (tp->t_state == TCPS_ESTABLISHED)
			{
				GLOB.ports[portno][1]++;
			}
			else
			{
				GLOB.ports[portno][2]++;
			}
		}
	}

	lowcnt = 65535;
	lowidx = -1;
	
	for (i=0; i<65536; ++i)
	{
		if (GLOB.ports[i][0])
		{
			if (inf->nports < 10)
			{
				#define npthis inf->ports[inf->nports]
				
				npthis.port = i;
				npthis.nestab = GLOB.ports[i][1];
				npthis.nother = GLOB.ports[i][2];
				
				sum = npthis.nestab + npthis.nother;
				
				if (sum < lowcnt)
				{
					lowcnt = sum;
					lowidx = i;
				}
				
				inf->nports++;
				
				#undef npthis
			}
			else
			{
				#define npthis inf->ports[lowidx]
				
				sum = GLOB.ports[i][1]+GLOB.ports[i][2];
				
				if (sum > (npthis.nestab + npthis.nother))
				{
					npthis.port = i;
					npthis.nestab = GLOB.ports[i][1];
					npthis.nother = GLOB.ports[i][2];
					
					lowcnt = 65535;
					for (j=0; j<10; ++j)
					{
						sum = inf->ports[j].nestab + inf->ports[j].nother;
						if ( sum < lowcnt)
						{
							lowcnt = sum;
							lowidx = j;
						}
					}
				}
				
				#undef npthis
			}
		}
	}
	
	free (buf);
}

int cpu_count (void)
{
	char buffer[256];
	FILE *cpuinfo;
	int count = 0;
	
	if (cpuinfo = fopen ("/proc/cpuinfo","r"))
	{
		while (! feof (cpuinfo))
		{
			buffer[0] = 0;
			fgets (buffer, 255, cpuinfo);
			if (strlen (buffer))
			{
				if (strncmp (buffer, "processor", 9) == 0)
				{
					++count;
				}
			}
		}
		fclose (cpuinfo);
	}
	else return 1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_ttys (info)                                               *
 * ---------------------------                                               *
 * Goes over utmp* to check for logged in users and records their tty,       *
 * username and remote host.                                                 *
\* ------------------------------------------------------------------------- */

void gather_ttys (netload_info *inf)
{
	inf->ntty = 0;
	return;
}

/* =========================================================================== *\
 * main (unit test)                                                            *
 * ----------------                                                            *
 * Test code for the statistics gathering. Define UNIT_TEST during compile     *
 * and link to the necessary objects to create a test program.                 *
\* =========================================================================== */

#ifdef UNIT_TEST
int main (int argc, char *argv[])
{
	int i;
	netload_info  inf;
	netload_pkt  *pkt;
	netload_rec  *rec;
	netload_info *dinf;
	
	bzero (&inf, sizeof (inf));
	
	load_config("/etc/netload/client.cf");
	gather_init();
	
	gather_meminfo (&inf);
	gather_netinfo (&inf);
	
	while (1)
	{
		for (i=0; i<3; ++i)
		{
			sample_tprocs (&inf);
			sleep (10);
		}

		gather_hostdat (&inf);
		printf ("--- 1\n");
		gather_load (&inf);
		printf ("--- 2\n");
		gather_meminfo (&inf);
		printf ("--- 3\n");
		gather_netinfo (&inf);
		printf ("--- 4\n");
		gather_mounts (&inf);
		printf ("--- 5\n");
		gather_tprocs (&inf);
		printf ("--- 6\n");
		gather_ports (&inf);

		pkt = encode_pkt (&inf, "this-is-my-key");
		i = validate_pkt (pkt, "this-is-my-key");
		rec = encode_rec (pkt, time (NULL), ST_STARTUP_1, 1, 1, 0);

		dinf = decode_rec (rec);
		if (! dinf)
		{
			fprintf (stderr, "WTF couldn't decode\n");
			sleep (60);
		}
		pool_free (rec);

		print_info (dinf, 0);
		pool_free (dinf);
	}
}
#endif
