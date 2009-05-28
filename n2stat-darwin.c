#include "n2stat.h"
#include "n2config.h"
#include "n2args.h"
#include "n2encoding.h"
#include "tproc.h"
#include "datatypes.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <kvm.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/vmmeter.h>
#include <sys/resource.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/errno.h>

/* --------------------------------------------------------------------------- *\
 * Internal datatypes                                                          *
\* --------------------------------------------------------------------------- */

typedef struct
{
	time_t				lastrun;
	unsigned long long	net_in;
	unsigned long long	net_out;
	unsigned short 		ports[65536][3];
	procrun				procs;
} darwingather_global;

darwingather_global GLOB;

portlist *getports (void)
{
	return &GLOB.ports;
}

procrun *getprocs (void)
{
	return &GLOB.procs;
}

/* --------------------------------------------------------------------------- *\
 * Internal globals                                                            *
\* --------------------------------------------------------------------------- */

int KMEMTOTAL;

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
	inf->ostype = MY_OSTYPE;
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
	struct vmtotal	 vmt;
	int				 mib[2];
	size_t			 len;
	
	mib[0] = CTL_HW;
	mib[1] = HW_PHYSMEM;
	len = sizeof (size_t);
	sysctl ((int *) mib, 2, &physmem, &len, NULL, 0);
	
	mib[0] = CTL_VM;
	mib[1] = VM_METER;
	len = sizeof (struct vmtotal);
	sysctl (mib, 2, &vmt, &len, NULL, 0);
	
	physmem = physmem >> 10;
	KMEMTOTAL = inf->kmemfree = physmem - (vmt.t_rm >> 10);
	inf->kswapfree = (vmt.t_vm >> 10) - (vmt.t_avm >> 10);
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

	if (sysctl (mib_net, 6, NULL, &needed, NULL, 0) < 0);
	buf = (char *) malloc (needed);
	alloc = needed;
	if (! buf) return;
	
	if (sysctl (mib_net, 6, buf, &needed, NULL, 0) < 0)
		return;
		
	lim = buf + needed;
	next = buf;
	while (next < lim)
	{
		ifm = (struct if_msghdr *) next;
		if (ifm->ifm_type != RTM_IFINFO)
			return;
		
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
			sdl = (struct sockaddr_dl *) ifm+1;
			if (sdl->sdl_family != AF_LINK) continue;
		
			totalin += ifm->ifm_data.ifi_ibytes;
			totalout += ifm->ifm_data.ifi_obytes;
		}
	}
	free (buf);
	
	if (GLOB.net_in)
	{
		diffin = totalin - GLOB.net_in;
		if (diffin < 0) diffin = totalin;
		diffout = totalout - GLOB.net_out;
		if (diffout < 0) diffout = totalout;
		
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
			gather_mounts_getmount (stbuf[i].f_fstypename,
									stbuf[i].f_mntonname,
									(1000L * stbuf[i].f_blocks) / stbuf[i].f_bavail,
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
	
	length = 0;
	
	kvm = kvm_open (NULL, NULL, NULL, O_RDONLY, "n2stat");
	if (kvm)
	{
		result = kvm_getprocs (kvm, KERN_PROC_ALL, 0, &length);
		if (result)
		{
			count = length;
			printf ("%i processes\n", count);
			for (i=0; i < count; ++i)
			{
				#define KP result[i].kp_proc
			
				strncpy (procnam, KP.p_comm, 23);
				procnam[23] = 0;
				
				printf ("%i %s %lli %lli\n", i, procnam,
						KP.p_uticks, KP.p_sticks + KP.p_iticks);
			
				procrun_setproc (&GLOB.procs, result[i].kp_proc.p_pid,
								 KP.p_uticks,
								 KP.p_sticks + KP.p_iticks,
								 result[i].kp_eproc.e_pcred.p_ruid,
								 result[i].kp_eproc.e_pcred.p_rgid,
								 procnam,
								 (result[i].kp_eproc.e_xrssize*40000)/KMEMTOTAL
								 );
								 
				#undef KP
			}
		}
		else
		{
			printf ("foobar1 %s\n", strerror (errno));
		}
		kvm_close (kvm);
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
	struct xinpgen *xig, *oxig;
	
	if (sysctlbyname ("net.inet.tcp.pcblist", 0, &len, 0, 0) < 0)
		return;
		
	buf = (char *) malloc (len);
	if (! buf) return;
	
	sysctlbyname ("net.inet.tcp.pcblist", buf, &len, 0, 0);

	// Now I should start doing useful things, but I'm tired.
	return;
	
	inf->nports = 0;
	bzero (&GLOB.ports, sizeof (GLOB.ports));

	F = fopen ("/proc/net/tcp", "r");
	if (F)
	{
		while (!feof (F))
		{
			*buf = 0;
			fgets (buf, 255, F);
			if (*buf)
			{
				c = buf+15;
				sscanf (c, "%04x", &portno);
				
				c = buf+34;
				sscanf (c, "%02x", &state);
				
				if (state == 10)
				{
					GLOB.ports[portno][0] = 1;
				}
				else if (GLOB.ports[portno][0])
				{
					if (state == 1)
					{
						GLOB.ports[portno][1]++;
					}
					else
					{
						GLOB.ports[portno][2]++;
					}
				}
			}
		}
		fclose (F);
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
	
	load_config("/etc/netload/client.cf");
	gather_init();
	
	gather_netinfo (&inf);
	
	while (1)
	{
		for (i=0; i<3; ++i)
		{
			sample_tprocs (&inf);
			sleep (10);
		}

		gather_hostdat (&inf);
		gather_load (&inf);
		gather_meminfo (&inf);
		gather_netinfo (&inf);
		gather_mounts (&inf);
		gather_tprocs (&inf);
		gather_ports (&inf);

		pkt = encode_pkt (&inf, "this-is-my-key");
		i = validate_pkt (pkt, "this-is-my-key");
		rec = encode_rec (pkt, time (NULL), ST_STARTUP_1, 1, 1, 0);

		dinf = decode_rec (rec);
		free (rec);

		print_info (dinf, 0);
		free (dinf);
	}
}
#endif
