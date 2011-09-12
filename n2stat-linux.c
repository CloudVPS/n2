#include "n2stat.h"
#include "n2config.h"
#include "n2args.h"
#include "n2encoding.h"
#include "tproc.h"
#include "datatypes.h"
#include "n2malloc.h"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <utmp.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <sys/mount.h>
#include <fcntl.h>

#ifdef DEBUG
  #define dprintf printf
#else
  #define dprintf //
#endif

/* ------------------------------------------------------------------------- *\
 * Internal datatypes                                                        *
\* ------------------------------------------------------------------------- */
typedef struct
{
	time_t				lastrun;
	unsigned long long  total_cpu;
	unsigned long long	net_in;
	unsigned long long	net_out;
	unsigned long long	io_blk;
	unsigned long long  io_wait;
	unsigned short 		ports[65536][3];
	procrun				procs;
} linuxgather_global;

static const char *afterlast (const char *in, char match)
{
	const char *res = in;
	const char *t;

	while (t = strchr (res, match)) res = t+1;
	return res;
}

/* ------------------------------------------------------------------------- *\
 * Internal globals                                                          *
\* ------------------------------------------------------------------------- */
linuxgather_global GLOB;
int KMEMTOTAL;

portlist *getports (void)
{
	return &GLOB.ports;
}

procrun *getprocs (void)
{
	return &GLOB.procs;
}

/* ------------------------------------------------------------------------- *\
 * Internal function prototypes                                              *
\* ------------------------------------------------------------------------- */
int volume_promille_used (const char *);
void gather_mounts_getmount (n2arglist *, netload_info *, unsigned short *, int *);

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_init (void)                                               *
 * ---------------------------                                               *
 * Initializes globals.                                                      *
\* ------------------------------------------------------------------------- */
void gather_init (void)
{
	FILE *F;
	char buf[256];
	GLOB.net_in = 0;
	GLOB.net_out = 0;
	GLOB.io_blk = 0;
	GLOB.io_wait = 0;
	GLOB.total_cpu = 0;
	GLOB.lastrun = time (NULL);
	
	procrun_init (&GLOB.procs);
	GLOB.procs.ncpu = 0;
	F = fopen ("/proc/cpuinfo","r");
	if (F)
	{
		while (! feof (F))
		{
			buf[0] = 0;
			fgets (buf, 255, F);
			if (strncmp (buf, "processor", 9) == 0)
			{
				GLOB.procs.ncpu++;
			}
		}
		fclose (F);
	}
	else
	{
		GLOB.procs.ncpu = 1;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_io (info)                                                 *
\* ------------------------------------------------------------------------- */
void gather_io (netload_info *inf)
{
	n2arglist *split;
	FILE *F;
	time_t ti;
	char buf[256];
	unsigned long long totalblk = 0;
	unsigned long long delta;
	unsigned long long cpudelta;
	unsigned long long totalcpu;
	unsigned long long totalwait = 0;
	
	F = fopen ("/proc/diskstats", "r");
	if (F)
	{
		while (! feof (F))
		{
			buf[0] = 0;
			fgets (buf, 255, F);
			if (! strlen (buf)) continue;
			
			split = make_args (buf);
			if (split->argc < 14)
			{
				destroy_args (split);
				continue;
			}
			
			totalblk += atoll (split->argv[5]);
			totalblk += atoll (split->argv[9]);
			
			destroy_args (split);
		}
		
		fclose (F);
	}
	else
	{
		F = fopen ("/proc/partitions", "r");
		if (F)
		{
			while (! feof (F))
			{
				buf[0] = 0;
				fgets (buf, 255, F);
				if (! strlen (buf)) continue;
				if (strchr (buf, '#') != NULL) continue;
				
				split = make_args (buf);
				if (split->argc < 15)
				{
					destroy_args (split);
					continue;
				}
				
				totalblk += atoll (split->argv[6]);
				totalblk += atoll (split->argv[10]);
				
				destroy_args (split);
			}
			
			fclose (F);
		}
	}

	F = fopen ("/proc/stat","r");
	if (F)
	{
		fgets (buf, 255, F);
		split = make_args (buf);
		totalwait = atoll (split->argv[5]);
		totalcpu = atoll (split->argv[1]) + atoll (split->argv[2]) +
				   atoll (split->argv[3]) + atoll (split->argv[4]);
		destroy_args (split);
		fclose (F);
	}
	
	delta = totalblk - GLOB.io_blk;
	
	ti = time (NULL);
	if (ti == GLOB.lastrun) GLOB.lastrun--;
	if (GLOB.io_blk)
	{
		inf->diskio = delta / (ti - GLOB.lastrun);
	}
	else
	{
		inf->diskio = 0;
	}

	delta = totalwait - GLOB.io_wait;
	cpudelta = totalcpu - GLOB.total_cpu;

	if (GLOB.io_wait)
	{
		/* delta is in 100Hz ticks, so this works out */
		inf->iowait = (100*delta) / cpudelta;
		if (inf->iowait > 100) inf->iowait = 100;
	}

	GLOB.io_blk = totalblk;
	GLOB.io_wait = totalwait;
	GLOB.total_cpu = totalcpu;
	GLOB.lastrun = ti;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_hostdat                                                   *
 * -----------------------                                                   *
 * Fill in host operating system data.                                       *
\* ------------------------------------------------------------------------- */
void gather_hostdat (netload_info *inf)
{
	FILE *F;
	char  buf[256];
  struct utsname unamebuf;
	
	strncpy (inf->hostname, CONF.hostname, 31);
	inf->hostname[31] = 0;
	inf->hosttime = time (NULL);
	inf->ostype = MY_OSTYPE;
	
	uname(&unamebuf);
	inf->hwtype = HW_OTHER;
	if (!strcmp(unamebuf.machine, "i386") || !strcmp(unamebuf.machine, "i686"))
	{
	    inf->hwtype = HW_IA32;
	}
 	else if (!strcmp(unamebuf.machine, "x86_64"))
 	{
		inf->hwtype = HW_IA64;
    }
  	else if (!strcmp(unamebuf.machine, "mips"))
  	{
    	inf->hwtype = HW_MIPS;
    }
	
	F = fopen ("/proc/uptime", "r");
	if (F)
	{
		fgets (buf, 255, F);
		fclose (F);
		
		inf->uptime = atoi (buf);
	}
	else
	{
		inf->uptime = 0;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_load (info)                                               *
 * ---------------------------                                               *
 * Fill in the loadaverage data.                                             *
\* ------------------------------------------------------------------------- */
void gather_load (netload_info *inf)
{
	FILE 		*F;
	char 		 buf[256];
	n2arglist	*arg;
	char		*slash;
	double		 td;
	
	
	F = fopen ("/proc/loadavg", "r");
	if (F)
	{
		fgets (buf, 255, F);
		fclose (F);
		
		arg = make_args (buf);
		
		td = atof (arg->argv[0]);
		inf->load1 = (int) (td * (double) 100);
		
		inf->nrun = atoi (arg->argv[3]);
		
		slash = strchr (arg->argv[3], '/');
		if (slash)
		{
			inf->nproc = atoi (slash+1);
		}
		
		destroy_args (arg);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_meminfo (info)                                            *
 * ------------------------------                                            *
 * Fill in memory/swap usage                                                 *
\* ------------------------------------------------------------------------- */
void gather_meminfo (netload_info *inf)
{
	FILE 		*F;
	char 		 buf[256];
	
	F = fopen ("/proc/meminfo", "r");
	if (F)
	{
		while (! feof (F))
		{
			*buf = 0;
			fgets (buf, 255, F);
			
			if (strncmp (buf, "MemTotal:", 9) == 0)
			{
				inf->kmemtotal = KMEMTOTAL = atoi (buf+9);
			}
			else if (strncmp (buf, "MemFree:", 8) == 0)
			{
				inf->kmemfree = atoi (buf+8);
			}
			else if (strncmp (buf, "Buffers:", 8) == 0)
			{
				inf->kmemfree += atoi (buf+8);
			}
			else if (strncmp (buf, "Cached:", 7) == 0)
			{
				inf->kmemfree += atoi (buf+7);
			}
			else if (strncmp (buf, "SwapFree:", 9) == 0)
			{
				inf->kswapfree = atoi (buf+9);
			}
		}
		fclose (F);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_netinfo (info)                                            *
 * ------------------------------                                            *
 * Set network interface statistics                                          *
\* ------------------------------------------------------------------------- */
void gather_netinfo (netload_info *inf)
{
	FILE				*F;
	char				 buf[256];
	unsigned long long	 totalin;
	unsigned long long	 totalout;
	long long			 diffin;
	long long			 diffout;
	n2arglist			*args;
	char				*colon;
	time_t				 ti;

	totalin = 0;
	totalout = 0;
	
	F = fopen ("/proc/net/dev", "r");
	if (F)
	{
		fgets (buf, 255, F);
		while (! feof (F))
		{
			*buf = 0;
			fgets (buf, 255, F);
			if ((*buf) && (colon = strchr (buf, ':')))
			{
				*colon = '\0';
				colon++;
				args = make_args (colon);
				
				colon = buf;
				while (isspace (*colon)) colon++;
				if (! interface_configured (colon))
				{
					destroy_args (args);
					continue;
				}
				
				totalin = totalin + (atoll (args->argv[0]) >> 7);
				totalout = totalout + (atoll (args->argv[8]) >> 7);
				destroy_args (args);
			}
		}
		fclose (F);
		ti = time (NULL);
		if (ti == GLOB.lastrun) GLOB.lastrun--;
		
		if (GLOB.net_in)
		{
			diffin = totalin - GLOB.net_in;
			if (diffin < 0) diffin = 0;
			diffout = totalout - GLOB.net_out;
			if (diffout < 0) diffout = 0;
			
			inf->netin = (unsigned int) ((diffin / (ti - GLOB.lastrun)) & 0x7fffffff);
			inf->netout = (unsigned int) ((diffout / (ti - GLOB.lastrun)) & 0x7fffffff);

			#define DELTAT (ti - GLOB.lastrun)
			GLOB.net_in = totalin;
			GLOB.net_out = totalout;
		}
		else
		{
			GLOB.net_in = totalin;
			GLOB.net_out = totalout;
		}
	}
	else
	{
	}
}

/*int diskdevice_size_in_gb (const char *devname)
{
	unsigned long long bytes = 0;
	int fd;

	fd = open (devname, O_RDONLY);
	if (fd<0) return 0;

	ioctl(fd, BLKGETSIZE64, &bytes);
	close (fd);
	return (bytes >> 30);
}*/

int diskdevice_size_in_gb (const char *devname)
{
	struct stat 		 st;
	n2arglist 			*args;
	int         		 iminor, imajor;
	FILE 				*F;
	char        		 buf[256];
	unsigned long long 	 sizebytes;

	if (stat (devname, &st)) return 0;
	iminor = minor (st.st_rdev);
	imajor = major (st.st_rdev);

	F = fopen ("/proc/partitions","r");
	if (!F) return 0;

	while (! feof (F))
	{
		fgets (buf, 255, F);
		buf[255] = 0;
		if (*buf) buf[strlen(buf)-1] = 0;
		if (! (*buf)) continue;

		args = make_args (buf);
		if (args->argc < 3)
		{
			destroy_args (args);
			continue;
		}

		if (imajor == atoi (args->argv[0]))
		{
			if (iminor == atoi (args->argv[1]))
			{
				sizebytes = atoll (args->argv[2]);
				destroy_args (args);
				return sizebytes/(1024*1024);
			}
		}
		destroy_args (args);
	}
	fclose (F);
	return 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION volume_promille_used                                             *
 * -----------------------------                                             *
 * A utility function that safely gets the usage information out of a        *
 * mounted volume, with a timeout for the eventuality that the mount 'hangs' *
 * Returns a number from 0 to 1000 depicting the 0.1% step usage of the      *
 * volume's filesystem. 1001 indicates an error condition.                   *
\* ------------------------------------------------------------------------- */
int volume_promille_used (const char *volume)
{
	struct statfs	sfs;
	int				retval;
	int				resval;
	struct timeval	tv;
	pid_t			cpid;
	pid_t			rpid;
	
	retval = 250;
	resval = 1001;
	
	/* Fork a background process to softly poke VFS */
	switch ((cpid = fork()))
	{
		case -1:
			/* uh oh */
			return 1001;
		
		case 0:
			/* ANALPROBE Mk2 launched */
			if (statfs (volume, &sfs) == 0)
			{
				retval = ((((unsigned long long)(sfs.f_blocks - sfs.f_bfree))*249) / (unsigned long long) (sfs.f_blocks+1));
				exit (retval);
			}
			exit ((int) 250); /* Unlikely failure but hey */
		
		default:
			break;
	}
	
	tv.tv_sec = 0;
	tv.tv_usec = 50000;
	
	/* Wait for a little bit */
	select (0, NULL, NULL, NULL, &tv);
	
	/* Collect the exit value if the child is done */
	rpid = waitpid (cpid, &retval, WNOHANG);
	if (rpid)
	{
		if (WIFEXITED(retval))
		{
			resval = WEXITSTATUS(retval);
			if (resval == 250) resval=1001;
			else resval *= 4;
		}
	}
	else /* It seems it wasn't quite done */
	{
		retval = 250;
		/* Grant it two more seconds */
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		select (0, NULL, NULL, NULL, &tv);
		rpid = waitpid (cpid, &retval, WNOHANG);
		if (rpid)
		{
			if (WIFEXITED(retval))
			{
				resval = WEXITSTATUS(retval);
				if (resval == 250) resval=1001;
				else resval *= 4;
			}
		}
		else /* Still no juice? */
		{
			resval = 1001;
			/* Give it a mercy shot */
			kill (cpid, 9);
			
			/* Collect the damage */
			rpid = waitpid (cpid, NULL, WNOHANG);
		}
	}
	
	waitpid (-1, NULL, WNOHANG);
	return resval;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_mounts (info)                                             *
 * -----------------------------                                             *
 * Get a list of mounts out of /proc/mtab and fill in the 4 most             *
 * heavily used volumes to return into the netload_info structure.           *
\* ------------------------------------------------------------------------- */
void gather_mounts (netload_info *inf)
{
	FILE			*F;
	char			 buf[256];
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
	
	lowusage = 1001;
	
	
	inf->nmounts = 0;
	
	F = fopen ("/proc/mounts", "r");
	if (F)
	{
		while (!feof (F))
		{
			*buf = 0;
			fgets (buf, 255, F);
			if (*buf)
			{
				args = make_args (buf);
				if (args->argc > 3)
				{
					/* only rw volumes */
					if ((! strncmp (args->argv[3], "rw", 2)) &&
					    (strcmp (args->argv[2], "rootfs")) &&
					    (strcmp (args->argv[2], "proc")) &&
					    (strcmp (args->argv[2], "usbdevfs")) &&
					    (strcmp (args->argv[2], "devfs")) &&
					    (strcmp (args->argv[2], "tmpfs")) &&
					    (strcmp (args->argv[2], "usbfs")) &&
					    (strcmp (args->argv[2], "autofs")) &&
					    (strncmp (args->argv[2], "nfs", 3)) &&
					    (strncmp (args->argv[2], "sys", 3)) &&
					    (strcmp (args->argv[2], "devpts")) &&
					    (strncmp (args->argv[2], "binfmt_", 7)) &&
					    (strncmp (args->argv[2], "rpc_", 4)) &&
					    (strcmp (args->argv[0], "none")) &&
					    (strncmp (args->argv[1], "/sys", 4)) &&
					    (strncmp (args->argv[1], "/proc", 5)))
					{
						gather_mounts_getmount (args, inf, &lowusage,
												&lowusageidx);
					}
				}
				destroy_args (args);
			}
		}
		fclose (F);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_mounts_getmount (args, info, lowusage, lowidx)            *
 * --------------------------------------------------------------            *
 * Checks out a specific mount (with an n2arglist containing the fields      *
 * as they came out of the /proc entry) and adds it into the info            *
 * structure if it has more priority than sitting entries or if there        *
 * is still an entry free.                                                   *
\* ------------------------------------------------------------------------- */
void gather_mounts_getmount (n2arglist *args, netload_info *inf,
							 unsigned short *lowusage, int *lowusageidx)
{
	const char *origindevice;
	const char *mountpoint;
	const char *fstype;
	int i;
	unsigned short usage;
	int sizegb;
	int	nmounts;

	fstype = args->argv[2];
	if (strcmp (fstype, "proc") &&
		strncmp (fstype, "dev", 3)) /* not procfs or devfsen */
	{
		origindevice = args->argv[0];
		mountpoint = args->argv[1];
		sizegb = diskdevice_size_in_gb (origindevice);
		usage = volume_promille_used (mountpoint);
		if (usage == 1001) return;
		
		nmounts = inf->nmounts;
		for (i=0; i<nmounts; ++i)
		{
			if (! strcmp (inf->mounts[i].device, origindevice)) return;
		}

		if (nmounts < 4)
		{
			#define tmnt inf->mounts[nmounts]
			strncpy (tmnt.mountpoint, mountpoint, 47);
			tmnt.mountpoint[47] = 0;
			
			strncpy (tmnt.device, origindevice, 63);
			tmnt.device[63] = 0;
			
			strncpy (tmnt.fstype, fstype, 11);
			tmnt.fstype[11] = 0;
			
			tmnt.usage = usage;
			tmnt.size = sizegb;

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
				
				strncpy (tmnt.mountpoint, mountpoint, 47);
				tmnt.mountpoint[47] = 0;
				
				strncpy (tmnt.device, origindevice, 63);
				tmnt.device[63] = 0;
			
				strncpy (tmnt.fstype, fstype, 11);
				tmnt.fstype[11] = 0;
				
				tmnt.usage = usage;
				tmnt.size = sizegb;

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

/* ------------------------------------------------------------------------- *\
 * FUNCTION sample_tprocs (info)                                             *
 * -----------------------------                                             *
 * Does a single sample run of the processes found inside /proc and tracks   *
 * their usage.                                                              *
\* ------------------------------------------------------------------------- */
void sample_tprocs (netload_info *inf)
{
	struct dirent	*de;
	DIR				*D;
	FILE			*F;
	pid_t			 pid;
	unsigned long	 utime;
	unsigned long	 stime;
	uid_t			 tuid;
	gid_t			 tgid;
	struct stat		 st;
	char			 buf[256];
	char			*c;
	n2arglist		*args;
	struct timeval	 tv;
	int				 pausetimer;
	long long		 rss;
	long long		 tpmem;
	int				 pmem;
	
	procrun_initsample (&GLOB.procs);
	D = opendir ("/proc");
	if (!D) return;
	pausetimer = 0;
	
	while ( (de = readdir (D)) )
	{
		pid = atoi (de->d_name);
		pausetimer++;
		if (pausetimer & 15)
		{
			tv.tv_sec = 0;
			tv.tv_usec = 64;
			select (0, NULL, NULL, NULL, &tv);
		}
		if (pid>0)
		{
			sprintf (buf, "/proc/%d", pid);
		
			if (stat (buf, &st) == 0)
			{
				tuid = st.st_uid;
				tgid = st.st_gid;
			}
			else
			{
				tuid = 0;
				tgid = 0;
			}
			sprintf (buf, "/proc/%d/stat", pid);
			
			if ( (stat(buf, &st) == 0) && (F = fopen (buf, "r")) )
			{
				fgets (buf, 255, F);
				buf[255] = 0;
				
				c = buf;
				while (strchr (c, ')'))
					c = strchr (c, ')') + 1;
					
				/* 11=u 12=s */
				args = make_args (c);
				if (args->argc > 12)
				{
					utime = atol (args->argv[11]);
					stime = atol (args->argv[12]);
				}
				fclose (F);
				destroy_args (args);

				sprintf (buf, "/proc/%d/statm", pid);
				if ((F = fopen (buf, "r")))
				{
					memset (buf, 0, 255);
					fgets (buf, 255, F);
					c = strchr (buf, ' ');
					if (c)
					{
						++c;
						rss = 4 * atoll (c);
						
						tpmem = rss;
						tpmem *= 10000;
						tpmem /= KMEMTOTAL;
						pmem = (int) (tpmem & 0xffffffff);
					}
					fclose (F);
				}
				else
				{
					rss = 128000;
				}
				
				sprintf (buf, "/proc/%d/cmdline", pid);
				if ((F = fopen (buf, "r")))
				{
					memset (buf, 0, 255);
					fread (buf, 0, 255, F);
					fclose (F);
					
					if (*buf == 0)
					{
						sprintf (buf, "/proc/%d/status", pid);
						if ((F = fopen (buf, "r")))
						{
							memset (buf, 0, 255);
							fgets (buf, 255, F);
							c = strchr (buf, ':');
							if (! c)
							{
								fclose (F);
								continue;
							}
							++c;
							while (*c <= ' ') ++c;
							if (strlen (c))
							{
								c[strlen(c)-1] = 0;
							}
							
							fclose (F);
							
							procrun_setproc (&GLOB.procs, pid, utime, stime,
											 tuid, tgid, c, pmem);
						}
					}
					else
					{
						procrun_setproc (&GLOB.procs, pid, utime, stime,
										 tuid, tgid, buf, pmem);
					}
				}
			}
		}
	}
	closedir (D);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION make_top_hole (info, position)                                   *
 * ---------------------------------------                                   *
 * Internal subroutine to insert a top entry into a specific slot of the     *
 * tprocs array, moving other entries to the bottom.                         *
\* ------------------------------------------------------------------------- */
void make_top_hole (netload_info *inf, int pos)
{
	int tailsz;
	
	if (pos>(MAX_NTOP-2)) return;
	tailsz = ((MAX_NTOP-1) - pos);
	
	memmove (inf->tprocs + pos + 1,
			 inf->tprocs + pos,
			 tailsz * sizeof (netload_topentry));
	
	if (inf->ntop < MAX_NTOP) ++inf->ntop;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_tprocs                                                    *
 * ----------------------                                                    *
 * Gathers the statistics from the tproc sample rounds and puts them into    *
 * the netload_info structure.                                               *
\* ------------------------------------------------------------------------- */
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
				if (((3*inf->tprocs[j].pcpu) + (inf->tprocs[j].pmem/2)) <
					((3*GLOB.procs.array[i].pcpu) + (GLOB.procs.array[i].pmem/2)))
				{
					// Skip if only memory is visible and < 5%
					if ((GLOB.procs.array[i].pcpu == 0) &&
					    (GLOB.procs.array[i].pmem < 501)) continue;
					    
					make_top_hole (inf, j);
					pwd = getpwuid (GLOB.procs.array[i].uid);
					if (pwd)
					{
						strncpy (inf->tprocs[j].username, pwd->pw_name, 15);
						inf->tprocs[j].username[15] = 0;
					}
					else
					{
						sprintf (inf->tprocs[j].username, "#%d",
								 GLOB.procs.array[i].uid);
					}
					inf->tprocs[j].pid = GLOB.procs.array[i].pid;
					inf->tprocs[j].pcpu = GLOB.procs.array[i].pcpu;
					inf->tprocs[j].pmem = GLOB.procs.array[i].pmem;
					inf->tprocs[j].secrun = 0;
					strncpy (inf->tprocs[j].ptitle, 
							 GLOB.procs.array[i].ptitle, 47);
					inf->tprocs[j].ptitle[47] = 0;
					inserted = 1;
					j = inf->ntop;
				}
			}
			
			/* If no inserts have been done but there's still space, add
			   the entry to the bottom */
			if ((! inserted) && (inf->ntop < (MAX_NTOP-2)) &&
				(GLOB.procs.array[i].pcpu || (GLOB.procs.array[i].pmem > 500)))
			{
				dprintf ("insert pcpu=%i pmem=%i\n", GLOB.procs.array[i].pcpu, GLOB.procs.array[i].pmem);
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
				inf->tprocs[j].pmem = GLOB.procs.array[i].pmem;
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

/* ------------------------------------------------------------------------- *\
 * FUNCTION gather_ports (info)                                              *
 * ----------------------------                                              *
 * Gets statistics of open tcp ports and their open/halfopen/closed          *
 * connection counts.                                                        *
\* ------------------------------------------------------------------------- */
void gather_ports (netload_info *inf)
{
	int lowidx;
	int lowcnt;
	char buf[256];
	char *c;
	unsigned int portno = 0;
	unsigned int state = 0;
	int sum;
	int i,j;
	FILE *F;
	
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
	F = fopen ("/proc/net/tcp6", "r");
	if (F)
	{
		while (!feof (F))
		{
			*buf = 0;
			fgets (buf, 255, F);
			if (*buf)
			{
				c = buf+0x27;
				sscanf (c, "%04x", &portno);
				
				c = buf+0x52;
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
			dprintf ("Evaluating port %i\n", i);
			for (j=0; j<10; ++j)
			{
				dprintf ("Position %i\n", j);
				#define npthis inf->ports[j]
				if (j>= inf->nports)
				{
					dprintf ("Last position, add\n");
					npthis.port = i;
					npthis.nestab = GLOB.ports[i][1];
					npthis.nother = GLOB.ports[i][2];
					inf->nports = j+1;
					break;
				}
				
				sum = npthis.nestab + npthis.nother;
				if (sum < GLOB.ports[i][1]+GLOB.ports[i][2])
				{
					dprintf ("sum higher\n");
					if (j<9)
					{
						dprintf ("move\n");
						memmove (inf->ports+j+1, inf->ports+j,
								 (9-j) * sizeof (short[3]));
					}
					npthis.port = i;
					npthis.nestab = GLOB.ports[i][1];
					npthis.nother = GLOB.ports[i][2];
					break;
				}
			}
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION cpu_count (void)                                                 *
 * -------------------------                                                 *
 * Returns the number of CPUs in the system.                                 *
\* ------------------------------------------------------------------------- */
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
	struct utmp *ut;
	int c;
	
	inf->ntty = 0;
	setutent();
	while ((inf->ntty < 10) && (ut = getutent()))
	{
		c = inf->ntty;
		if ((ut->ut_type == USER_PROCESS) && (ut->ut_addr))
		{
			strncpy (inf->ttys[c].line, ut->ut_line, 8);
			inf->ttys[c].line[7] = 0;
			strncpy (inf->ttys[c].username, ut->ut_user, 12);
			inf->ttys[c].username[11] = 0;
			inf->ttys[c].host = htonl (ut->ut_addr);
			inf->ntty++;
		}
	}
	endutent();
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION main (unit test)                                                 *
 * -------------------------                                                 *
 * Test code for the statistics gathering. #DEFINE UNIT_TEST during compile  *
 * and link to the necessary objects to create a test program.               *
\* ------------------------------------------------------------------------- */
#ifdef UNIT_TEST
int main (int argc, char *argv[])
{
	int i, ii;
	netload_info  inf;
	netload_pkt  *pkt;
	netload_rec  *rec;
	netload_info *dinf;
	
	pool_init ();
	
	load_config("/etc/netload/client.cf");
	gather_init();
	init_netload_info (&inf);
	
	gather_netinfo (&inf);
	gather_meminfo (&inf);

	gather_mounts (&inf);
	
	for (ii=0; ii<4; ++ii)
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
		gather_io (&inf);
		gather_mounts (&inf);
		gather_tprocs (&inf);
		gather_ports (&inf);
		gather_ttys (&inf);

		/*print_info (&inf, 0x7f000001);*/

		pkt = encode_pkt (&inf, "this-is-my-key");
		i = open ("packet.out", O_RDWR|O_CREAT);
		write (i, pkt, pkt->pos);
		close (i);

		i = validate_pkt (pkt, "this-is-my-key");
		rec = encode_rec (pkt, time (NULL), ST_STARTUP_1, 1, 0, 0);

		dinf = decode_rec (rec);
		pool_free (rec);

		print_info (dinf, 0x7f000001);
		pool_free (dinf);
	}
	free (GLOB.procs.array);
	return 0;
}

int interface_configured (const char *ifname)
{
	return 1;
}

#endif
