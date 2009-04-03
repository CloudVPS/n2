#ifndef _DATATYPES_H
#define _DATATYPES_H 1

#include <sys/types.h>

/* ------------------------------------------------------------------------- *\
 * Enumeration types                                                         *
\* ------------------------------------------------------------------------- */

enum
{
	OS_LINUX,	/* 0 */
	OS_BSD,
	OS_SOLARIS,
	OS_IRIX,
	OS_AIX,
	OS_HPUX,
	OS_X,
	OS_WINDOWS,
	OS_OTHER	/* 8 */
};

typedef char ostype_t;

enum
{
	HW_IA32,	/* 0 */
	HW_IA64,
	HW_PPC,
	HW_MIPS,
	HW_SPARC,
	HW_ALPHA,
	HW_PARISC,
	HW_OTHER	/* 7 */
};
typedef char hwtype_t;

enum
{
	ST_UNSET,		/* 0 */
	ST_STARTUP_1,	
	ST_STARTUP_2,
	ST_STARTUP_3,
	ST_STARTUP_4,
	ST_STARTUP_5,
	ST_STARTUP_6,
	ST_STARTUP_7,
	ST_STARTUP_8,
	ST_STARTUP_9,
	ST_OK,
	ST_WARNING,
	ST_ALERT,
	ST_CRITICAL,	/* 13 */
	ST_STALE,		/* 14 */
	ST_DEAD			/* 15 */
};

enum /* bit-offset of relevant flags */
{
	FLAG_RTT = 0,
	FLAG_LOSS = 1,
	FLAG_LOAD = 2,
	FLAG_OTHER = 3
};

typedef char status_t;

enum /* bit-offsets of oflags when matching FLAG_OTHER */
{
	OFLAG_RAM = 0,
	OFLAG_SWAP = 1,
	OFLAG_NETIN = 2,
	OFLAG_NETOUT = 3,
	OFLAG_SVCDOWN = 4,
	OFLAG_DISKIO = 5
};

typedef unsigned int oflag_t;

extern const char *STR_STATUSFLAGS[];

#define MKSTATUS(pval,pstat) ((pval & 0xf0)|(pstat & 0x0f))
#define RDSTATUS(pval) (pval & 0x0f)
#define SETSTATUSFLAG(pval,bit) (pval = (pval | (1 << ((bit&3)+4))))
#define CLRSTATUSFLAG(pval,bit) (pval = (pval & (0xff ^ (1 << ((bit&3)+4)))))
#define CHKSTATUSFLAG(pval,bit) ( (pval & (1 << ((bit&3)+4))) ? 1 : 0 )
#define FLAGTEXT(pval) (STR_STATUSFLAGS[(pval & 0xf0) >> 4])
#define INCSTATUS(pval) ( ((pval & 0x0f)+1) | (pval & 0xf0) )
#define DECSTATUS(pval) ( ((pval & 0x0f)-1) | (pval & 0xf0) )
#define SETOFLAG(oval,bit) (oval |= 1 << bit)
#define CLROFLAG(oval,bit) (oval = oval & (0xffffffff ^ (1 << bit)))
#define CHKOFLAG(oval,bit) ((oval & (1 << bit)) >> bit)

enum
{
	SVC_NETLOAD 	= 0x00000001,
	SVC_SSH 		= 0x00000002,
	SVC_HTTP 		= 0x00000004,
	SVC_SNMP		= 0x00000008,
	SVC_SMTP		= 0x00000010,
	SVC_IMAP		= 0x00000020,
	SVC_POP3		= 0x00000040,
	SVC_FTP			= 0x00000080,
	SVC_NNTP		= 0x00000100,
	SVC_CRON		= 0x00000200,
	SVC_HTTPADMIN	= 0x00000400,
	SVC_SQLDB		= 0x00000800,
	SVC_NFS			= 0x00001000,
	SVC_CIFS		= 0x00002000,
	SVC_ATALK       = 0x00004000,
	SVC_DNS         = 0x00008000,
	SVC_LDAP		= 0x00010000,
	SVC_SPAMD		= 0x00020000,
	SVC_ROUTING		= 0x00040000,
	SVC_INETD		= 0x00080000,
	SVC_DHCP		= 0x00100000,
	SVC_FIREWALL	= 0x00200000,
	SVC_SYSLOG		= 0x00400000,
	SVC_PRINTER		= 0x00800000,
	SVC_VM			= 0x01000000,
	SVC_USER1		= 0x02000000,
	SVC_USER2		= 0x04000000,
	SVC_USER3		= 0x08000000,
	SVC_USER4		= 0x10000000,
	SVC_USER5		= 0x20000000,
	SVC_USER6		= 0x40000000,
	SVC_USER7		= 0x80000000
};
typedef unsigned int svcflags_t;

/* ------------------------------------------------------------------------- *\
 * Storage structures                                                        *
\* ------------------------------------------------------------------------- */

typedef struct netload_mountinfo_struc
{
	char				device[64];     /* origin device (not encoded) */
	char				mountpoint[48];	/* the path of the mountpoint */
	char				fstype[12];		/* the filesystem type */
	unsigned short		usage;			/* filesystem usage percentage x10 */
} netload_mountinfo;

typedef struct netload_topentry_struc
{
	char				username[16];
	pid_t				pid;
	unsigned short		pcpu;
	unsigned short		pmem;
	time_t				secrun;
	char				ptitle[48];
} netload_topentry;

typedef struct netload_httpsocket_struc
{
	char				vhost[48];
	unsigned int		count;
} netload_httpsocket;

typedef struct netload_xenvps_struc
{
	char				id[16];
	unsigned short		pcpu; /* 0 - 10000 (100%) */
	unsigned int		memory; /* megabytes */
	unsigned int		iops; /* i/o operations per second */
} netload_xenvps;

typedef struct netload_ttyentry_struc
{
	char				line[10];
	char				username[14];
	unsigned int		host;
} netload_ttyentry;

typedef struct netload_portinfo_struc
{
	unsigned short		port;
	unsigned short		nestab;
	unsigned short		nother;
} netload_portinfo;

#define NR_HTTP 16
#define NR_TTYS 10
#define NR_PORTS 10
#define NR_TPROCS 24
#define NR_MOUNTS 4
#define NR_XENVPS 16

typedef struct netload_info_struc
{
	status_t		 	 status;
	oflag_t				 oflags;
	time_t				 localtime;
	unsigned short		 ping10; /* avg pingtime * 0.1 ms */
	unsigned short		 loss;
	
	time_t				 uptime;
	char				 hostname[32];
	time_t				 hosttime;
	ostype_t			 ostype;
	hwtype_t			 hwtype;
	unsigned short		 load1; /* loadavg * 100 */
	unsigned char		 cpu; /* cpu perc * 2.55 */
	unsigned int		 diskio; /* disk io blk/s */
	unsigned int		 services;
	unsigned short		 nrun;
	unsigned short		 nproc;
	int					 kmemfree;
	int					 kswapfree;
	unsigned int		 netin;		/* total network in  kilobit/s */
	unsigned int		 netout;	/* total network out kilobit/s */
	short				 nmounts;
	netload_mountinfo	 mounts[NR_MOUNTS];
	short				 ntop;
	netload_topentry	 tprocs[NR_TPROCS];
	short				 nports;
	netload_portinfo	 ports[NR_PORTS];
	short				 ntty;
	netload_ttyentry	 ttys[NR_TTYS];
	short				 nhttp;
	netload_httpsocket	 http[NR_HTTP];
	short				 nxenvps;
	netload_xenvps		 xenvps[NR_XENVPS];
} netload_info;

/* ------------------------------------------------------------------------- *\
 * Packed structures                                                         *
\* ------------------------------------------------------------------------- */

typedef struct netload_scache_struc
{
	struct netload_scache_struc	*next;
	char						*str;
	int							 pktpos;
} netload_scache; /* used for string compression */

typedef struct netload_pkt_struc
{
	unsigned char	 data[640];
	short			 pos;
	short			 rpos;
	short			 eof;
	netload_scache	*cache;
} netload_pkt;

typedef struct netload_rec_struc
{
	unsigned char	data[640];
	short			pos;
	short			rpos;
	short			eof;
} netload_rec;

#endif
