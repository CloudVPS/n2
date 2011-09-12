#include "n2encoding.h"
#include "n2hostlog.h"
#include "md5.h"
#include "iptypes.h"
#include "n2malloc.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

/* tables and macros to translate to and from 6 bit encoded strings */

unsigned char LMASKS[] = {0xfc, 0x7e, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01};
unsigned char RMASKS[] = {0x00, 0x00, 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8};

/* The table of 6bit-compatible ASCII characters */
const char *CTABLE = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPRSTUVWXY"
					 "-./:0123456789";
					 
/* Translation table from 7bit ASCII to 6bit, 127 for invalid conversion */
const char RCTABLE[] = { 127,127,127,127,127,127,127,127,127,127,127,127,127,
						127,127,127,127,127,127,127,127,127,127,127,127,127,127,
						127,127,127,127,127,0,127,127,127,127,127,127,127,127,
						127,127,127,127,50,51,52,54,55,56,57,58,59,60,61,62,63,
						53,127,127,127,127,127,127,27,28,29,30,31,32,33,34,35,
						36,37,38,39,40,127,41,127,42,43,44,45,46,47,48,49,127,
						127,127,127,127,127,127,1,2,3,4,5,6,7,8,9,10,11,12,13,
						14,15,16,17,18,19,20,21,22,23,24,25,26,127,127,127,127};

/* used for 6 bit encoding: Uses RCTABLE to convert a regular ASCII character
   to a 6 bit value. */
#define CTRANS(foo) (RCTABLE[foo & 0x7f])
					  
/* used for 6 bit decoding: Given a source buffer foo, get the 6 bit value at
   bit-offset offs. */
#define BITVAL(foo,offs) ( RMASKS[offs&7] ? \
						   ((foo[offs/8] & (LMASKS[offs&7])) << ((offs&7)-2)) | \
						   ((foo[(offs/8)+1] & (RMASKS[offs&7])) >> (10-(offs&7))) : \
						   ((foo[offs/8] & (LMASKS[offs&7])) >> (2-(offs&7))) \
						 )

#define PKT_MAXSZ 632

/* ------------------------------------------------------------------------- *\
 * FUNCTION init_netload_info (inf)                                          *
 * --------------------------------                                          *
 * Initializes the memory of a netload_info structure.                       *
\* ------------------------------------------------------------------------- */
void init_netload_info (netload_info *inf)
{
	inf->status = ST_UNSET;
	inf->localtime = 0;
	inf->ping10 = 0;
	inf->loss = 0;
	memset (inf->hostname, 0, 23);
	inf->hosttime = 0;
	inf->ostype = OS_OTHER;
	inf->hwtype = HW_OTHER;
	inf->load1 = 0;
	inf->nrun = 0;
	inf->nproc = 0;
	inf->kmemfree = 0;
	inf->kswapfree = 0;
	inf->kmemtotal = 0;
	inf->netin = 0;
	inf->netout = 0;
	inf->nmounts = 0;
	inf->ntty = 0;
	memset (inf->mounts, 0, NR_MOUNTS * sizeof(netload_mountinfo));
	inf->ntop = 0;
	memset (inf->tprocs, 0, NR_TPROCS * sizeof (netload_topentry));
	inf->nports = 0;
	memset (inf->ports, 0, NR_PORTS * sizeof (netload_portinfo));
	inf->nhttp = 0;
	memset (inf->http, 0, NR_HTTP * sizeof (netload_httpsocket));
	inf->ntty = 0;
	memset (inf->ttys, 0, NR_TTYS * sizeof (netload_ttyentry));
	inf->nxenvps = 0;
	memset (inf->xenvps, 0, NR_XENVPS * sizeof (netload_xenvps));
}

/* macros to encode/decode uptime into 16 bits */

#define MAXTS 0x4000

#define encode_uptime(x) ((x) < MAXTS ? (x) : \
						  (x/60) < MAXTS ? ((x/60)|0x4000) : \
						  (x/3600) < MAXTS ? ((x/3600)|0x8000) : \
						  ((x/86400)|0xc000))
#define decode_uptime(x) ((x & 0xc000) == 0 ? (x) : \
						  (x & 0xc000) == 0x4000 ? (x & 0x3fff) * 60 : \
						  (x & 0xc000) == 0x8000 ? (x & 0x3fff) * 3600 : \
						  (x & 0x3fff) * 86400)

/* ------------------------------------------------------------------------- *\
 * FUNCTION find_scache (pkt, string, position)                              *
 * --------------------------------------------                              *
 * Looks in the stringcache for a packet to find an earlier copy of          *
 * the literal string. If no match was found, a new entry is created.        *
 * Returns the position of the earlier copy, or the same value as the        *
 * argument if this is the first occurence of this string sequence.          *
\* ------------------------------------------------------------------------- */
int find_scache (netload_pkt *pkt, const char *str, int atposition)
{
	netload_scache *crsr;
	
	crsr = pkt->cache;
	if (! crsr)
	{
		crsr = (netload_scache *) calloc (1, sizeof (netload_scache));
		if (! crsr) return atposition;
		crsr->str = strdup (str);
		crsr->pktpos = atposition;
		pkt->cache = crsr;
		return atposition;
	}
	
	do
	{
		if (! strcmp (crsr->str, str))
		{
			/* If the distance is too great, force a new copy */
			if ((atposition - crsr->pktpos) > 255)
			{
				crsr->pktpos = atposition;
			}
			return crsr->pktpos;
		}
		if (crsr->next) crsr = crsr->next;
		else
		{
			crsr->next = (netload_scache *) calloc (1, sizeof (netload_scache));
			crsr = crsr->next;
			if (crsr)
			{
				crsr->str = strdup (str);
				crsr->pktpos = atposition;
			}
			return atposition;
		}
	} while (crsr);
	return atposition;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION clear_scache (pkt)                                               *
 * ---------------------------                                               *
 * Frees up all allocated memory associated to a packet's string cache.      *
\* ------------------------------------------------------------------------- */
void clear_scache (netload_pkt *pkt)
{
	netload_scache *c, *nc;
	
	c = pkt->cache;
	while (c)
	{
		nc = c->next;
		free (c->str);
		free (c);
		c = nc;
	}
	pkt->cache = NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION encode_pkt (inf, key)                                            *
 * ------------------------------                                            *
 * Encodes the information contained in a netload_info structure into a      *
 * netload_pkt structure, compacted to fit inside a single udp packet.       *
\* ------------------------------------------------------------------------- */
netload_pkt *encode_pkt (netload_info *inf, const char *key)
{
	netload_pkt *pkt;
	int			 i;
	md5_state_t	 md5state;
	int			 ntpos;
	int			 extraheadroom = 0;
	
	if (inf->nhttp) extraheadroom += 80;
	
	/* Allocate memory */
	
	pkt = (netload_pkt *) pool_alloc (sizeof (netload_pkt));
	if (pkt == NULL) return pkt;
	
	pkt->cache = NULL;

	/* Reserve 16 bytes for the MD5 checksum */

	pkt->pos = 16;
	pkt->rpos = 0;
	
	/* Print the heading */
	
	pkt_prints  (pkt, inf->hostname, 24);
	pkt_print8  (pkt, (inf->ostype & 0x0f) | ((inf->hwtype & 0x0f) << 4));
	pkt_print16 (pkt, inf->load1);
	pkt_print8  (pkt, inf->cpu);
	pkt_print24 (pkt, inf->diskio);
	pkt_print32 (pkt, inf->services);
	pkt_print16 (pkt, encode_uptime (inf->uptime));
	pkt_print24 (pkt, inf->hosttime & 0x00ffffff);

#ifdef N2_ENCODE_LEGACY_FORMAT
	pkt_print8  (pkt, inf->nrun & 0x7f);
#else
	pkt_print8  (pkt, 0x80 | (inf->iowait & 0x7f));
#endif
	pkt_print16 (pkt, inf->nproc);

#ifdef N2_ENCODE_LEGACY_FORMAT	
	if (inf->kmemfree > 0x00ffffff) inf->kmemfree = 0x00ffffff;
	if (inf->kswapfree > 0x00ffffff) inf->kswapfree = 0x00ffffff;
	
	pkt_print24 (pkt, inf->kmemfree);
	pkt_print24 (pkt, inf->kswapfree);
#else
	if (inf->kmemfree > 0x3fffffff) inf->kmemfree = 0x3fffffff;
	if (inf->kswapfree > 0x3fffffff) inf->kswapfree = 0x3fffffff;

	pkt_print16 (pkt, inf->kmemtotal/4096);
	pkt_print24 (pkt, inf->kmemfree/64);
	pkt_print24 (pkt, inf->kswapfree/64);
#endif

	pkt_print32 (pkt, inf->netin);
	pkt_print32 (pkt, inf->netout);
	
	/* Add recorded mountpoints */
	
#ifdef N2_ENCODE_LEGACY_FORMAT
	pkt_print8  (pkt, inf->nmounts);
#else
	pkt_print8	(pkt, 0x80 | (inf->nmounts & 0x7f));
#endif

	for (i=0; i<inf->nmounts; ++i)
	{
		pkt_prints  (pkt, inf->mounts[i].mountpoint, 32);
		pkt_prints  (pkt, inf->mounts[i].fstype, 8);
		pkt_print16 (pkt, inf->mounts[i].usage);
#ifndef N2_ENCODE_LEGACY_FORMAT
		pkt_print16 (pkt, inf->mounts[i].size);
#endif
	}
	
	/* Add recorded top entries */
	
	ntpos = pkt->pos;
	pkt_print8 (pkt, inf->ntop);
	for (i=0; i<inf->ntop; ++i)
	{
		if (pkt->pos < (PKT_MAXSZ-(110+extraheadroom)))
		{
			pkt_prints  (pkt, inf->tprocs[i].username, 12);
			pkt_print32 (pkt, inf->tprocs[i].pid);
			pkt_print16 (pkt, inf->tprocs[i].pcpu);
			pkt_print16 (pkt, inf->tprocs[i].pmem);
			pkt_print24 (pkt, inf->tprocs[i].secrun);
			pkt_prints  (pkt, inf->tprocs[i].ptitle, 31);
		}
		else
		{
			pkt->data[ntpos] = i;
			i = inf->ntop;
		}
	}
	
	/* Add recorded tcp port entries */
	//dprintf (">>> encode %i ports\n", inf->nports);
	pkt_print8 (pkt, inf->nports);
	for (i=0; i<inf->nports; ++i)
	{
		pkt_print16 (pkt, inf->ports[i].port);
		pkt_print16 (pkt, inf->ports[i].nestab);
		pkt_print16 (pkt, inf->ports[i].nother);
	}
	
	/* Add logged in remote ttys */
	
	ntpos = pkt->pos;
	pkt_print8 (pkt, inf->ntty);
	for (i=0; i<inf->ntty; ++i)
	{
		if (pkt->pos < (PKT_MAXSZ-(18+extraheadroom)))
		{
			pkt_prints (pkt, inf->ttys[i].line, 6);
			pkt_prints (pkt, inf->ttys[i].username, 10);
			pkt_print32 (pkt, inf->ttys[i].host);
		}
		else
		{
			pkt->data[ntpos] = i;
			i = inf->ntty;
		}
	}
	
	/* Add apache mod_status vhosts, if any */
	
	ntpos = pkt->pos;
	pkt_print8 (pkt, inf->nhttp);
	for (i=0; i<inf->nhttp; ++i)
	{
		if (pkt->pos < (PKT_MAXSZ - 24))
		{
			pkt_prints (pkt, inf->http[i].vhost, 48);
			pkt_print16 (pkt, inf->http[i].count);
			
			if (pkt->eof)
			{
				pkt->data[ntpos] = i;
				i = inf->nhttp;
			}
		}
		else
		{
			pkt->data[ntpos] = i;
			i = inf->nhttp;
		}
	}
	
	/* Add xen vps-list */
	
	ntpos = pkt->pos;
	pkt_print8 (pkt, inf->nxenvps);
	for (i=0; i<inf->nxenvps; ++i)
	{
		if (pkt->pos < (PKT_MAXSZ - 24))
		{
			pkt_prints (pkt, inf->xenvps[i].id, 16);
			pkt_print16 (pkt, inf->xenvps[i].pcpu);
			pkt_print16 (pkt, inf->xenvps[i].memory / 16);
			pkt_print16 (pkt, inf->xenvps[i].iops / 16);
			
			if (pkt->eof)
			{
				pkt->data[ntpos] = i;
				i = inf->nxenvps;
			}
		}
		else
		{
			pkt->data[ntpos] = i;
			i = inf->nxenvps;
		}
	}
	
	/* Create the MD5 checksum key */	

	md5_init (&md5state);
	md5_append (&md5state, pkt->data+16, pkt->pos-16);
	md5_append (&md5state, (const md5_byte_t*) key, strlen(key));
	md5_finish (&md5state, pkt->data);
	
	clear_scache (pkt);
	
	return pkt;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION validate_pkt (pkt, key)                                          *
 * --------------------------------                                          *
 * Validates a packet's MD5 checksum with a provided key string.             *
\* ------------------------------------------------------------------------- */
int validate_pkt (netload_pkt *pkt, const char *key)
{
	md5_state_t		md5state;
	unsigned char 	realsum[16];
	realsum[0] = 0;
	
	if (! key) return 0;

	md5_init (&md5state);
	md5_append (&md5state, pkt->data+16, pkt->pos-16);
	md5_append (&md5state, (const md5_byte_t*) key, strlen (key));
	md5_finish (&md5state, realsum);
	
	if (memcmp (pkt->data, realsum, 16) == 0) return 1;
	return 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION encode_rec (pkt, time, status, ping, loss)                       *
 * ---------------------------------------------------                       *
 * Convert a packet with md5sum to a disk record.                            *
\* ------------------------------------------------------------------------- */
netload_rec *encode_rec (netload_pkt *pkt, time_t ti, status_t st,
						 unsigned short ping10, unsigned short loss,
						 unsigned int oflags)
{
	short oldpos = pkt->pos;
	pkt->pos = 0;
	pkt_print8 (pkt, 0);
	pkt_print8 (pkt, st);
	pkt_print16 (pkt, oldpos+1);
	pkt_print32 (pkt, ti);
	pkt_print16 (pkt, ping10);
	pkt_print16 (pkt, loss);
	pkt_print32 (pkt, oflags);
	pkt->pos = oldpos;
	pkt_print8 (pkt, 0);
	
	return (netload_rec *) pkt;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION decode_rec_inline (rec, into_info)                               *
 * -------------------------------------------                               *
 * Decodes a disk record into a netload_info structure.                      *
\* ------------------------------------------------------------------------- */
const char *DECODE_ERROR;

#ifdef DEBUG_DECODING
  #define DPRINTF printf ("offs %03x ", rec->rpos) && printf
#else
  #define DPRINTF(foo,...) {}
#endif

int decode_rec_inline (netload_rec *rec, netload_info *dst)
{
	int			  row;
	int			  tmp;

	init_netload_info (dst);
	
	rec->rpos = 0;
	DECODE_ERROR = "OK";
	
	(void)			  rec_read8  (rec);
	dst->status		= rec_read8  (rec);
	(void)			  rec_read16 (rec);
	dst->localtime	= rec_read32 (rec);
	dst->ping10		= rec_read16 (rec);
	dst->loss		= rec_read16 (rec);
	dst->oflags		= rec_read32 (rec);
	
	DPRINTF ("status=<%i> localtime=<%i> ping10=<%i> loss=<%i>\n",
			 dst->status, dst->localtime, dst->ping10, dst->loss);
	
	if (rec->eof)
	{
		DECODE_ERROR = "EOF after reading header";
		return 0;
	}
	
	(void)			  rec_reads  (rec, dst->hostname, 32);

	DPRINTF ("hostname=<%s>\n", dst->hostname);

	tmp				= rec_read8  (rec);
	dst->ostype		= (tmp & 0x0f);
	dst->hwtype		= (tmp & 0xf0) >> 4;
	
	dst->load1		= rec_read16 (rec);
	dst->cpu		= rec_read8  (rec);
	dst->diskio		= rec_read24 (rec);
	dst->services	= rec_read32 (rec);
	
	DPRINTF ("ostype=<%i> hwtype=<%i> load1=<%i> cpu=<%i> diskio=<%i>\n",
			 dst->ostype, dst->hwtype, dst->load1, dst->cpu, dst->diskio);
	DPRINTF ("services=<%08x>\n", dst->services);

	if (rec->eof)
	{
		DECODE_ERROR = "EOF after reading services";
		return 0;
	}
	
	tmp				= rec_read16 (rec);
	dst->uptime		= decode_uptime (tmp);
	
	DPRINTF ("uptime=<%i>\n", dst->uptime);
	
	dst->hosttime	= rec_read24 (rec);

	tmp 			= rec_read8  (rec);

	if (tmp & 0x80)
	{
		dst->iowait = tmp & 0x7f;
		dst->nrun = 1;
	}
	else
	{
		dst->iowait = 0;
		dst->nrun = tmp;
	}

	dst->nproc		= rec_read16 (rec);

	if (tmp & 0x80)
	{
		dst->kmemtotal = rec_read16 (rec) * 4096;
		dst->kmemfree = rec_read24 (rec) * 64;
		dst->kswapfree = rec_read24 (rec) * 64;	
	}
	else
	{
		dst->kmemfree	= rec_read24 (rec);
		dst->kswapfree	= rec_read24 (rec);
	}

	DPRINTF ("hosttime=<%i> nrun=<%i> nproc=<%i> kmemfree=<%i> kswapfree=<%i>\n",
			 dst->hosttime, dst->nrun, dst->nproc, dst->kmemfree,
			 dst->kswapfree);

	dst->netin		= rec_read32 (rec);
	dst->netout		= rec_read32 (rec);

	DPRINTF ("netin=<%i> netout=<%i>\n", dst->netin, dst->netout);

	if (rec->eof)
	{
		DECODE_ERROR = "EOF after reading netout";
		return 0;
	}

	tmp             = rec_read8  (rec);
	dst->nmounts    = tmp & 0x7f;
	
	DPRINTF ("nmounts=<%i> tmp=<%i>\n", dst->nmounts, tmp);
	
	if (dst->nmounts > 4)
	{
		dst->nmounts = 4;
		DECODE_ERROR = "Illegal number of mounts";
		return 0;
	}
	
	for (row=0; row < dst->nmounts; ++row)
	{
		DPRINTF ("reading mount %i\n", row);
		dst->mounts[row].device[0] = 0;
		(void) rec_reads  (rec, dst->mounts[row].mountpoint, 32);
		(void) rec_reads  (rec, dst->mounts[row].fstype, 8);
		dst->mounts[row].usage	= rec_read16 (rec);
		if (tmp & 0x80) dst->mounts[row].size = rec_read16 (rec);
		else dst->mounts[row].size = 0;
	}

	DPRINTF ("end of mounts\n");
	
	if (rec->eof)
	{
		DECODE_ERROR = "EOF after reading mounts";
		return 0;
	}
	
	dst->ntop = rec_read8  (rec);
	
	DPRINTF ("ntop=<%i>\n", dst->ntop);
	
	if (dst->ntop > NR_TPROCS)
	{
		dst->ntop = NR_TPROCS;
		DECODE_ERROR = "Illegal number of toprecs";
		return 0;
	}
	
	for (row=0; row < dst->ntop; ++row)
	{
		DPRINTF ("reading top-entry %i eof=<%i>\n", row, rec->eof);
		(void) rec_reads  (rec, dst->tprocs[row].username, 9);
		dst->tprocs[row].pid	= rec_read32 (rec);
		dst->tprocs[row].pcpu	= rec_read16 (rec);
		dst->tprocs[row].pmem	= rec_read16 (rec);
		dst->tprocs[row].secrun	= rec_read24 (rec);
		(void) rec_reads  (rec, dst->tprocs[row].ptitle, 31);
		DPRINTF ("pid=<%i> secrun=<%i> title=<%s>\n", dst->tprocs[row].pid,
				 dst->tprocs[row].secrun, dst->tprocs[row].ptitle);
	}
	
	if (rec->eof)
	{
		DECODE_ERROR = "EOF after reading toprecs";
		return 0;
	}
	
	dst->nports		= rec_read8  (rec);
	
	DPRINTF ("nports=<%i>\n", dst->nports);
	
	if (dst->nports > NR_PORTS)
	{
		dst->nports = NR_PORTS;
		DECODE_ERROR = "Illegal number of ports";
		return 0;
	}
	
	for (row=0; row < dst->nports; ++row)
	{
		dst->ports[row].port	= rec_read16  (rec);
		dst->ports[row].nestab	= rec_read16  (rec);
		dst->ports[row].nother	= rec_read16  (rec);
	}

	if (rec->eof)
	{
		DECODE_ERROR = "EOF after reading ports";
		return 0;
	}
	
	if ( (rec->pos - rec->rpos) > 2 ) /* tty records? */
	{
		dst->ntty = rec_read8 (rec);
		if (dst->ntty > NR_TTYS) dst->ntty = NR_TTYS;
		
		if (dst->ntty)
		{
			for (row=0; (! rec->eof) && (row < dst->ntty); ++row)
			{
				rec_reads (rec, dst->ttys[row].line, 8);
				rec_reads (rec, dst->ttys[row].username, 12);
				dst->ttys[row].host = rec_read32 (rec);
			}
			dst->ntty = row;
			if (rec->eof)
			{
				DECODE_ERROR = "EOF while reading ttys";
				return 0;
			}
		}
	}
	else
	{
		dst->ntty = 0;
		dst->nhttp = 0;
		dst->nxenvps = 0;
		return 1;
	}
	
	if ((rec->pos - rec->rpos) > 1) /* vhost records? */
	{
		dst->nhttp = rec_read8 (rec);
		DPRINTF ("nhttp %i\n", dst->nhttp);
		if (dst->nhttp > NR_HTTP) dst->nhttp = NR_HTTP;
		
		if (dst->nhttp)
		{
			for (row=0; (! rec->eof) && (row < dst->nhttp); ++row)
			{
				DPRINTF ("reading http row %i\n", row);
				rec_reads (rec, dst->http[row].vhost, 48);
				dst->http[row].count = rec_read16 (rec);
			}
			
			dst->nhttp = row;
		}
	}
	else
	{
		dst->nhttp = 0;
		dst->nxenvps = 0;
		return 1;
	}
	
	if ((rec->pos - rec->rpos) > 1) /* xenvps records? */
	{
		dst->nxenvps = rec_read8 (rec);
		if (dst->nxenvps > NR_XENVPS) dst->nxenvps = NR_XENVPS;
		
		if (dst->nxenvps)
		{
			for (row=0; (! rec->eof) && (row < dst->nxenvps); ++row)
			{
				rec_reads (rec, dst->xenvps[row].id, 16);
				dst->xenvps[row].pcpu = rec_read16 (rec);
				dst->xenvps[row].memory = rec_read16 (rec) * 16;
				dst->xenvps[row].iops = rec_read16 (rec) * 16;
				if (rec->eof) row--;
			}
			
			dst->nxenvps = row;
		}
	}
	/* there should be a trailing 0 */
	if (rec->eof)
	{
		DECODE_ERROR = "End of file at end of parsing";
		return 0;
	}
	
	return 1;
}


/* ------------------------------------------------------------------------- *\
 * FUNCTION create_error_rec ()                                              *
 * -------------------------                                                 *
 * creates a empty netload_info, with a status ST_ALERT                      *
 * and other flags set to decoding error									 *
\* ------------------------------------------------------------------------- */
netload_info *create_error_rec()
{
	netload_info *dst_error;
	
	dst_error = (netload_info *) pool_alloc (sizeof (netload_info));
	dst_error->status = MKSTATUS(dst_error->status,ST_ALERT);
	SETSTATUSFLAG(dst_error->status,FLAG_OTHER);
	SETOFLAG(dst_error->oflags,OFLAG_DECODINGERR);
	
	return dst_error;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION decode_rec (rec)                                                 *
 * -------------------------                                                 *
 * Decodes a disk record into a netload_info structure.                      *
\* ------------------------------------------------------------------------- */
netload_info *decode_rec (netload_rec *rec)
{
	netload_info *dst;
	netload_info *dst_error;
	int			  row;
	int			  tmp;
	int			  failure = 0;
	
	/* Allocate a netload_info structure */
	dst = (netload_info *) pool_alloc (sizeof (netload_info));
	if (decode_rec_inline (rec, dst)) 
	{
		return dst;
	}
	else
	{
		pool_free (dst);
		dst_error = create_error_rec();
		
		return dst_error;
	}
	
	pool_free (dst_error);
	return NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_get_hosttime (pkt)                                           *
 * -------------------------------                                           *
 * Extracts the hosttime out of a netload_pkt structure                      *
\* ------------------------------------------------------------------------- */
unsigned int pkt_get_hosttime (netload_pkt *rec)
{
	char			 hostname[32];
	unsigned int	 hosttime;
	
	rec->rpos = 16;
	rec_reads ((netload_rec *) rec, hostname, 32);
	rec_read8 ((netload_rec *) rec);
	rec_read16 ((netload_rec *) rec);
	rec_read32 ((netload_rec *) rec);
	rec_read32 ((netload_rec *) rec);
	rec_read16 ((netload_rec *) rec);
	hosttime = rec_read24 ((netload_rec *) rec);
	return hosttime;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_get_uptime (pkt)                                             *
 * -----------------------------                                             *
 * Extracts the uptime out of a netload_pkt structure                        *
\* ------------------------------------------------------------------------- */
unsigned int pkt_get_uptime (netload_pkt *rec)
{
	char			 hostname[32];
	unsigned int	 uptime;
	
	rec->rpos = 16;
	rec_reads ((netload_rec *) rec, hostname, 32);
	rec_read8 ((netload_rec *) rec);
	rec_read16 ((netload_rec *) rec);
	rec_read32 ((netload_rec *) rec);
	rec_read32 ((netload_rec *) rec);
	uptime = rec_read16 ((netload_rec *) rec);
	uptime = decode_uptime (uptime);
	return uptime;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_get_uptime (pkt)                                             *
 * -----------------------------                                             *
 * Extracts the uptime out of a netload_pkt structure                        *
\* ------------------------------------------------------------------------- */
unsigned int pkt_get_services (netload_pkt *rec)
{
	char			 hostname[32];
	unsigned int	 services;
	
	rec->rpos = 16;
	rec_reads ((netload_rec *) rec, hostname, 32);
	rec_read8 ((netload_rec *) rec);
	rec_read16 ((netload_rec *) rec);
	rec_read32 ((netload_rec *) rec);
	services = rec_read32 ((netload_rec *) rec);
	return services;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_get_status (rec)                                             *
 * -----------------------------                                             *
 * Extracts the status out of a netload_rec structure                        *
\* ------------------------------------------------------------------------- */
status_t rec_get_status (netload_rec *rec)
{
	return (status_t) rec->data[1];
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_set_status (rec, status)                                     *
 * -------------------------------------                                     *
 * Updates the status field inside a netload_rec block.                      *
\* ------------------------------------------------------------------------- */
void rec_set_status (netload_rec *rec, status_t status)
{
	short oldpos;
	
	oldpos = rec->pos;
	rec->pos = 1;
	pkt_print8 ((netload_pkt *) rec, status);
	rec->pos = oldpos;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_set_ping10 (rec, ping)                                       *
 * -----------------------------------                                       *
 * Updates the ping10 field inside a netload_rec block.                      *
\* ------------------------------------------------------------------------- */
void rec_set_ping10 (netload_rec *rec, int ping)
{
	short oldpos;
	oldpos = rec->pos;
	rec->pos = 8;
	pkt_print16 ((netload_pkt *) rec, ping);
	rec->pos = oldpos;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_set_loss (rec, loss)                                         *
 * ---------------------------------                                         *
 * Updates the packetloss field inside a netload_rec block.                  *
\* ------------------------------------------------------------------------- */
void rec_set_loss (netload_rec *rec, int loss)
{
	short oldpos;
	oldpos = rec->pos;
	rec->pos = 10;
	pkt_print16 ((netload_pkt *) rec, loss);
	rec->pos = oldpos;
}

void rec_set_oflags (netload_rec *rec, oflag_t oflags)
{
	short oldpos;
	oldpos = rec->pos;
	rec->pos = 12;
	pkt_print32 ((netload_pkt *) rec, oflags);
	rec->pos = oldpos;
}

oflag_t rec_get_oflags (netload_rec *rec)
{
	int i;
	i = (rec->data[12]) | (rec->data[13] << 8) |
		(rec->data[14] << 16) | (rec->data[15] << 24);
	return (oflag_t) i;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_print8 (pkt, byte)                                           *
 * -------------------------------                                           *
 * Append an 8-bit integer to a packet stream.                               *
\* ------------------------------------------------------------------------- */
void pkt_print8 (netload_pkt *p, unsigned char n)
{
	if (p->pos < PKT_MAXSZ)
	{
		p->eof = 0;
		p->data[p->pos++] = n;
	}
	else
	{
		p->eof = 1;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_print16 (pkt, data)                                          *
 * --------------------------------                                          *
 * Append an 16-bit integer to a packet stream.                              *
\* ------------------------------------------------------------------------- */
void pkt_print16 (netload_pkt *p, unsigned short n)
{
	if (p->pos < (PKT_MAXSZ-1))
	{
		p->data[p->pos++] = (n & 0x00ff);
		p->data[p->pos++] = (n & 0xff00) >> 8;
		p->eof = 0;
	}
	else
	{
		p->eof = 1;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_print24 (pkt, data)                                          *
 * --------------------------------                                          *
 * Append an 24-bit integer to a packet stream.                              *
\* ------------------------------------------------------------------------- */
void pkt_print24 (netload_pkt *p, int n)
{
	if (p->pos<(PKT_MAXSZ-2))
	{
		p->data[p->pos++] = (n & 0x000000ff);
		p->data[p->pos++] = (n & 0x0000ff00) >> 8;
		p->data[p->pos++] = (n & 0x00ff0000) >> 16;
		p->eof = 0;
	}
	else
	{
		p->eof = 1;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_print32 (pkt, data)                                          *
 * --------------------------------                                          *
 * Append an 32-bit integer to a packet stream.                              *
\* ------------------------------------------------------------------------- */
void pkt_print32 (netload_pkt *p, int n)
{
	if (p->pos<(PKT_MAXSZ-3))
	{
		p->data[p->pos++] = (n & 0x000000ff);
		p->data[p->pos++] = (n & 0x0000ff00) >> 8;
		p->data[p->pos++] = (n & 0x00ff0000) >> 16;
		p->data[p->pos++] = (n & 0xff000000) >> 24;
		p->eof = 0;
	}
	else
	{
		p->eof = 1;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pkt_prints (pkt, string)                                         *
 * ---------------------------------                                         *
 * Append a size-prefix pascal string to a packet stream.                    *
\* ------------------------------------------------------------------------- */
void pkt_prints (netload_pkt *p, const char *str, int maxln)
{
	int c;
	int maxpos;
	int szpos;
	int len = strlen(str);
	
	if (len >2) /* For strings sized 3 and up, consider dropping redundants */
	{
		c = find_scache (p, str, p->pos); /* Find our string in the cache */
		if ((c < p->pos) && ( (p->pos - c) < 256)) /* Refers to older pos? */
		{
			if ( (p->pos +2) < PKT_MAXSZ) /* We have room to spare for 2 bytes? */
			{
				c = p->pos - c;
				/* Store the backreference flag and offset */
				p->data[p->pos++] = 0x80;
				p->data[p->pos++] = c;
				return;
			}
		}
	}
	if (len >3) /* For strings sized 4 and up, consider 6 bit encoding */
	{
		/* Characters not in the 6 bit set will yield 127 */
		for (c=0; c<len; ++c) if (CTRANS(str[c]) == 127) break;
		if (c == len) /* The entire string is inside the 6 bit charset */
		{
			szpos = p->pos;
			p->data[p->pos++] = len | 0x80;
			maxpos = p->pos + maxln;
			if (maxpos > PKT_MAXSZ) maxpos = PKT_MAXSZ;
			
			/* Keep storing characters until we are over size */
			for (c=0; (p->pos < maxpos) && (c<len); ++c)
			{
				switch (c & 3)
				{
					case 0:
						p->data[p->pos] = CTRANS(str[c]) << 2;
						break;
					
					case 1:
						p->data[p->pos] = p->data[p->pos] | CTRANS(str[c]) >> 4;
						p->pos++;
						p->data[p->pos]    = (CTRANS(str[c]) & 0x0f) << 4;
						break;
					
					case 2:
						p->data[p->pos] = p->data[p->pos] |
										  (CTRANS(str[c]) & 0x3c) >> 2;
						p->pos++;
						p->data[p->pos]    = (CTRANS(str[c]) & 0x03) << 6;
						break;
						
					case 3:
						p->data[p->pos] = p->data[p->pos] |
										  (CTRANS(str[c]) & 0x3f);
						p->pos++;
						break;
				}
			}
			/* If we didn't make the full string, reset the length field */
			if (c < len) p->data[szpos] = c | 0x80;
			if (c & 3) p->pos++;
			if (p->pos >= PKT_MAXSZ) p->eof = 1;
			return;
		}
	}
	/* Plain old pascal string encoding */
	if (len > maxln) len = maxln; /* Don't write too much */
	if (( (p->pos + len + 1) < PKT_MAXSZ) && (len < 128))
	{
		p->data[p->pos++] = len;
		memcpy (p->data + p->pos, str, len);
		p->pos += len;
		p->eof = 0;
	}
	else /* Didn't fit */
	{
		p->eof = 1;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_read8 (rec)                                                  *
 * ------------------------                                                  *
 * Extracts an 8-bit integer from a record stream structure.                 *
\* ------------------------------------------------------------------------- */
unsigned char rec_read8 (netload_rec *r)
{
	if (r->rpos >= r->pos)
	{
		r->eof = 1;
		return 0;
	}
	
	r->eof = 0;
	return r->data[r->rpos++];
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_read16 (rec)                                                 *
 * -------------------------                                                 *
 * Extracts a 16-bit integer from a record stream structure.                 *
\* ------------------------------------------------------------------------- */
unsigned short rec_read16 (netload_rec *r)
{
	unsigned short res;

	if ((r->rpos +1) >= r->pos)
	{
		r->eof = 1;
		return 0;
	}
	
	r->eof = 0;
	res = r->data[r->rpos] | (r->data[r->rpos+1] << 8);
	r->rpos += 2;
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_read24 (rec)                                                 *
 * -------------------------                                                 *
 * Extracts a 24-bit integer from a record stream structure.                 *
\* ------------------------------------------------------------------------- */
int rec_read24 (netload_rec *r)
{
	int res;

	if ((r->rpos +2) >= r->pos)
	{
		r->eof = 1;
		return 0;
	}
	
	r->eof = 0;
	res = r->data[r->rpos] | (r->data[r->rpos+1] << 8) |
							 (r->data[r->rpos+2] << 16);
	r->rpos += 3;
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_read32 (rec)                                                 *
 * -------------------------                                                 *
 * Extracts a 32-bit integer from a record stream structure.                 *
\* ------------------------------------------------------------------------- */
int rec_read32 (netload_rec *r)
{
	int res;
	
	if ((r->rpos +2) >= r->pos)
	{
		r->eof = 1;
		return 0;
	}
	
	r->eof = 0;
	res = r->data[r->rpos] | (r->data[r->rpos+1] << 8) |
		  (r->data[r->rpos+2] << 16) | (r->data[r->rpos+3] << 24);
	
	r->rpos += 4;
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION rec_reads (rec, into, maxsize)                                   *
 * ---------------------------------------                                   *
 * Extracts a sized pascal string from a record stream structure.            *
\* ------------------------------------------------------------------------- */
int rec_reads (netload_rec *r, char *data, size_t maxsz)
{
	unsigned int ln;
	unsigned int clen;
	int pos;
	int crpos;
	int res;
	size_t realsz;
	char *start;
	
	if (r->rpos >= r->pos) return 0;
	
	ln = r->data[r->rpos++];
	
	if (ln == 0x80) /* repeated string */
	{
		pos = r->data[r->rpos];
		if (! pos) /* points to self, invalid */
		{
			r->eof = 1;
			r->rpos = r->pos;
			data[0] = 0;
			return 0;
		}
		pos = r->rpos - (pos+1);
		
		if ((pos>0) && (r->data[pos] == 0x80)) /* no recursive jumps ktx */
		{
			pos = 0;
		}
		
		if (pos<1) /* can't possibly point there, go away */
		{
			r->eof = 1;
			r->rpos = r->pos;
			data[0] = 0;
			return 0;
		}
		
		crpos = r->rpos; /* store current position */
		r->rpos = pos; /* put in old string position */
		if (rec_reads (r, data, maxsz)) /* recurse once */
		{
			r->rpos = crpos+1; /* restore old read position */
			return 1; /* all ok */
		}
		return 0;
	}
	
	if (ln & 0x80) /* 6bit encoding */
	{
		clen = ln & 0x7f;
		ln = (((ln & 0x7f) * 6) / 8);
		if (clen & 3) ln++;
		
		start = (char *) r->data + r->rpos;
		
		if ((r->rpos + ln) > r->pos)
		{
			r->eof = 1;
			r->rpos = r->pos;
			data[0] = 0;
			return 0;
		}
		
		for (pos=0; (pos < maxsz) && (pos < clen); ++pos)
		{
			crpos = pos * 6;
			data[pos] = CTABLE[BITVAL(start,crpos) & 0x3f];
		}
		if (pos<maxsz) data[pos] = 0;
		else data[maxsz-1] = 0;
		
		r->rpos += ln;
		if (r->rpos > r->pos)
		{
			r->eof=1;
		}
		return 1;
	}
	
	if ((r->rpos + ln) > r->pos) /* illegal string header */
	{
		r->eof = 1;
		r->rpos = r->pos;
		data[0] = 0;
		
		return 0;
	}
	
	r->eof = 0;
	realsz = ln;
	if (realsz >= maxsz) /* string longer than allowed */
	{
		realsz = maxsz-1;
	}
	
	memcpy (data, r->data + r->rpos, realsz);
	data[realsz] = 0;
	
	r->rpos += ln;
	
	return 1;
}

/* Translation string arrays for human/machine readable output formats */

const char *STR_STATUS[] = {
	"Unset",
	"INIT0",
	"INIT1",
	"INIT2",
	"INIT3",
	"INIT4",
	"INIT5",
	"INIT6",
	"INIT7",
	"INIT8",
	"OK",
	"WARN",
	"ALERT",
	"CRIT",
	"STALE",
	"DEAD"
};

const char *STR_STATUSFLAGS[] = {
	"rtt",
	"loss",
	"load",
	"other"
};

const char *STR_OFLAGS[] = {
	"ram", /* 0 */
	"swap", /* 1 */
	"netin", /* 2 */
	"netout", /* 3 */
	"svcdown", /* 4 */
	"diskio", /* 5 */
	"diskspace", /* 6 */
	"decoding", /* 7 */
	"iowait", /* 8 */
	"", /* 9 */
	"", /* 10 */
	"", /* 11 */
	"", /* 12 */
	"", /* 13 */
	"", /* 14 */
	"", /* 15 */
	"", /* 16 */
	"", /* 17 */
	"", /* 18 */
	"", /* 19 */
	"", /* 20 */
	"", /* 21 */
	"", /* 22 */
	"", /* 23 */
	"", /* 24 */
	"", /* 25 */
	"", /* 26 */
	"", /* 27 */
	"", /* 28 */
	"", /* 29 */
	"", /* 30 */
	"acked" /* 31 */
};

const char *STR_OS[] = {
	"Linux",
	"BSD",
	"Solaris",
	"IRIX",
	"AIX",
	"HPUX",
	"OSX",
	"Windows",
	"Other",
	"9",
	"10",
	"11",
	"12",
	"13",
	"14",
	"15"
};

const char *STR_HW[] = {
	"x86",
	"x86_64",
	"ppc",
	"mips",
	"sparc",
	"alpha",
	"pa-risc",
	"other",
	"8",
	"9",
	"10",
	"11",
	"12",
	"13",
	"14",
	"15"
};

const char *STR_SVC[] = {
	"n2rxd",
	"sshd",
	"httpd",
	"snmpd",
	"smtpd",
	"imapd",
	"pop3d",
	"ftpd",
	"news",
	"cron",
	"admin",
	"db",
	"nfs",
	"cifs",
	"atalk",
	"named",
	"ldap",
	"spamd",
	"routed",
	"inetd",
	"dhcpd",
	"firewall",
	"syslogd",
	"printer",
	"vm",
	"chat",
	"user2",
	"user3",
	"user4",
	"user5",
	"user6",
	"user7"
};

const char *get_servicename (int i)
{
	return STR_SVC[i & 31];
}

/* conversion macros to convert uptime in seconds to meaningful values */

#define to_dys(x) ((x)/86400)
#define to_hrs(x) (((x) - (to_dys(x) * 86400)) / 3600 )
#define to_mns(x) (((x) - (to_dys(x) * 86400) - (to_hrs(x) * 3600)) / 60)
#define to_sec(x) (((x) - (to_dys(x) * 86400) - \
						  (to_hrs(x) * 3600) - (to_mns(x) * 60)))

/* String array used to build the cpu gauge */

const char *CPUBAR[] = { "-[               ]+",
						 "-[#              ]+",
						 "-[##             ]+",
						 "-[###            ]+",
						 "-[####           ]+",
						 "-[#####          ]+",
						 "-[######         ]+",
						 "-[#######        ]+",
						 "-[########       ]+",
						 "-[#########      ]+",
						 "-[##########     ]+",
						 "-[###########    ]+",
						 "-[############   ]+",
						 "-[#############  ]+",
						 "-[############## ]+",
						 "-[###############]+" };
						 

/* Text constant to preserve source width */

#define SEPARATOR "-------------------\n"

/* ------------------------------------------------------------------------- *\
 * FUNCTION print_info (info)                                                *
 * --------------------------                                                *
 * Prints contens of a netload_info struct in human readable format.         *
\* ------------------------------------------------------------------------- */
void print_info (netload_info *inf, unsigned int addr)
{
	int i;
	int j;
	int statusflg_cnt, otherflg_cnt, max_statusflgs, max_oflgs;
	int showpmem;
	char ip[32];
	
	printip (addr, ip);

	printf ("---( HOST )--------------------------------------" SEPARATOR);

	printf ("Hostname........: %s\n", inf->hostname);
	printf ("Address.........: %s\n", ip);
	printf ("Status..........: %s\n", STR_STATUS[inf->status & 15]);
	
	if ((RDSTATUS(inf->status) > ST_OK) && (RDSTATUS(inf->status) < ST_STALE))
	{
		max_statusflgs = sizeof(STR_STATUSFLAGS)/sizeof(*STR_STATUSFLAGS);
		max_oflgs = sizeof(STR_OFLAGS)/sizeof(*STR_OFLAGS);
		printf ("Problems........:");
		for (statusflg_cnt = 0; statusflg_cnt<max_statusflgs; ++statusflg_cnt)
		{
			if (1 == CHKSTATUSFLAG(inf->status,statusflg_cnt))
			{
				printf(" %s", STR_STATUSFLAGS[statusflg_cnt]);
			}
		}
		if (1 == CHKSTATUSFLAG(inf->status,FLAG_OTHER))
		{
			for (otherflg_cnt = 0; otherflg_cnt<max_oflgs; ++otherflg_cnt)
			{
				if (1 == CHKOFLAG(inf->oflags,otherflg_cnt))
				{
					printf(" %s", STR_OFLAGS[otherflg_cnt]);
				}
			}
		}
		printf ("\n");
	}
	
	printf ("Host time.......: %d\n", inf->hosttime);
	printf ("Host uptime.....: %i day(s), %i:%02i:%02i\n", to_dys(inf->uptime),
												to_hrs(inf->uptime),
												to_mns(inf->uptime),
												to_sec(inf->uptime));
	printf ("OS/Hardware.....: %s (%s)\n",
							STR_OS[inf->ostype & 15],
							STR_HW[inf->hwtype & 15]);
	
	printf ("Services........: ");
	j=0;
	for (i=0; i<32; ++i)
	{
		if (inf->services & (1 << i))
		{
			if (j) printf (",");
			if (j>7)
			{
				printf ("\n                  ");
				j = 0;
			}
			j++;
			printf ("%s", STR_SVC[i]);
		}
	}
	if (! j) printf ("none");
	printf ("\n");
	
	printf ("---( RESOURCES )---------------------------------" SEPARATOR);
	printf ("Processes.......: %i (%i running)\n", inf->nproc, inf->nrun);
	printf ("Load/CPU........: %3.2f (%3.2f %%)                %s\n",
			 (double) inf->load1 / 100.0,
			 (double) inf->cpu / 2.55,
			 CPUBAR[inf->cpu >> 4]);
	printf ("I/O wait........: %i %%\n", inf->iowait);
	if (inf->kmemtotal)
	{
		printf ("Available RAM...: %.2f MB\n", ((float)inf->kmemtotal)/1024.0);
	}
	printf ("Free RAM/Swap...: %.2f MB / %.2f MB\n",
			((float)inf->kmemfree)/1024.0,
			((float)inf->kswapfree)/1024.0);
	printf ("Network in/out..: %i Kb/s / %i Kb/s\n", inf->netin, inf->netout);
	printf ("Disk i/o........: %i blk/s\n", inf->diskio);
	printf ("---( PING TIMES )--------------------------------" SEPARATOR);
	printf ("Average RTT.....: %5.1f ms\n", (double) inf->ping10 / 10.0);
	printf ("Packet loss.....: %6.2f %%\n", (double) inf->loss / 100.0);
	
	printf ("---( MOUNTS )------------------------------------" SEPARATOR);
	
	for (i=0; i<inf->nmounts; ++i)
	{
		if (inf->mounts[i].usage < 1001)
		{
			printf ("%8s  %6.02f %%  %i GB  %s\n", inf->mounts[i].fstype,
										 (double) inf->mounts[i].usage / 10.0,
										 inf->mounts[i].size,
										 inf->mounts[i].mountpoint);
		}
		else
		{
			printf ("%8s   -ERR- %%  %s\n", inf->mounts[i].fstype,
					inf->mounts[i].mountpoint);
		}
	}

	printf ("---( TPROCS )------------------------------------" SEPARATOR);
	
	showpmem = 0;
	for (i=0; i<inf->ntop; ++i)
	{
		if (inf->tprocs[i].pmem)
		{
			showpmem = 1;
			break;
		}
	}
	
	if (inf->ntop)
	{
		if (showpmem)
		{
			printf ("PID       USER       CPU      MEM  NAME\n");
		}
		else
		{
			printf ("PID       USER       CPU  NAME\n");
		}
	}
	
	for (i=0; i<inf->ntop; ++i)
	{
		if (showpmem)
		{
			printf ("%5i %8s   %5.2f %%  %5.2f %%  %s\n",
					 inf->tprocs[i].pid,
					 inf->tprocs[i].username,
					 (double) inf->tprocs[i].pcpu / 100.0,
					 (double) inf->tprocs[i].pmem / 100.0,
					 inf->tprocs[i].ptitle);
		}
		else
		{
			printf ("%5i %8s   %5.2f %%  %s\n",
					inf->tprocs[i].pid,
					inf->tprocs[i].username,
					(double) inf->tprocs[i].pcpu / 100.0,
					inf->tprocs[i].ptitle);
		}
	}
	
	if (inf->nxenvps)
	{
		printf ("---( VPS )---------------------------------------" SEPARATOR);
		printf ("ID               CPU       MEMORY          I/O\n");
		//       .......*.......* ##### % ..... MB ...... blk/s
		for (i=0; i<inf->nxenvps; ++i)
		{
			printf ("%-16s %5i %% %5i MB %6i blk/s\n",
					inf->xenvps[i].id,
					inf->xenvps[i].pcpu,
					inf->xenvps[i].memory,
					inf->xenvps[i].iops);
		}
	}

	if (inf->ntty)
	{
		printf ("---( LOGGED IN USERS )---------------------------" SEPARATOR);
		for (i=0; i<inf->ntty; ++i)
		{
			printip (inf->ttys[i].host, ip);
			printf ("%-7s %-9s %s\n", inf->ttys[i].line,
					inf->ttys[i].username, ip);
		}
	}
	
	if (inf->nhttp)
	{
		printf ("---( HTTP )--------------------------------------" SEPARATOR);
		for (i=0; i<inf->nhttp; ++i)
		{
			printf ("%-48s %i\n", inf->http[i].vhost, inf->http[i].count);
		}
	}

	printf ("---( TCP PORTS )---------------------------------" SEPARATOR);
	
	for (i=0; i<inf->nports; ++i)
	{
		printf ("%5i: ", inf->ports[i].port);
		if ((inf->ports[i].nestab)||(inf->ports[i].nother))
		{
			printf ("%3i/%3i   ", inf->ports[i].nestab, inf->ports[i].nother);
		}
		else printf ("          ");
		if ((i&3)==3) printf ("\n");
	}
	if (i&3) printf ("\n");
	printf ("---( EVENT LOG )---------------------------------" SEPARATOR);
	print_hostlog (addr);
	printf ("-------------------------------------------------" SEPARATOR);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION print_info_xml (info)                                            *
 * ------------------------------                                            *
 * Prints contens of a netload_info struct in XML format.                    *
\* ------------------------------------------------------------------------- */
void print_info_xml (netload_info *inf, unsigned long host, unsigned int dt,
					 int offs)
{
	int i;
	char astr[32];

	printip (host, astr);
	
	printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
	printf ("<host xmlns=\"http://opensource.xlshosting.com/n2/xmlns/host/1\" "
			"addr=\"%s\" date=\"%u\" offset=\"%u\">\n",
			 astr, dt, offs);
	
	printf ("  <hostname>%s</hostname>\n", inf->hostname);
	printf ("  <status>%s</status>\n", STR_STATUS[inf->status & 15]);
	printf ("  <flags>\n");
	printf ("    <rtt>%i</rtt>\n", CHKSTATUSFLAG(inf->status,FLAG_RTT));
	printf ("    <loss>%i</loss>\n", CHKSTATUSFLAG(inf->status,FLAG_LOSS));
	printf ("    <load>%i</load>\n", CHKSTATUSFLAG(inf->status,FLAG_LOAD));
	printf ("    <ram>%i</ram>\n", CHKOFLAG(inf->oflags,OFLAG_RAM));
	printf ("    <swap>%i</swap>\n", CHKOFLAG(inf->oflags,OFLAG_SWAP));
	printf ("    <netin>%i</netin>\n", CHKOFLAG(inf->oflags,OFLAG_NETIN));
	printf ("    <netout>%i</netout>\n", CHKOFLAG(inf->oflags,OFLAG_NETOUT));
	printf ("    <svcdown>%i</svcdown>\n", CHKOFLAG(inf->oflags,OFLAG_SVCDOWN));
	printf ("    <diskio>%i</diskio>\n", CHKOFLAG(inf->oflags,OFLAG_DISKIO));
	printf ("    <diskspace>%i</diskspace>\n", CHKOFLAG(inf->oflags,OFLAG_DISKSPACE));
	printf ("    <decoding>%i</decoding>\n", CHKOFLAG(inf->oflags,OFLAG_DECODINGERR));
	printf ("    <acked>%i</acked>\n", CHKOFLAG(inf->oflags,OFLAG_ACKED));
	printf ("    <other>%i</other>\n", CHKSTATUSFLAG(inf->status,FLAG_OTHER));
	printf ("  </flags>\n");
	printf ("  <uptime>%i</uptime>\n", inf->uptime);
	printf ("  <os>%s</os>\n", STR_OS[inf->ostype & 15]);
	printf ("  <hardware>%s</hardware>\n", STR_HW[inf->hwtype & 15]);
	
	if (inf->services)
	{
		printf ("  <services>\n");
		for (i=0; i<32; ++i)
		{
			if (inf->services & (1 << i))
			{
				printf ("    <service>%s</service>\n", STR_SVC[i]);
			}
		}
		printf ("  </services>\n");
	}
	else
	{
		printf ("  <services/>\n");
	}
	
	printf ("  <loadavg>%3.2f</loadavg>\n",
			(double) inf->load1 / 100.0);
	
	printf ("  <percentcpu>%3.2f</percentcpu>\n",
			(double) inf->cpu/2.55);
			
	printf ("  <processcount running=\"%i\">%i</processcount>\n",
			inf->nrun, inf->nproc);
	
	printf (" <iowait>%i</iowait>\n", inf->iowait);
	
	if (inf->kmemtotal)
	{
		printf ("  <mbtotalram>%.2f</mbtotalram>\n",
								((float)inf->kmemtotal)/1024.0);
	}
		
	printf ("  <mbfreeram>%.2f</mbfreeram>\n",
			((float)inf->kmemfree)/1024.0);
			
	printf ("  <mbfreeswap>%.2f</mbfreeswap>\n",
			((float)inf->kswapfree)/1024.0);
			
	printf ("  <netin>%i</netin>\n", inf->netin);
	printf ("  <netout>%i</netout>\n", inf->netout);
	printf ("  <diskio>%i</diskio>\n", inf->diskio);
	printf ("  <rtt>%.1f</rtt>\n", (double) inf->ping10 / 10.0);
	printf ("  <packetloss>%.2f</packetloss>\n",
			(double) inf->loss/100.0);

	if (inf->nmounts)
	{
		printf ("  <mounts>\n");
		for (i=0; i<inf->nmounts; ++i)
		{
			if (inf->mounts[i].usage > 1000)
			{
				printf ("    <mount fstype=\"%s\" size=\"%i\" usage=\"100\""
						" error=\"1\">%s</mount>\n",
						inf->mounts[i].fstype,
						inf->mounts[i].size,
						inf->mounts[i].mountpoint);
			}
			else
			{
				printf ("    <mount fstype=\"%s\" size=\"%i\" "
						"usage=\"%.02f\">%s</mount>\n",
						inf->mounts[i].fstype,
						inf->mounts[i].size,
						(double) inf->mounts[i].usage / 10.0,
						inf->mounts[i].mountpoint);
			}
		}
		printf ("  </mounts>\n");
	}
	else printf ("  <mounts/>\n");
	
	if (inf->ntop)
	{
		printf ("  <processes>\n");
		for (i=0; i<inf->ntop; ++i)
		{
			printf ("    <process id=\"%i\" user=\"%s\" "
					"usage=\"%.2f\" memusage=\"%.2f\">%s</process>\n",
					inf->tprocs[i].pid,
					inf->tprocs[i].username,
					(double) inf->tprocs[i].pcpu / 100.0,
					(double) inf->tprocs[i].pmem / 100.0,
					inf->tprocs[i].ptitle);
		}
		printf ("  </processes>\n");
	}
	else printf ("  <processes/>\n");
	
	if (inf->nports)
	{
		printf ("  <ports>\n");
		for (i=0; i<inf->nports; ++i)
		{
			printf ("    <port num=\"%i\" connected=\"%i\" "
					"other=\"%i\"/>\n",
					inf->ports[i].port, inf->ports[i].nestab,
					inf->ports[i].nother);
		}
		printf ("  </ports>\n");
	}
	else printf ("  <ports/>\n");
	
	if (inf->ntty)
	{
		printf ("  <ttys>\n");
		for (i=0; i<inf->ntty; ++i)
		{
			printip (inf->ttys[i].host, astr); 
			printf ("    <tty line=\"%s\" username=\"%s\" host=\"%s\"/>\n",
					inf->ttys[i].line, inf->ttys[i].username, astr);
		}
		printf ("  </ttys>\n");
	}
	else printf ("  <ttys/>\n");
	
	if (inf->nhttp)
	{
		printf ("  <http>\n");
		for (i=0; i<inf->nhttp; ++i)
		{
			printf ("    <vhost id=\"%s\">%i</vhost>\n",
					inf->http[i].vhost, inf->http[i].count);
		}
		printf ("  </http>\n");
	}
	else printf ("  <http/>\n");
	
	if (inf->nxenvps)
	{
		printf ("  <xenvps>\n");
		for (i=0; i<inf->nxenvps; ++i)
		{
			if (inf->xenvps[i].id[0] == 0) continue;
			
			printf ("    <vps id=\"%s\" cpu=\"%i\" mem=\"%i\" "
					"iops=\"%i\"/>\n", inf->xenvps[i].id,
					inf->xenvps[i].pcpu,
					inf->xenvps[i].memory,
					inf->xenvps[i].iops);
		}
		printf ("  </xenvps>\n");
	}
	else printf ("  <xenvps/>\n");
	
	print_hostlog_xml (host);
	printf ("</host>\n");
}
