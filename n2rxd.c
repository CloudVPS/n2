#include "datatypes.h"
#include "n2config.h"
#include "n2acl.h"
#include "n2ping.h"
#include "n2encoding.h"
#include "n2diskdb.h"
#include "n2hostlog.h"
#include "hcache.h"
#include "n2malloc.h"
#include "iptypes.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <stdarg.h>
#include <dirent.h>
#include <stdlib.h>
#include <strings.h>

time_t STARTTIME;

extern const char *STR_STATUS[];

#ifdef DEBUG
 #define dprintf printf
#else
 #define dprintf //
#endif

typedef struct netload_queued_pkt_struc
{
	unsigned char data[640];
	size_t psize;
	struct sockaddr_in remote_addr;
} netload_queued_pkt;

typedef struct netload_queue_struc
{
	netload_queued_pkt queue[4096];
	volatile unsigned int rpos;
	volatile unsigned int wpos;
	pthread_mutexattr_t attr;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_attr_t tattr;
	pthread_t      thread;
} netload_queue;

typedef struct netload_logmeta_struc
{
	FILE *f;
	pthread_mutexattr_t attr;
	pthread_mutex_t mutex;
} netload_logmeta;

int				 UDPSOCK;
netload_queue	 QUEUE;
netload_logmeta	 LOG;

void			 populate_cache (hcache *);
int				 check_alert_status (unsigned long, netload_info *,
									 status_t, acl *, hcache_node *);
void			 systemlog (const char *, ...);
void			 statuslog (unsigned int, const char *, ...);
void			 errorlog (unsigned int, const char *);
void			 eventlog (unsigned int, const char *);
void			 handle_status_change (unsigned long, status_t, status_t);
void			 udp_receive_thread (void *param);

void			 daemonize (void);
void			 huphandler (int);

/* ------------------------------------------------------------------------- *\
 * FUNCTION udp_queue_init                                                   *
 * -----------------------                                                   *
 * Initializes the global netload_queue instance and creates the background  *
 * thread. The global UDP socket SOCK should already be initialized and      *
 * listening before calling this function.                                   *
\* ------------------------------------------------------------------------- */
void udp_queue_init (void)
{
	bzero (&QUEUE, sizeof(QUEUE));
	pthread_mutexattr_init (&QUEUE.attr);
	pthread_mutex_init (&QUEUE.mutex, &QUEUE.attr);
	pthread_cond_init (&QUEUE.cond, NULL);
	
	pthread_attr_init (&QUEUE.tattr);
	pthread_create (&QUEUE.thread, &QUEUE.attr, udp_receive_thread, NULL);
}

void log_init (void)
{
	if (CONF.log != LOG_NONE)
	{
		LOG.f = fopen (CONF.logfile, "a");
	}
	else
	{
		LOG.f = NULL;
	}
	
	pthread_mutexattr_init (&LOG.attr);
	pthread_mutex_init (&LOG.mutex, &LOG.attr);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION udp_receive_thread                                               *
 * ---------------------------                                               *
 * This function will run inside a background thread. It is responsible for  *
 * getting packet data out of the udp socket as soon as possible.            *
\* ------------------------------------------------------------------------- */
void udp_receive_thread (void *param)
{
	int rsize = sizeof (struct sockaddr_in);
	int backlog;
	int errcnt = 0;
	
	while (1)
	{
		bzero (QUEUE.queue + QUEUE.wpos, sizeof (netload_queued_pkt));
		QUEUE.queue[QUEUE.wpos].psize = 
			recvfrom (UDPSOCK, QUEUE.queue[QUEUE.wpos].data, 640, 0,
					  (struct sockaddr *) &(QUEUE.queue[QUEUE.wpos].remote_addr),
					  &rsize);
		
		if (QUEUE.queue[QUEUE.wpos].psize > 25)
		{
			QUEUE.wpos = (QUEUE.wpos+1) & 4095;
			
			backlog = QUEUE.wpos - QUEUE.rpos;
			if (backlog < 0) backlog += 4096;
			
			if (backlog > 128)
			{
				if (! (errcnt & 31))
				{
					systemlog ("UDP receiver backlog: %i", backlog);
				}
				errcnt++;
			}
			
			pthread_mutex_lock (&QUEUE.mutex);
			pthread_cond_signal (&QUEUE.cond);
			pthread_mutex_unlock (&QUEUE.mutex);
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION udp_read_packet                                                  *
 * ------------------------                                                  *
 * Reads a packet off the packet queue created by the receiver thread. The   *
 * queue has a read- and write-cursor. If both point to the same location,   *
 * this function will wait on the queue's pthread conditional.               *
\* ------------------------------------------------------------------------- */
size_t udp_read_packet (unsigned char *data, struct sockaddr_in *addr)
{
	size_t res;
	while (QUEUE.wpos == QUEUE.rpos)
	{
		pthread_mutex_lock (&QUEUE.mutex);
		pthread_cond_wait (&QUEUE.cond, &QUEUE.mutex);
		pthread_mutex_unlock (&QUEUE.mutex);
	}
	
	memcpy (data, QUEUE.queue[QUEUE.rpos].data, 640);
	memcpy (addr, &(QUEUE.queue[QUEUE.rpos].remote_addr), sizeof(struct sockaddr_in));
	res = QUEUE.queue[QUEUE.rpos].psize;
	QUEUE.rpos = (QUEUE.rpos + 1) & 4095;
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION save_mangled_packet                                              *
 * ----------------------------                                              *
 * Write contents of a packet to /var/state/n2/mangled_packet.               *
\* ------------------------------------------------------------------------- */
void save_mangled_packet (netload_pkt *pkt)
{
	FILE *f;
	f = fopen ("/var/state/n2/mangled_packet", "w");
	if (! f) return;
	fwrite (pkt->data, 640, 1, f);
	fclose (f);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION handle_packet                                                    *
 * ----------------------                                                    *
 * Do all necessary handling for a single n2 packet.                         *
\* ------------------------------------------------------------------------- */
void handle_packet (netload_pkt *pkt, unsigned long rhost,
					hcache *cache, size_t psize,
					netload_info *info, acl *cacl)
{
	ping_log *plog; 				/* Pointer for the ping log array */
	unsigned short pingtime; 		/* Host's calculated pingtime */
	unsigned short packetloss; 		/* Host's calculated packet loss */
	time_t hosttime; 				/* The unix time local to the host */
	time_t lasttime;
	unsigned int uptime;			/* The host's recorded uptime */
	status_t status; 				/* Status of the current host */
	oflag_t oflags;					/* Extended problem flags */
	char str[256];					/* Generic string buffer */
	netload_rec *rec; 				/*  Disk record (address equals pkt) */
	unsigned int services;			/* Services flags */
	unsigned int oldservices;		/* Previous services flags */
	int i;
	hcache_node *cnode;
	unsigned char isfresh = 0;

	/* gather pingdata */
	plog = read_ping_data (rhost);
	if (plog != NULL)
	{
		pingtime = calc_ping10 (plog);
		packetloss = calc_loss (plog);
		if (packetloss != 0)
		{
			sprintf (str, "packetloss %i", packetloss);
			eventlog (rhost, str);
		}
		pool_free (plog);
	}
	else /* No ping data available; make shit up */
	{
		pingtime = 0;
		packetloss = 0;
	}
	
	/* extract the host's local idea of time(NULL) */
	hosttime = pkt_get_hosttime (pkt);
	uptime = pkt_get_uptime (pkt);
	services = pkt_get_services (pkt);
	
	cnode = hcache_resolve (cache, rhost);
	if (cnode->isfresh) isfresh = 1;
	lasttime = hcache_getlast (cache, rhost);
	
	if (time(NULL) - STARTTIME < 60) isfresh = 1;
	
	/* Only consider newer data */
	if (hosttime > lasttime)
	{
		/* Update the timestamp in the cache */
		hcache_setlast (cache, rhost, hosttime);
		status = hcache_getstatus (cache, rhost);
		oflags = hcache_getoflags (cache, rhost);
		oldservices = hcache_getservices (cache, rhost);
		
		if (RDSTATUS(status) >= ST_STALE)
		{
			handle_status_change(rhost, RDSTATUS(status), ST_OK);
			status = ST_OK;
			hcache_setstatus (cache, rhost, ST_OK);
		}
		
		if (uptime < hcache_getuptime (cache, rhost))
		{
			if (uptime < 600)
			{
				handle_status_change(rhost, status, ST_STARTUP_1);
				status = ST_STARTUP_1;
				statuslog (rhost, "Reboot detected");
				hostlog (rhost, status, status, oflags, "Reboot detected");
				cnode->alertlevel = 0;
			}
			else if (uptime != 982800 || /* overlap in the transition */
					 hcache_getuptime (cache,rhost) != 982980)
			{
				sprintf (str, "Time wibble detected, "
						 "uptime %u < %u",
						 uptime,
						 hcache_getuptime (cache, rhost));
				
				statuslog (rhost, str);
				hostlog (rhost, status, status, oflags, str);
			}
		}
		
		hcache_setuptime (cache, rhost, uptime);
		hcache_setservices (cache, rhost, services);
		
		if ((services != oldservices) &&
		    (RDSTATUS(status) >= ST_OK) &&
		    (isfresh == 0))
		{
			for (i=0; i<32; ++i)
			{
				if ( ((oldservices & (1<<i)) == 0) &&
				     ((services & (1<<i)) != 0) )
				{
					sprintf (str, "Service %s started", get_servicename(i));
					hostlog (rhost, status, status, oflags, str);
					statuslog (rhost, str);
				}
				else if ( ((oldservices & (1<<i)) != 0) && 
						  ((services & (1<<i)) == 0) )
				{
					sprintf (str, "Service %s stopped", get_servicename(i));
					hostlog (rhost, status, status, oflags, str);
					statuslog (rhost, str);
				}
			}
		}
		
		
		/* The startp status should evolve into OK */
		if (RDSTATUS(status) < ST_OK)
		{
			++status;
			hcache_setstatus (cache, rhost, status);
			if (RDSTATUS(status) == ST_OK)
			{
				statuslog (rhost, "Host back to normal");
				hostlog (rhost, status-1, status, oflags,
						 "Host back to normal");
			}
		}
		
		/* turn packet into a record */
		pkt->pos = psize;
		rec = encode_rec (pkt, time (NULL), status,
						  pingtime, packetloss, oflags);
	
		/* Write the record to disk. This may be redundant,
		   but it will at least guarantee us a saved
		   packet if something screws up with the decoding
		   process. */
		   
		diskdb_setcurrent (rhost, rec);
		
		/* decode the record so we can check for alerts */
		if (decode_rec_inline (rec, info))
		{
			/* check_alert_status will set specific alert
			   information in the netload_info record and
			   return a true if the status was changed from
			   our existing status. */
			
			if (check_alert_status (rhost, info, status, cacl, cnode))
			{
				/* Keep quiet about ST_STARTUP issues */
				if (RDSTATUS(info->status) >= ST_OK)
				{
					hostlog (rhost, status, info->status, info->oflags,
							 "Host changed status");
					statuslog (rhost, "Status changed to %s",
							   STR_STATUS[info->status & 15]);
					handle_status_change(rhost, status, info->status);
				}
				
				/* Store the new status in the cache */
				hcache_setstatus (cache, rhost, info->status);
				hcache_setoflags (cache, rhost, info->oflags);
				
				/* Change the status byte inside the disk
				   record, then write the record back with
				   the new information */
				rec_set_status (rec, info->status);
				rec_set_oflags (rec, info->oflags);
				diskdb_setcurrent (rhost, rec);
			}
			else
			{
				rec_set_status (rec, info->status);
				rec_set_oflags (rec, info->oflags);
				if (info->oflags != oflags)
				{
					diskdb_setcurrent (rhost, rec);
				}
				
			}
			
			sprintf (str, "Recv packet size=%i "
						  "status=%s",
						  rec->pos,
						  STR_STATUS[info->status & 15]);
			eventlog (rhost, str);
		}
		else /* validated */
		{
			save_mangled_packet (pkt);
			errorlog (rhost, "Mangled packet");
		}
	}
	else /* hosttime > hcache_getlast() */
	{
		if (((hosttime & 0x00ffff00) == 0) &&
			((lasttime & 0x00ffff00) != 0))
		{
			/* perfectly normal clock wrap */
		}
		else if (hosttime < lasttime)
		{
			sprintf (str, "Illegal backwards timestamp, "
					 "%u < %u",
					 hosttime,
					 hcache_getlast (cache, rhost));
			errorlog (rhost, str);
		}
	}
}


/* ------------------------------------------------------------------------- *\
 * FUNCTION main                                                             *
 * -------------                                                             *
 * Sets up the listening socket and handles incoming packets.                *
\* ------------------------------------------------------------------------- */
int main (int argc, char *argv[])
{
	struct sockaddr_in listen_addr; /* For the listening socket */
	struct sockaddr_in remote_addr; /* To keep track of the remote address */
	
	time_t ti; 						/* Current time */
	time_t lastclean; 				/* Time of last stale host check */
	int i; 							/* Generic counter */
	char str[256];					/* Generic string buffer */
	
	netload_info *info; 			/* Extracted data for a node */
	netload_pkt *pkt; 				/* Storage for received packet */
	netload_rec *rec; 				/*  Disk record (address equals pkt) */
	ping_log *plog; 				/* Pointer for the ping log array */
	acl *cacl; 						/* monitor-group matching the host */
	size_t psize; 					/* The received packet size */
	
	unsigned short pingtime; 		/* Host's calculated pingtime */
	unsigned short packetloss; 		/* Host's calculated packet loss */
	unsigned long rhost;			/* Host ip address in host order */
	int validated; 					/* Validity of the packet MD5 checksum */
	
	hcache *cache; 					/* Pointer to the hostcache root */
	hcache_node *ccrsr; 			/* Cursor-pointers if we want to graze */
	hcache_node *cnext; 			/* through the cache for something */
	
	STARTTIME = time (NULL);
	
	/* Initialize all the configuration stuff */
	acl_init ();
	conf_init ();
	
	/* Create the host cache */
	cache = (hcache *) calloc (1, sizeof (hcache));
	
	/* Somehow repeatedly doing a calloc() and free() on an info structure
	   makes the RSS/VSZ grow like a giraffe on hormones, so we allocate
	   this baby once and clean it between rounds. Easier on the brk()s */
	info = (netload_info *) calloc (1, sizeof (netload_info));
	
	/* Load the configuration file */
	load_config ("/etc/n2/n2rxd.conf");
	
	/* Handle SIGHUP (will reload config) */
	signal (SIGHUP, huphandler);
	
	/* This will keep the reaper off our backs for the first 15 seconds */
	lastclean = time (NULL);

	log_init ();
	
	/* FIXME: stupid n2config fills in a default so this is no way to
	          spot a missing configfile */
	if (! CONF.listenport)
	{
		fprintf (stderr, "%% Could not load/parse /etc/n2/n2rxd.conf\n");
		return 1;
	}
	
	/* If there is a specific listen address, set it up */
	if (CONF.listenaddr)
	{
		listen_addr.sin_addr.s_addr = htonl (CONF.listenaddr);
	}
	else
	{
		/* Listen to INADDR_ANY */
		listen_addr.sin_addr.s_addr = INADDR_ANY;
	}
	
	listen_addr.sin_port = htons (CONF.listenport);
	
	/* Create the socket and bind it */
	UDPSOCK = socket (AF_INET, SOCK_DGRAM, 0);
	if (bind (UDPSOCK,(struct sockaddr *) &listen_addr, sizeof(listen_addr))!= 0)
	{
		fprintf (stderr, "%% Error creating udp listener\n");
		exit (1);
	}
	
	/* Fork into the background (unless if compiled with debugging) */
	daemonize ();
	
	/* Tell the world our happy news */
	systemlog ("Daemon started pid=%u", getpid());
	
	populate_cache (cache);
	systemlog ("Cache populated");
	
	udp_queue_init ();
	systemlog ("Receiver thread initialized");
	
	/* Here the main loop starts */
	while (1)
	{
		if (config_changed) /* The SIGHUP handler will set this */
		{
			systemlog ("Reloading configuration");
			acl_clear ();
			load_config ("/etc/n2/n2rxd.conf");
			config_changed = 0;
		}
		
		/* Allocate a fresh netload_pkt structure */
		pkt = (netload_pkt *) calloc (1, sizeof (netload_pkt));
		pkt->pos = 0;
		pkt->rpos = 0;
		pkt->eof = 0;
		cacl = NULL;
		
		/* Suck a packet off the wire */
		psize = udp_read_packet (pkt->data, &remote_addr);
		
		/* Store the peer address data */
		rhost = ntohl (remote_addr.sin_addr.s_addr);
		rhost = translate_alias (rhost);
		
		/* Packet should be larger than the minimum size */
		if (psize > 25)
		{
			pkt->pos = psize;
			
			/* Look up the IP address in the configuration */
			
			cacl = acl_match (rhost);
			if (cacl)
			{
				/* Validate the MD5 key */
				validated = validate_pkt (pkt, cacl->key);
				if (validated)
				{
					handle_packet (pkt, rhost, cache, psize, info, cacl);
				}
				else /* validated */
				{
					errorlog (rhost, "Authentication error on packet");
				}
			}
			else /* cacl */
			{
				errorlog (rhost, "Received message from unconfigured host");
			}
		}
		else /* psize > 25 */
		{
			errorlog (rhost, "Short packet received");
		}
		
		free (pkt);
		
		/* About once every 15 seconds we go through all the nodes in the
		   cache to scan for dead wood. While we're at it, we will also
		   update the rtt/loss information for any hosts we find that
		   haven't been updated in the last 15 seconds */
		   
		ti = time (NULL);
		if ((ti - lastclean) > 14)
		{
			eventlog (0, "Starting garbage collection round");
			lastclean = ti;
			
			/* Go over the hash buckets */
			for (i=0; i<256; ++i)
			{
				ccrsr = cache->hash[i];
				while (ccrsr) /* Iterate over the cache nodes */
				{
					if ((ti - ccrsr->lastseen) > 90) /* It's dead, Jim */
					{
						/* Update the disk record with the status and ping
						   information */
						
						rec = diskdb_get_current ((unsigned long) ccrsr->addr);
						if (! rec)
						{
							ccrsr = ccrsr->next;
							continue;
						}

						if (RDSTATUS(ccrsr->status) < ST_STALE)
						{
							/* And we didn't know it was stale yet */
							errorlog ((unsigned long) ccrsr->addr,
									  "Status changed to STALE");
							hostlog (ccrsr->addr, ccrsr->status, ST_STALE, 0,
									 "Host went stale");
							handle_status_change (ccrsr->addr, ccrsr->status,
												  ST_STALE);
							ccrsr->status = ST_STALE;
							rec_set_status (rec, ST_STALE);
						}
						
						plog = read_ping_data ((unsigned long) ccrsr->addr);
						if (plog)
						{
							pingtime = calc_ping10 (plog);
							packetloss = calc_loss (plog);
							rec_set_ping10 (rec, pingtime);
							rec_set_loss (rec, packetloss);
							if (packetloss == 10000)
							{
								rec_set_status (rec, ST_DEAD);
								if (RDSTATUS(ccrsr->status) < ST_DEAD)
								{
									hostlog (ccrsr->addr, ST_STALE, ST_DEAD, 0,
											 "Full packet loss");
									errorlog (ccrsr->addr, "Status changed "
														   "to DEAD");
									handle_status_change (ccrsr->addr,
														  ccrsr->status,
														  ST_DEAD);
									ccrsr->status = ST_DEAD;
								}
							}
							else
							{
								if (ccrsr->status == ST_DEAD)
								{
									errorlog (ccrsr->addr, "Status changed "
											  "back to STALE");
									hostlog (ccrsr->addr, ST_DEAD, ST_STALE, 0,
											 "Ping traffic recovering");
									rec_set_status (rec, ST_STALE);
									ccrsr->status = ST_STALE;
								}
							}
							pool_free (plog);
						}
						else
						{
							rec_set_ping10 (rec, 0);
							rec_set_loss (rec, 10000);
						}
						/* Store the updated data back on disk */
						diskdb_setcurrent (ccrsr->addr, rec);
						free (rec);
					}
					else if ((ti - ccrsr->lastseen) > 14)
					{
						/* Get new ping data */
						rec = diskdb_get_current ((unsigned long) ccrsr->addr);
						plog = read_ping_data ((unsigned long) ccrsr->addr);
						
						if (! rec)
						{
							ccrsr = ccrsr->next;
							continue;
						}
						
						if (plog)
						{
							pingtime = calc_ping10 (plog);
							packetloss = calc_loss (plog);
							rec_set_ping10 (rec, pingtime);
							rec_set_loss (rec, packetloss);
							pool_free (plog);
						}
						else
						{
							rec_set_ping10 (rec, 0);
							rec_set_loss (rec, 10000);
						}
						
						/* Store it back in the disk database */
						diskdb_setcurrent (ccrsr->addr, rec);
						free (rec);
					}
					ccrsr = ccrsr->next;
				}
			}
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION is_alert_state                                                   *
 * -----------------------                                                   *
 * Returns 1 for any status_t that is ST_ALERT or worse.                     *
\* ------------------------------------------------------------------------- */
int is_alert_state (status_t s)
{
	if (s == ST_ALERT || s == ST_CRITICAL || s == ST_DEAD || s == ST_STALE)
		return 1;
		
	return 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION handle_status_change                                             *
 * -----------------------------                                             *
 * Propagate status changtes to n2event / n2notifyd.                         *
\* ------------------------------------------------------------------------- */
void handle_status_change (unsigned long rhost, status_t olds, status_t news)
{
	status_t oldstatus, newstatus;
	char cmd[256];
	char ip[64];
	const char *event;
	int i;
	
	oldstatus = RDSTATUS(olds);
	newstatus = RDSTATUS(news);
	
	if (newstatus == ST_STARTUP_1)
	{
		event = "recovery";
	}
	else if (is_alert_state (oldstatus))
	{
		if (! is_alert_state (newstatus))
		{
			event = "recovery";
		}
		else return;
	}
	else
	{
		if (is_alert_state (newstatus))
		{
			event = "problem";
		}
		else return;
	}
	
	printip (rhost, ip);
	sprintf (cmd, "/usr/bin/n2event %s %s >/dev/null </dev/null", ip, event);
	i = system (cmd);
	systemlog ("%s: Sent change notification: %x", ip, i);
}

#define setMinimum(foo) { if (RDSTATUS(info->status) < foo) \
	info->status = MKSTATUS(info->status,foo); }

/* ------------------------------------------------------------------------- *\
 * FUNCTION check_alert_status (rhost, info, oldstatus, acl)                 *
 * ---------------------------------------------------------                 *
 * Determines any configured alert levels for a host and sees whether that   *
 * is different from the previous alert state provided to the function.      *
\* ------------------------------------------------------------------------- */
int check_alert_status (unsigned long rhost,
						netload_info *info,
						status_t oldstatus,
						acl *cacl,
						hcache_node *hcnode)
{
	int hadalert = 0;
	int hadwarning = 0;
	unsigned short rtt = info->ping10;
	unsigned short loss = info->loss;
	unsigned short loadavg = info->load1;
	unsigned int maxlevel;
	int i;
	
	CLRSTATUSFLAG(info->status,FLAG_LOSS);
	CLRSTATUSFLAG(info->status,FLAG_RTT);
	CLRSTATUSFLAG(info->status,FLAG_LOAD);
	CLRSTATUSFLAG(info->status,FLAG_OTHER);
	info->oflags = 0;
	
	/* Disregard if we're still in the ST_STARTUP range m'kay? */
	if (RDSTATUS(info->status) < ST_OK) return 0;
	
	/* We only get here if we're evaluating a received packet, so in
	   case of a stale host, this is a de facto resurrection and
	   we should kick the machine back into the startup state to
	   give it some time to get readjusted. */
	if (RDSTATUS(info->status) >= ST_STALE)
	{
		errorlog (rhost, "Host back from the dead");
		hostlog (rhost, info->status, ST_STARTUP_1, 0,
					"Host back from the dead");
		info->status = ST_OK;
		return 1;
	}
	
	/* We define two macros for all the flag handling, one for those
	   that trigger a major flag and one for those inside the realm
	   of FLAG_OTHER. Both have the same list of arguments:
	   
	      xtype: The acl value name to check (rtt,loadavg,loss,etc,...)
	      xdir: The direction of the comparison (over|under)
	      xvar: The variable of the current situation
	      xflag: The flag/oflag (FLAG_RTT,OFLAG_SWAP)
	*/
	#define ACLHANDLE_FLAG(xtype,xdir,xvar,xflag) \
		if (acl_is ## xdir ## _ ## xtype ## _alert (cacl,xvar)) \
		{ \
			SETSTATUSFLAG(info->status,xflag); \
			hadalert++; \
		} \
		else if (acl_is ## xdir ## _ ## xtype ## _warning (cacl,xvar)) \
		{ \
			SETSTATUSFLAG(info->status,xflag); \
			hadwarning++; \
		}

	#define ACLHANDLE_OFLAG(xtype,xdir,xvar,xflag) \
		if (acl_is ## xdir ## _ ## xtype ## _alert (cacl,xvar)) \
		{ \
			SETSTATUSFLAG(info->status,FLAG_OTHER); \
			SETOFLAG(info->oflags,xflag); \
			hadalert++; \
		} \
		else if (acl_is ## xdir ## _ ## xtype ## _warning (cacl,xvar)) \
		{ \
			SETSTATUSFLAG(info->status,FLAG_OTHER); \
			SETOFLAG(info->oflags,xflag); \
			hadwarning++; \
		}

	ACLHANDLE_FLAG(loss,over,loss,FLAG_LOSS);
	ACLHANDLE_FLAG(rtt,over,rtt,FLAG_RTT);
	ACLHANDLE_FLAG(loadavg,over,loadavg,FLAG_LOAD);
	ACLHANDLE_OFLAG(ram,under,info->kmemfree,OFLAG_RAM);
	ACLHANDLE_OFLAG(swap,under,info->kswapfree,OFLAG_SWAP);
	ACLHANDLE_OFLAG(netin,over,info->netin,OFLAG_NETIN);
	ACLHANDLE_OFLAG(netout,over,info->netout,OFLAG_NETOUT);
	ACLHANDLE_OFLAG(diskio,over,info->diskio,OFLAG_DISKIO);

	#ifdef DEBUG
		printf ("diskio %i warning %i alert %i\n",
				info->diskio, acl_get_diskio_warning (cacl),
				acl_get_diskio_alert (cacl));
		printf ("diskspace warning %i alert %i\n",
				acl_get_diskspace_warning (cacl),
				acl_get_diskspace_alert (cacl));
		printf ("io %i space %i\n", info->oflags & OFLAG_DISKIO,
				info->oflags & OFLAG_DISKSPACE);
		printf ("status %08x oflags %08x\n", info->status,info->oflags);
	#endif

	/* Be more lenient about CPU, basically don't recognize it as
	   an ALERT event ever */
	if (acl_isover_cpu_alert (cacl,info->cpu))
	{
		SETSTATUSFLAG(info->status,FLAG_LOAD);
		hadwarning++;
	}
	else if (acl_isover_cpu_warning (cacl,info->cpu))
	{
		SETSTATUSFLAG(info->status,FLAG_LOAD);
		hadwarning++;
	}
	
	for (i=0; i < info->nmounts; ++i)
	{
		if (acl_isover_diskspace_alert (cacl,info->mounts[i].usage))
		{
			#ifdef DEBUG
				printf ("mount %i usage %i alert %i\n", i,
						info->mounts[i].usage,
						acl_get_diskspace_alert (cacl));
			#endif
			SETSTATUSFLAG(info->status,FLAG_OTHER);
			SETOFLAG(info->oflags,OFLAG_DISKSPACE);
			hadalert++;
		}
		else if (acl_isover_diskspace_warning (cacl,info->mounts[i].usage))
		{
			#ifdef DEBUG
				printf ("mount %i usage %i warn %i\n", i,
						info->mounts[i].usage,
						acl_get_diskspace_warning (cacl));
			#endif
			SETSTATUSFLAG(info->status,FLAG_OTHER);
			SETOFLAG(info->oflags,OFLAG_DISKSPACE);
			hadwarning++;
		}
	}

	if ((hadwarning == 0) && (hadalert == 0))
	{
		if (hcnode->alertlevel > 12)
		{
			hcnode->alertlevel = hcnode->alertlevel >> 1;
		}
		else hcnode->alertlevel = 0;
	}
	else
	{
		if (hadalert > 1) maxlevel = 50;
		else if (hadalert > 0) maxlevel = 35;
		else maxlevel = 20;
		
		if (hcnode->alertlevel < maxlevel)
		{
			hcnode->alertlevel += hadwarning + 3 * hadalert;
			if (hcnode->alertlevel > maxlevel)
			{
				hcnode->alertlevel = maxlevel;
			}
		}
		else hcnode->alertlevel = maxlevel;
	}
	
	if (hcnode->alertlevel < 7) info->status = MKSTATUS(info->status,ST_OK);
	if (hcnode->alertlevel > 6) info->status = MKSTATUS(info->status,ST_WARNING);
	if (hcnode->alertlevel > 24) info->status = MKSTATUS(info->status,ST_ALERT);
	if (hcnode->alertlevel > 40) info->status = MKSTATUS(info->status,ST_CRITICAL);
	
	/* Determine if we changed the status */
	if (RDSTATUS(info->status) != RDSTATUS(oldstatus))
	{
		return 1;
	}
	return 0;
}

/* easy macro to get an octet out of a 32 bit unsigned int or some such */
#define BYTE(qint,qbyt) ((qint >> (8*qbyt)) & 0xff)

/* ------------------------------------------------------------------------- *\
 * FUNCTION systemlog (format, ...)                                          *
 * --------------------------------                                          *
 * If the logfile is open, write a generic system message to it.             *
\* ------------------------------------------------------------------------- */
void systemlog (const char *fmt, ...)
{
	va_list ap;
	char buffer[512];
	char tbuf[32];
	time_t t;
	
	if (! LOG.f) return;

	t = time (NULL);
	ctime_r (&t, tbuf);
	tbuf[24] = 0;
	
	va_start (ap, fmt);
	vsnprintf (buffer, 512, fmt, ap);
	va_end (ap);

	pthread_mutex_lock (&LOG.mutex);
	fprintf (LOG.f, "%%SYS%% %s %s\n", tbuf, buffer);
	fflush (LOG.f);
	pthread_mutex_unlock (&LOG.mutex);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION statuslog (host, format, ...)                                    *
 * --------------------------------------                                    *
 * If the logfile is open, write a host status message to it.                *
\* ------------------------------------------------------------------------- */
void statuslog (unsigned int host, const char *fmt, ...)
{
	va_list ap;
	char buffer[512];
	char tbuf[32];
	time_t t;
	
	/* Bail if the logfile is not open */
	if (! LOG.f) return;

	/* Format the date string */
	t = time (NULL);
	ctime_r (&t, tbuf);
	tbuf[24] = 0;
	
	/* Parse varargs */
	va_start (ap, fmt);
	vsnprintf (buffer, 512, fmt, ap);
	va_end (ap);

	/* Write to file */
	pthread_mutex_lock (&LOG.mutex);
	fprintf (LOG.f, "%%STX%% %s %i.%i.%i.%i: %s\n", tbuf,
		     BYTE(host,3), BYTE(host,2), BYTE(host,1), BYTE(host,0),
			 buffer);
	fflush (LOG.f);
	pthread_mutex_unlock (&LOG.mutex);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION errorlog (host, text)                                            *
 * ------------------------------                                            *
 * If the logfile is open, and we are configured for this class, write a     *
 * host error message to it.                                                 *
\* ------------------------------------------------------------------------- */
void errorlog (unsigned int host, const char *crime)
{
	char tbuf[32];
	time_t t;

	/* Bail if the logfile is not open */
	if (! LOG.f) return;

	/* Only at the right loglevels */
	if ((CONF.log == LOG_MALFORMED) || (CONF.log == LOG_ALL))
	{
		/* Format the date string */
		t = time (NULL);
		ctime_r (&t, tbuf);
		tbuf[24] = 0;
	
		pthread_mutex_lock (&LOG.mutex);
		fprintf (LOG.f, "%%ERR%% %s %i.%i.%i.%i: %s\n", tbuf,
			     BYTE(host,3), BYTE(host,2), BYTE(host,1), BYTE(host,0),
			     crime);
		fflush (LOG.f);
		pthread_mutex_unlock (&LOG.mutex);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION eventlog (host, text)                                            *
 * ------------------------------                                            *
 * If the logfile is open, and we are configured for this class, write a     *
 * host event message to it.                                                 *
\* ------------------------------------------------------------------------- */
void eventlog (unsigned int host, const char *whatup)
{
	char tbuf[32];
	time_t t;


	/* Bail if the logfile is not open */
	if (! LOG.f) return;

	/* Only at the right loglevels */
	if ((CONF.log == LOG_EVENTS) || (CONF.log == LOG_ALL))
	{
		/* Format the date string */
		t = time (NULL);
		ctime_r (&t, tbuf);
		tbuf[24] = 0;
	
		pthread_mutex_lock (&LOG.mutex);
		fprintf (LOG.f, "%%EVT%% %s %i.%i.%i.%i: %s\n", tbuf,
			     BYTE(host,3), BYTE(host,2), BYTE(host,1), BYTE(host,0),
			     whatup);
		fflush (LOG.f);
		pthread_mutex_unlock (&LOG.mutex);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION huphandler (signal)                                              *
 * ----------------------------                                              *
 * SIGUP handler, sets the config_changed flag to trigger a configuration    *
 * reload after the next packet is handled.                                  *
\* ------------------------------------------------------------------------- */
void huphandler (int sig)
{
	config_changed = 1;
	signal (SIGHUP, huphandler);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION daemonize (void)                                                 *
 * -------------------------                                                 *
 * General utility function, sets the userid/groupid proper and forks into   *
 * the background, leaving behind a pid-file.                                *
\* ------------------------------------------------------------------------- */
void daemonize (void)
{
	pid_t pid1;
	pid_t pid2;
	FILE *pidfile;
	uid_t uid;
	gid_t gid;
	struct passwd *pwd;
	
	/* open pidfile with our original privileges */
	pidfile = fopen ("/var/run/n2rxd.pid","w");
	
	/* find desired uid/gid by looking up either n2 or bobody in pwdb */
	pwd = getpwnam ("n2");
	if (! pwd) pwd = getpwnam ("nobody");
	
	uid = pwd->pw_uid;
	gid = pwd->pw_gid;
	
	/* Set the uid and gid to the destination values */
	setregid (gid, gid);
	setreuid (uid, uid);

#ifdef DEBUG
	pid1 = getpid();
	fprintf (pidfile, "%u", pid1);
	fclose (pidfile);
	return;
#endif
	
	/* Do some forkery to daemonize ourselves proper */
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

/* ------------------------------------------------------------------------- *\
 * FUNCTION populate_cache (cache)                                           *
 * -------------------------------                                           *
 * Goes over the /var/state/n2/current directory to scoop up hosts that are  *
 * under watch. We run this at startup so that we can properly detect hosts  *
 * that fell off the map and mark them STALE.                                *
\* ------------------------------------------------------------------------- */
void populate_cache (hcache *cache)
{
	DIR *dir;
	struct dirent *de;
	char *name;
	unsigned int addr;
	time_t ti;
	netload_rec *rec;
	
	ti = time (NULL);

	dir = opendir ("/var/state/n2/current");
	if (! dir)
	{
		systemlog ("Could not open /var/state/n2/current");
		exit (1);
	}
	
	while (de = readdir (dir))
	{
		addr = atoip (de->d_name);
		if (addr)
		{
			rec = diskdb_get_current (addr);
			if (rec)
			{
				hcache_setlast (cache, addr, 0);
				hcache_setstatus (cache, addr, rec_get_status (rec));
				free (rec);
				rec = NULL;
			}
		}
	}
	closedir (dir);
}
