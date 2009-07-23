#ifdef DEBUG
 #define dprintf printf
#else
 #define dprintf //
#endif

#include "n2config.h"
#include "datatypes.h"
#include "n2encoding.h"
#include "n2malloc.h"
#include "n2stat.h"
#include "proctitle.h"
#include "tproc.h"
#include "xenvps.h"
#include "http_fetcher.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>

void daemonize (char **);
unsigned int huntservices (portlist *, procrun *);

int runroot;
void huphandler (int);

pid_t DAEMON_PID;

void write_packet (netload_pkt *pkt)
{
	FILE *F;
	umask (0077);
	if (! (F=fopen ("/var/run/n2txd.packet", "w"))) return;
	fwrite (pkt->data, 640, 1, F);
	fclose (F);
}

int interface_configured (const char *ifname)
{
	int i;
	if (! CONF.ifcount) return 1;
	for (i=0; i<CONF.ifcount; ++i)
	{
		if (! strcmp (CONF.interfaces[i].ifname, ifname)) return 1;
	}
	return 0;
}

void termhandler (int sig)
{
	kill (DAEMON_PID, SIGTERM);
	exit (0);
}

void add_modstatus_vhost (netload_info *inf, const char *h)
{
	char host[48];
	int i;
	
	strncpy (host, h, 48);
	host[47] = 0;
	
	for (i=0; i<inf->nhttp; ++i)
	{
		if (! strcasecmp (host, inf->http[i].vhost))
		{
			inf->http[i].count++;
			return;
		}
	}
	
	if (inf->nhttp < NR_HTTP)
	{
		strcpy (inf->http[inf->nhttp].vhost, host);
		inf->http[inf->nhttp].count = 1;
		inf->nhttp++;
	}
}

void gather_modstatus_apache2 (netload_info *inf, char *body)
{
	char *crsr;
	char *ecrsr;
	int i;
	
	dprintf ("mod_status apache2\n");
	
	crsr = strstr (body, "<tr");
	if (! crsr) return;
	crsr = strstr (crsr+3, "<tr");
	if (! crsr) return;
	
	while (crsr)
	{
		for (i=0; i<4; ++i)
		{
			crsr = strstr (crsr, "<td>");
			if (! crsr) return;
			crsr += 4;
		}
		if (strncmp (crsr, "<b>W</b>", 8) == 0)
		{
			crsr = strstr (crsr, "<td nowrap>");
			if (! crsr) return;
			crsr -= 14;
			if ( (strncmp (crsr, "127.0.0.1", 9) != 0) &&
			     (strncmp (crsr, "localhost", 9) != 0) )
			{
				crsr += 14;
				crsr += 11;
				ecrsr = strstr (crsr, "</td>");
				if (! ecrsr) return;
				*ecrsr = 0;
				add_modstatus_vhost (inf, crsr);
				crsr = ecrsr+1;
			}
		}
		
		crsr = strstr (crsr, "<tr>");
	}
}

void gather_modstatus_apache1 (netload_info *inf, char *body)
{
	char *crsr;
	char *ecrsr;
	int i;
	
	dprintf ("mod_status apache1\n");
	
	crsr = strstr (body, "<tr");
	if (! crsr) return;
	crsr = strstr (crsr+3, "<tr");
	if (! crsr) return;
	
	while (crsr)
	{
		for (i=0; i<4; ++i)
		{
			crsr = strstr (crsr, "<td>");
			if (! crsr) return;
			crsr += 4;
		}
		if (strncmp (crsr, "<b>W</b>", 8) == 0)
		{
			crsr = strstr (crsr, "<td nowrap>");
			if (! crsr) return;
			crsr += 11;
			crsr = strchr (crsr, '>');
			if (! crsr) return;
			crsr++;
			if (strncmp (crsr, "127.0.0.1", 9) != 0)
			{
				crsr = strstr (crsr+1, "<td nowrap>");
				if (! crsr) return;
				crsr = strstr (crsr+1, "<font");
				if (! crsr) return;
				crsr = strchr (crsr, '>');
				if (! crsr) return;
				crsr++;
				ecrsr = strchr (crsr, '<');
				if (! ecrsr) return;
				*ecrsr = 0;
				add_modstatus_vhost (inf, crsr);
				crsr = ecrsr+1;
			}
		}
		
		crsr = strstr (crsr, "<tr");
	}
}

void gather_modstatus (netload_info *inf)
{
	char *body = NULL;
	char *crsr;
	int sz;
	
	dprintf ("modstatus prefetch\n");
	sz = http_fetch (CONF.statusurl, &body);
	dprintf ("modstatus fetch %i bytes\n", sz);
	if (sz>0)
	{
		crsr = strstr (body, "</pre>");
		if (crsr) gather_modstatus_apache2 (inf, crsr);
		else
		{
			crsr = strstr (body, "</PRE>");
			if (crsr) gather_modstatus_apache1 (inf, crsr);
		}
	}
	
	if (body) free (body);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION main (argc, argv)                                                *
 * --------------------------                                                *
 * Initializes, then goes in an infinite loop running all the statistics     *
 * gathering functions and sending the packet to every server that wants     *
 * to hear.                                                                  *
\* ------------------------------------------------------------------------- */

int main (int argc, char *argv[])
{
	int i, ii;
	if (argc<2) execl (argv[0], argv[0], "--really-long-optarg-just-because", NULL);
	
	pool_init ();
	proctitle_init (argc, argv);
	
	runroot = 0;
	
	if (argc > 1)
	{
		if (! strcmp (argv[1], "-r")) runroot = 1;
	}
	
	conf_init ();
	load_config ("/etc/n2/n2txd.conf");
	
	if (! CONF.servers)
	{
		fprintf (stderr, "%% No servers configured in n2txd.conf\n");
		exit (1);
	}
	
#ifdef DEBUG
	mainloop (NULL);
#else
	daemonize(argv);
#endif
}

int mainloop (void *idontcare)
{
	int roundno = 0;
	time_t next_round;
	int sleeptime;
	netload_info inf;
	netload_pkt *pkt;
	int sock;
#ifdef DEBUG
	netload_info *dinf;
	netload_rec *rec;
#endif
	n2server *srv;
	struct sockaddr_in local_addr;
	struct sockaddr_in remote_addr;

#ifndef DEBUG
	setproctitle ("[monitor]");
#endif
	signal (SIGHUP, huphandler);
	signal (SIGTERM, termhandler);
	bzero (&inf, sizeof (inf));
	bzero (&local_addr, sizeof (local_addr));

	srv = CONF.servers;

	gather_init();
	gather_netinfo(&inf);
	gather_meminfo(&inf);
	init_xenvps ();
	
	sock = socket (AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		fprintf (stderr, "%% Error creating udp socket\n");
		exit (1);
	}
	
	if (CONF.listenaddr)
	{
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = htonl (CONF.listenaddr);
		if (CONF.listenport && (CONF.listenport > 1024))
		{
			local_addr.sin_port = htons (CONF.listenport);
		}
		else
		{
			local_addr.sin_port = htons (4224);
		}
		bind (sock, (struct sockaddr *) &local_addr, sizeof (local_addr));
	}
	
	while (1)
	{
		++roundno;
		next_round = time (NULL) + 27;
		
		sample_tprocs (&inf);
		inf.nhttp = 0;
		dprintf ("CONF.modstatus=%i\n", CONF.modstatus);
		if (CONF.modstatus) gather_modstatus (&inf);

		sleep (5);
		
		/* resend the previous packet once every two rounds*/
		srv = (roundno & 1) ? NULL : CONF.servers;
		while (srv)
		{
			if ((pkt = srv->lastpacket))
			{
				remote_addr.sin_addr.s_addr = htonl (srv->host);
				remote_addr.sin_port = htons (srv->port);
				remote_addr.sin_family = AF_INET;
				sendto (sock, pkt->data, pkt->pos, 0,
						(struct sockaddr *) &remote_addr,
						sizeof (struct sockaddr));
				
			}
			srv = srv->next;
		}
		
		sample_tprocs (&inf);
		sleep (6);
		sample_tprocs (&inf);
		if (CONF.modstatus) gather_modstatus (&inf);
		sleep (2);
		
		gather_ports (&inf);
		
		inf.services = huntservices (getports(), getprocs());
		dprintf ("gather_hostdat\n");
		gather_hostdat (&inf);
		dprintf ("gather_load\n");
		gather_load (&inf);
		dprintf ("gather_meminfo\n");
		gather_meminfo (&inf);
		dprintf ("gather_netinfo\n");
		gather_netinfo (&inf);
		dprintf ("gather_io\n");
		gather_io (&inf);
		dprintf ("gather_mounts\n");
		gather_mounts (&inf);
		dprintf ("gather_tprocs\n");
		gather_tprocs (&inf);
		if (CONF.modstatus) gather_modstatus (&inf);
		if ((CONF.encoding & ENCODE_TCPSTAT) == 0)
		{
			inf.nports = 0;
		}
		if (CONF.encoding & ENCODE_LOGINS)
		{
			dprintf ("gather_ttys\n");
			gather_ttys (&inf);
		}
		else
		{
			inf.ntty = 0;
		}
		
		if (CONF.xen) gather_xenvps (&inf);
		else inf.nxenvps = 0;
		
#ifdef DEBUG
		pkt = encode_pkt (&inf, "md5meharder");
		rec = encode_rec (pkt, time (NULL), ST_OK, 1, 1, 0);
		dinf = decode_rec (rec);
		pool_free (rec);
		print_info (dinf, 0x7f000001);
		pool_free (dinf);
#else
		if (config_changed)
		{
			load_config ("/etc/n2/n2txd.conf");
			config_changed = 0;
		}

		srv = CONF.servers;
		while (srv)
		{
			remote_addr.sin_addr.s_addr = htonl (srv->host);
			remote_addr.sin_port = htons (srv->port);
			remote_addr.sin_family = AF_INET;

			dprintf ("sendpacket %08x %08x\n", srv->host, srv->port);
			pkt = encode_pkt (&inf, srv->key);
			write_packet (pkt);
			sendto (sock, pkt->data, pkt->pos, 0,
					(struct sockaddr *) &remote_addr,
					sizeof (struct sockaddr));
			if (srv->lastpacket) pool_free (srv->lastpacket);
			srv->lastpacket = pkt;
			srv = srv->next;
		}
		dprintf ("done\n\n");
#endif
		
		sleeptime = next_round - time (NULL);
		if (sleeptime>30) sleeptime = 30;
		if (sleeptime>0) sleep (sleeptime);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION daemonize (void)                                                 *
 * -------------------------                                                 *
 * Change privilege levels and fork into the background.                     *
\* ------------------------------------------------------------------------- */

pid_t myclone (int (*fn)(void *), void *optarg)
{
#ifdef STATIC
	char *nstack = malloc (8192);
	return clone (fn, nstack + 8184, CLONE_FS | CLONE_FILES | SIGCHLD, optarg);
#else
	pid_t res = fork();
	if (res == 0) exit (fn (optarg));
	return res;
#endif
}

int daemonize_secondfork (void *a)
{
	int retval = 0;
	pid_t pid3;
	FILE *pidfile = NULL;
	
	DAEMON_PID = pid3 = myclone (mainloop, NULL);
	
	while (pid3)
	{
		if (pid3<0)
		{
			exit (1);
		}
		
		pidfile = fopen ("/var/run/n2txd.pid","w");
		fprintf (pidfile, "%u", pid3);
		fclose (pidfile);
		setproctitle ("[watchdog]");
		
		while (wait (&retval) != pid3);
		if (retval == 0) exit (0);
		DAEMON_PID = pid3 = myclone (mainloop, NULL);
	}
}

int daemonize_firstfork (void *a)
{
	pid_t pid2;
	
	close (0);
	close (1);
	close (2);
	pid2 = myclone (daemonize_secondfork, NULL);
	if (pid2 < 0) exit (1);
	exit (0);
}

void daemonize (char *argv[])
{
	pid_t pid1 = -1;
	uid_t uid = 0;
	gid_t gid = 0;
	FILE *pidfile = NULL;
	struct passwd *pwd = NULL;
	char buf[256];
	
	bzero (buf, 255);
	
	pidfile = fopen ("/var/run/n2txd.pid", "r");
	if (pidfile)
	{
		buf[0] = 0;
		fread (buf, 1, 255, pidfile);
		fclose (pidfile);
		
		pid1 = atoi (buf);
		if (pid1)
		{
			if (kill (pid1, 0) == 0)
			{
				fprintf (stderr, "Already running\n");
				exit (1);
			}
		}
	}
	
	pidfile = fopen ("/var/run/n2txd.pid","w");
	fclose (pidfile);
	
	pwd = getpwnam ("n2");
	if (! pwd) pwd = getpwnam ("nobody");
	
	uid = pwd->pw_uid;
	gid = pwd->pw_gid;
	
	chown ("/var/run/n2txd.pid", uid, gid);

	if (! runroot)
	{	
		setregid (gid, gid);
		setreuid (uid, uid);
	}

#ifdef DEBUG
	pid1 = getpid();
	pidfile = fopen ("/var/run/n2txd.pid","w");
	fprintf (pidfile, "%u", pid1);
	fclose (pidfile);
	setproctitle ("[debug]");
	return;
#endif
	
	switch (pid1 = myclone (daemonize_firstfork, NULL))
	{
		case -1:
			fprintf (stderr, "%% Fork failed\n");
			exit (1);
			
		default:
			exit (0);
	}
}


/* ------------------------------------------------------------------------- *\
 * FUNCTION huphandler (signal)                                              *
 * ----------------------------                                              *
 * Handles the SIGHUP signal, sets the flag to reload the configuration.     *
\* ------------------------------------------------------------------------- */

void huphandler (int sig)
{
	config_changed = 1;
	signal (SIGHUP, huphandler);
}

int findprocuid (procrun *procs, const char *name, uid_t owneruid)
{
	int i;
	char *ptitle;
	char *c;
	
	dprintf ("findproc: name='%s', uid=%i\n", name, owneruid);
	
	for (i=0; i<procs->count; ++i)
	{
		ptitle = procs->array[i].ptitle;
		while ((*ptitle && (c = strchr (ptitle+1, '/')))) ptitle = c+1;
		if (c = strchr (ptitle, ' '))
		{
			*c = 0;
		}
		if (! strcmp (ptitle, name))
		{
			dprintf ("findproc: found proc uid=%i\n", procs->array[i].uid);
			if (owneruid == 1) return 1;
			if (procs->array[i].uid == owneruid) return 1;
		}
	}
	
	return 0;
}

unsigned int huntservices (portlist *ports, procrun *procs)
{
	unsigned int svcmask = 0;
	unsigned int svcid;
	unsigned int i;
	uid_t owneruid;
	svc_match *crsr;
	struct passwd *pw;
	
	for (svcid=0; svcid<32; ++svcid)
	{
		crsr = CONF.matches[svcid];
		for (i=0; crsr[i].name; ++i)
		{
			dprintf ("huntsvc: checking service '%s' port %i owner '%s'\n", crsr[i].name, crsr[i].port, crsr[i].owner);
			if ((crsr[i].port == 0) || (*ports)[crsr[i].port][0])
			{
				if (strcmp (crsr[i].owner, "*") == 0)
				{
					owneruid = 1;
				}
				else
				{
					pw = getpwnam (crsr[i].owner);
					if (pw) owneruid = pw->pw_uid;
					else owneruid = 0;
				}
				if (findprocuid (procs, crsr[i].name, owneruid))
				{
					dprintf ("huntsvc: found\n");
					svcmask |= 1 << svcid;
				}
			}
		}
	}
	
	dprintf ("huntsvc: SVCMASK %08x\n", svcmask);
	return svcmask;
}
