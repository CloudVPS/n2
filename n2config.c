#include "iptypes.h"
#include "n2acl.h"
#include "n2config.h"
#include "n2args.h"
#include "version.h"
#include "n2malloc.h"
#include "datatypes.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* Local prototypes */
void parse_cmd (const char *);
void conf_ip_address (n2arglist *);
void conf_log_type (n2arglist *);
void conf_log_file (n2arglist *);
void conf_user (n2arglist *);
void conf_group (n2arglist *);
void conf_hostname (n2arglist *);
void conf_service_match (n2arglist *);
void conf_monitor_host (n2arglist *);
void conf_monitor_group (n2arglist *);
void conf_monitor_key (n2arglist *);
void conf_monitor_contact (n2arglist *);
void conf_monitor_rtt_warning (n2arglist *);
void conf_monitor_rtt_alert (n2arglist *);
void conf_monitor_loadavg_warning (n2arglist *);
void conf_monitor_loadavg_alert (n2arglist *);
void conf_monitor_loss_warning (n2arglist *);
void conf_monitor_loss_alert (n2arglist *);
void conf_monitor_sock_warning (n2arglist *);
void conf_monitor_sock_alert (n2arglist *);
void conf_monitor_cpu_warning (n2arglist *);
void conf_monitor_cpu_alert (n2arglist *);
void conf_monitor_diskspace_warning (n2arglist *);
void conf_monitor_diskspace_alert (n2arglist *);
void conf_monitor_ram_warning (n2arglist *);
void conf_monitor_ram_alert (n2arglist *);
void conf_monitor_swap_warning (n2arglist *);
void conf_monitor_swap_alert (n2arglist *);
void conf_monitor_netin_warning (n2arglist *);
void conf_monitor_netin_alert (n2arglist *);
void conf_monitor_netout_warning (n2arglist *);
void conf_monitor_netout_alert (n2arglist *);
void conf_monitor_diskio_warning (n2arglist *);
void conf_monitor_diskio_alert (n2arglist *);
void conf_monitor_default (n2arglist *);
void conf_alias (n2arglist *);
void conf_server (n2arglist *);
void conf_server_key (n2arglist *);
void conf_iflist (n2arglist *);
void conf_iolist (n2arglist *);
void conf_service (n2arglist *);
void conf_modstatus (n2arglist *);
void conf_encode_modstatus (n2arglist *);
void conf_xenvps (n2arglist *);
void conf_encode_xen (n2arglist *);
void conf_host_group (n2arglist *);
void conf_group_member_host (n2arglist *);
void conf_group_member_network (n2arglist *);
void conf_group_email_addr (n2arglist *);
void conf_group_email_subject (n2arglist *);
void conf_group_email_sender (n2arglist *);
void conf_group_madnotify_url (n2arglist *);
void conf_group_madnotify_user (n2arglist *);
void conf_group_madnotify_pass (n2arglist *);
void conf_group_alert_trigger (n2arglist *);
void conf_group_description (n2arglist *);
void conf_encode_logins (n2arglist *);
void conf_no_encode_logins (n2arglist *);
void conf_encode_tcpstat (n2arglist *);
void conf_no_encode_tcpstat (n2arglist *);
void conf_no_monitor_group (n2arglist *);
void conf_no_host_group (n2arglist *);
void conf_host_group_no (n2arglist *);
void conf_monitor_no (n2arglist *);
void conf_version (n2arglist *);

/* ------------------------------------------------------------------------- *\
 * Configuration menu structures (CONF_ROOT is where it starts)              *
\* ------------------------------------------------------------------------- */
n2command CONF_IP_BIND[] = {
	{"address", NULL, conf_ip_address},
	{NULL, NULL, NULL}
};

n2command CONF_IP[] = {
	{"bind", CONF_IP_BIND, NULL},
	{NULL, NULL, NULL}
};

n2command CONF_LOG_TYPE[] = {
	{"none", NULL, conf_log_type},
	{"events", NULL, conf_log_type},
	{"malformed", NULL, conf_log_type},
	{"all", NULL, conf_log_type},
	{NULL, NULL, NULL}
};

n2command CONF_LOG[] = {
	{"type", CONF_LOG_TYPE, NULL},
	{"file", NULL, conf_log_file},
	{NULL, NULL, NULL}
};

n2command CONF_NO_ENC_OPT[] = {
	{"logins", NULL, conf_no_encode_logins},
	{"tcpstat", NULL, conf_no_encode_tcpstat},
	{NULL, NULL, NULL}
};

n2command CONF_ENC_OPT[] = {
	{"logins", NULL, conf_encode_logins},
	{"tcpstat", NULL, conf_encode_tcpstat},
	{"modstatus", NULL, conf_encode_modstatus},
	{"xen", NULL, conf_encode_xen},
	{"no", CONF_NO_ENC_OPT, NULL},
	{NULL, NULL, NULL}
};

n2command CONF_NO[] = {
	{"monitor-group", NULL, conf_no_monitor_group},
	{"host-group", NULL, conf_no_host_group},
	{NULL, NULL, NULL}
};

n2command CONF_ROOT[] = {
	{"ip", CONF_IP, NULL},
	{"log", CONF_LOG, NULL},
	{"service-match", NULL, conf_service_match},
	{"default", NULL, conf_monitor_default},
	{"encoding-options", CONF_ENC_OPT, NULL},
	{"user", NULL, conf_user},
	{"group", NULL, conf_group},
	{"monitor-group", NULL, conf_monitor_group},
	{"monitor-host", NULL, conf_monitor_host},
	{"host-group", NULL, conf_host_group},
	{"server", NULL, conf_server},
	{"service", NULL, conf_service},
	{"modstatus", NULL, conf_modstatus},
	{"xen", NULL, conf_xenvps},
	{"interface-list", NULL, conf_iflist},
	{"iodev-list", NULL, conf_iolist},
	{"hostname", NULL, conf_hostname},
	{"no", CONF_NO, NULL},
	{"version", NULL, conf_version},
	{"alias", NULL, conf_alias},
	{NULL, NULL, NULL}
};

n2command CONF_HOST_GROUP_MEMBER[] = {
	{"host", NULL, conf_group_member_host},
	{"network", NULL, conf_group_member_network},
	{NULL, NULL, NULL}
};

n2command CONF_GROUP_EMAIL[] = {
	{"address", NULL, conf_group_email_addr},
	{"subject", NULL, conf_group_email_subject},
	{"sender", NULL, conf_group_email_sender},
	{NULL, NULL, NULL}
};

n2command CONF_GROUP_MADNOTIFY[] = {
	{"url", NULL, conf_group_madnotify_url},
	{"username", NULL, conf_group_madnotify_user},
	{"password", NULL, conf_group_madnotify_pass},
	{NULL, NULL, NULL}
};

n2command CONF_HOST_GROUP_NOTIFICATION[] = {
	{"email", CONF_GROUP_EMAIL, NULL},
	{"madnotify", CONF_GROUP_MADNOTIFY, NULL},
	{NULL, NULL, NULL}
};

n2command CONF_HOST_GROUP[] = {
	{"description", NULL, conf_group_description},
	{"member", CONF_HOST_GROUP_MEMBER, NULL},
	{"notification", CONF_HOST_GROUP_NOTIFICATION, NULL},
	{"alert-trigger", NULL, conf_group_alert_trigger},
	{"no", NULL, conf_host_group_no},
	{NULL, NULL, NULL}
};

n2command CONF_MONITOR_GROUP[] = {
	{"key", NULL, conf_monitor_key},
	{"contact", NULL, conf_monitor_contact},
	{"rtt-warning", NULL, conf_monitor_rtt_warning},
	{"rtt-alert", NULL, conf_monitor_rtt_alert},
	{"loadavg-warning", NULL, conf_monitor_loadavg_warning},
	{"loadavg-alert", NULL, conf_monitor_loadavg_alert},
	{"loss-warning", NULL, conf_monitor_loss_warning},
	{"loss-alert", NULL, conf_monitor_loss_alert},
	{"sockstate-warning", NULL, conf_monitor_sock_warning},
	{"sockstate-alert", NULL, conf_monitor_sock_alert},
	{"cpu-warning", NULL, conf_monitor_cpu_warning},
	{"cpu-alert", NULL, conf_monitor_cpu_alert},
	{"ram-warning", NULL, conf_monitor_ram_warning},
	{"ram-alert", NULL, conf_monitor_ram_alert},
	{"swap-warning", NULL, conf_monitor_swap_warning},
	{"swap-alert", NULL, conf_monitor_swap_alert},
	{"netin-warning", NULL, conf_monitor_netin_warning},
	{"netin-alert", NULL, conf_monitor_netin_alert},
	{"netout-warning", NULL, conf_monitor_netout_warning},
	{"netout-alert", NULL, conf_monitor_netout_alert},
	{"diskio-warning", NULL, conf_monitor_diskio_warning},
	{"diskio-alert", NULL, conf_monitor_diskio_alert},
	{"diskspace-warning", NULL, conf_monitor_diskspace_warning},
	{"diskspace-alert", NULL, conf_monitor_diskspace_alert},
	{"no", NULL, conf_monitor_no},
	{NULL, NULL, NULL}
};

n2command CONF_SERVER[] = {
	{"key", NULL, conf_server_key},
	{NULL, NULL, NULL}
};

/* ------------------------------------------------------------------------- *\
 * Default process and port matches for different services.                  *
\* ------------------------------------------------------------------------- */
svc_match MATCH_NETLOAD[] = {{"n2rxd", "n2", 0},{NULL,NULL,0}};
svc_match MATCH_SSH[] = {{"sshd", "root", 0},{NULL,NULL,0}};
svc_match MATCH_HTTP[] = {
	{"httpd", "root", 80},
	{"apache", "root", 80},
	{"apache2","root", 80},
	{"lighttpd", "*", 80},
	{NULL,NULL,0}
};
svc_match MATCH_SMTP[] = {
	{"sendmail", "root", 25},
	{"exim", "*", 25},
	{"master", "root", 25},
	{"qmail-smtpd", "qmaild", 25},
	{NULL, NULL, 0}
};
svc_match MATCH_SNMP[] = {{"snmpd", "snmp", 0},{NULL,NULL,0}};
svc_match MATCH_IMAP[] = {
	{"imapd", "cyrus", 143},
	{"couriertcpd","root", 143},
	{"xinetd","root", 143},
	{NULL,NULL,0}
};
svc_match MATCH_POP3[] = {
	{"pop3d", "cyrus", 110},
	{"couriertcpd","root", 110},
	{"vm-pop3d","root", 110},
	{"xinetd","root", 110},
	{NULL,NULL,0}
};
svc_match MATCH_FTP[] = {
	{"vsftpd", "root", 21},
	{"pure-ftpd","root", 21},
	{"xinetd","root", 21},
	{"ftpd", "root", 21},
	{NULL,NULL,0}
};
svc_match MATCH_NNTP[] = {{"*", "*", 119},{NULL,NULL,0}};
svc_match MATCH_CRON[] = {{"crond", "root", 0},{NULL,NULL,0}};
svc_match MATCH_HTTPADMIN[] = {
	{"directadmin", "nobody", 2222},
	{"cpsrvd-ssl", "root", 2086},
	{"opencore", "opencore", 4088},
	{"httpsd", "root", 8443},
	{NULL, NULL, 0}
};
svc_match MATCH_SQLDB[] = {{"mysqld", "mysql", 3306},{NULL, NULL, 0}};
svc_match MATCH_NFS[] = {{"nfsd", "*", 2049},{NULL, NULL, 0}};
svc_match MATCH_CIFS[] = {{"smbd", "root", 139},{NULL, NULL, 0}};
svc_match MATCH_ATALK[] = {{"afpd", "root", 548},{NULL, NULL, 0}};
svc_match MATCH_DNS[] = {
	{"named", "*", 53},
	{"pdns_server", "*", 53},
	{"pdns_recursor", "*", 53},
	{"unbound", "*", 53},
	{"dnscache", "*", 53},
	{NULL, NULL, 0}
};
svc_match MATCH_LDAP[] = {
	{"slapd", "*", 389},
	{NULL, NULL, 0}
};
svc_match MATCH_SPAMD[] = {
	{"spamd", "root", 0},
	{NULL, NULL, 0}
};
svc_match MATCH_ROUTING[] = {
	{"zebra", "*", 0},
	{"quagga", "*", 0},
	{"routed", "*", 0},
	{NULL, NULL, 0}
};
svc_match MATCH_INETD[] = {
	{"inetd", "root", 0},
	{"xinetd", "root", 0},
	{NULL, NULL, 0}
};
svc_match MATCH_DHCP[] = {{"dhcpd", "root", 0},{NULL, NULL, 0}};
svc_match MATCH_FIREWALL[] = {{NULL, NULL, 0}};
svc_match MATCH_SYSLOG[] = {{"syslogd", "root", 0},{NULL, NULL, 0}};
svc_match MATCH_PRINTER[] = {
	{"lpd", "root", 515},
	{"cupsd","root", 631},
	{NULL, NULL, 0}
};
svc_match MATCH_VM[] = {
	{"xend", "root", 0},
	{NULL, NULL, 0}
};
svc_match MATCH_CHAT[] = {
	{"c2s", "*", 5222},
	{"ircd", "*", 6667},
	{"ircu", "*", 6667},
	{"ircd-hybrid", "*", 6667},
	{NULL, NULL, 0}
};

static const char *STR_SVC[] = {
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

svc_match MATCH_NONE[] = {{NULL, NULL, 0}};
ackednode *ACKED;

/* GLOBALS */
n2command	*CROOT;
acl			*curacl;
n2server	*curserver;
n2config	 CONF;
groupdb		 GROUPS;
int			 config_changed;
hostgroup	*curhostgroup;

/* ------------------------------------------------------------------------- *\
 * FUNCTION parse_cmd (string)                                               *
 * ---------------------------                                               *
 * Parses a configuration line in context.                                   *
\* ------------------------------------------------------------------------- */
void parse_cmd (const char *str)
{
	n2arglist *ar;
	int		   pos;
	n2command *root;
	int		   cpos;
	
	ar = make_args (str);
	pos = 0;
	root = CROOT;
	
	while (pos<ar->argc)
	{
		cpos = 0;
		while (root[cpos].name)
		{
			if (strcmp (root[cpos].name, "*") == 0)
			{
				if (root[cpos].function)
				{
					root[cpos].function (ar);
					destroy_args (ar);
					return;
				}
				if (root[cpos].children)
				{
					root = root[cpos].children;
					break;
				}
			}
			else if (strcasecmp (root[cpos].name, ar->argv[pos]) == 0)
			{
				if (root[cpos].function)
				{
					root[cpos].function (ar);
					destroy_args (ar);
					return;
				}
				if (root[cpos].children)
				{
					root = root[cpos].children;
					break;
				}
			}
			++cpos;
		}
		++pos;
	}
	
	destroy_args (ar);
	
	if (str[0] >= ' ')
		printf ("%% Syntax error in configuration line:\n  '%s'\n", str);
}

ackednode *create_acknode (void)
{
	ackednode *crsr = ACKED;
	ackednode *newnode;
	
	while (crsr && crsr->next) crsr = crsr->next;
	newnode = (ackednode *) malloc (sizeof (ackednode));
	newnode->next = NULL;
	newnode->acked_oflags = 0;
	newnode->acked_flags = 0;
	newnode->acked_stale_or_dead = 0;
	newnode->expires = 0;
	
	if (crsr) crsr->next = newnode;
	else ACKED = newnode;
	
	return newnode;
}

ackednode *find_acked (unsigned long addr)
{
	time_t tnow;
	ackednode *crsr = ACKED;
	if (! crsr) return NULL;
	tnow = time(NULL);
	while (crsr)
	{
		if (crsr->addr == addr && crsr->expires > tnow) return crsr;
		crsr = crsr->next;
	}
	return NULL;
}

void load_ackedlist (void)
{
	time_t tnow, texp;
	ackednode *crsr;
	ackednode *newnode;
	n2arglist *arg;
	FILE *f;
	char buf[1024];
	int i;
	
	tnow = time (NULL);
	
	crsr = ACKED;
	while (crsr)
	{
		newnode = crsr->next;
		free (crsr);
		crsr = newnode;
	}
	
	ACKED = NULL;
	
	f = fopen ("/etc/n2/n2rxd.acked","r");
	if (f)
	{
		while (! feof (f))
		{
			buf[0] = 0;
			fgets (buf, 1023, f);
			buf[1023] = 0;
			i = strlen(buf);
			if (i)
			{
				if (buf[i-1] < ' ') buf[i-1] = 0;
			}
			if (! *buf) continue;
			arg = make_args (buf);
			// 1.2.3.4 texp prob1 prob2 prob3 prob4
			if (arg->argc > 2)
			{
				texp = strtoul (arg->argv[1], NULL, 10);
				if (texp < tnow)
				{
					destroy_args (arg);
					continue;
				}
				newnode = create_acknode();
				newnode->addr = atoip (arg->argv[0]);
				newnode->expires = strtoul (arg->argv[1], NULL, 10);
				
				#define chk_flag(flag,str) { \
						if(strcmp(arg->argv[i],str) ==0) { \
							newnode->acked_flags |= (1 << flag); \
							continue; \
						} \
					}

				#define chk_oflag(flag,str) { \
						if(strcmp(arg->argv[i],str) ==0) { \
							newnode->acked_oflags |= (1 << flag); \
							continue; \
						} \
					}
				
				for (i=2; i<arg->argc; ++i)
				{
					chk_flag(FLAG_RTT, "rtt");
					chk_flag(FLAG_LOSS, "loss");
					chk_flag(FLAG_LOAD, "load");
					chk_oflag(OFLAG_RAM, "ram");
					chk_oflag(OFLAG_SWAP, "swap");
					chk_oflag(OFLAG_NETIN, "netin");
					chk_oflag(OFLAG_NETOUT, "netout");
					chk_oflag(OFLAG_SVCDOWN, "svcdown");
					chk_oflag(OFLAG_DISKIO, "diskio");
					chk_oflag(OFLAG_DISKSPACE, "diskspace");
					chk_oflag(OFLAG_DECODINGERR, "decodingerr");
					if (strcmp(arg->argv[i],"dead") == 0)
					{
						newnode->acked_stale_or_dead = 1;
						continue;
					}
				}
			}
			destroy_args (arg);
		}
		fclose (f);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION load_config (filename)                                           *
 * -------------------------------                                           *
 * Loads and parses a configuration file.                                    *
\* ------------------------------------------------------------------------- */
void load_config (const char *fname)
{
	const char	*tmp;
	n2server	*crsr;
	n2server	*next;
	char		 buf[512];
	FILE 		*F;
	int			 ln;
	
	if (CONF.logfile)
	{
		pool_free (CONF.logfile);
		CONF.logfile = NULL;
		crsr = CONF.servers;
		while (crsr)
		{
			next = crsr->next;
			if (crsr->lastpacket)
				pool_free (crsr->lastpacket);
			pool_free (crsr);
			crsr = next;
		}
		CONF.servers = NULL;
	}
	CONF.logfile = pool_strdup ("/var/log/n2/n2.log");
	CONF.log = LOG_NONE;
	CONF.listenaddr = 0;
	CONF.listenport = 444;
	strcpy (CONF.user, "nobody");
	strcpy (CONF.group, "nobody");
	CONF.servers = NULL;
	
	tmp = getenv ("HOSTNAME");
	if (tmp)
	{
		strncpy (CONF.hostname, tmp, 31);
	}
	else
	{
		if (gethostname (buf, 511))
		{
			strncpy (CONF.hostname, "localhost", 31);
		}
		else
		{
			strncpy (CONF.hostname, buf, 31);
		}
	}
	
	CONF.hostname[31] = 0;
	
	CROOT = CONF_ROOT;
	curacl = NULL;
	curserver = NULL;
	
	F = fopen (fname, "r");
	if (F)
	{
		while (! feof (F))
		{
			buf[0] = 0;
			fgets (buf, 511, F);
			if (*buf)
			{
				ln = strlen(buf);
				if ((ln>1)&&(buf[ln-1]<32)) buf[ln-1] = 0;
				
				if (*buf && (*buf != '!'))
				{
					if (*buf > ' ')
					{
						CROOT = CONF_ROOT;
					}
					parse_cmd (buf);
				}
			}
		}
		fclose (F);
	}
	CROOT = CONF_ROOT;
	load_ackedlist ();
	
	/*F = fopen ("/var/state/n2/acl.states","w");
	if (F) dump_acl_tree (F, ACL, 0);
	fclose (F);*/
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_ip_address (args)                                           *
\* ------------------------------------------------------------------------- */
void conf_ip_address (n2arglist *arg)
{
	if (arg->argc > 3)
	{
		CONF.listenaddr = atoip (arg->argv[3]);
		if (arg->argc > 5)
		{
			if (strcasecmp (arg->argv[4], "port") == 0)
			{
				CONF.listenport = atoi (arg->argv[5]);
			}
		}
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<ip address> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_log_type (args)                                             *
\* ------------------------------------------------------------------------- */
void conf_log_type (n2arglist *arg)
{
	if (arg->argc > 2)
	{
		if (strcasecmp (arg->argv[2], "none") == 0) \
			CONF.log = LOG_NONE;
		
		else if (strcasecmp (arg->argv[2], "events") == 0)
			CONF.log = LOG_EVENTS;
		
		else if (strcasecmp (arg->argv[2], "malformed") == 0) 
			CONF.log = LOG_MALFORMED;
		
		else CONF.log = LOG_ALL;
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<log type> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_log_file (args)                                             *
\* ------------------------------------------------------------------------- */
void conf_log_file (n2arglist *arg)
{
	if (arg->argc > 2)
	{
		if (CONF.logfile) pool_free (CONF.logfile);
		CONF.logfile = pool_strdup (arg->argv[2]);
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<log file> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_user (args)                                                 *
\* ------------------------------------------------------------------------- */
void conf_user (n2arglist *arg)
{
	if (arg->argc > 1)
	{
		strncpy (CONF.user, arg->argv[1], 15);
		CONF.user[15] = 0;
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<user> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_hostname (args)                                             *
\* ------------------------------------------------------------------------- */
void conf_hostname (n2arglist *arg)
{
	if (arg->argc > 1)
	{
		strncpy (CONF.hostname, arg->argv[1], 31);
		CONF.user[31] = 0;
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<hostname> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_service_match (args)                                        *
\* ------------------------------------------------------------------------- */
void conf_service_match (n2arglist *arg)
{
	const char *svcname;
	const char *procname;
	char *user = strdup ("*");
	int port = 0;
	int i;
	int bit;
	
	// service-match sshd procname ssh [user root [port 22]]
	if ((arg->argc < 4) || (strcasecmp (arg->argv[2], "procname")))
	{
		fprintf (stderr, "%% Syntax error in service-match\n");
		exit (1);
	}
	
	procname = strdup (arg->argv[3]);
	for (i=4; (i+1) < arg->argc; i+= 2)
	{
		if (strcasecmp (arg->argv[i], "user") == 0)
		{
			free (user);
			user = strdup (arg->argv[i+1]);
		}
		else if (strcasecmp (arg->argv[i], "port") == 0)
		{
			port = atoi (arg->argv[i+1]);
		}
		else
		{
			fprintf (stderr, "%% Syntax error in service-match: "
					 "unknown keyword '%s'\n", arg->argv[i]);
			exit (1);
		}
	}
	
	svcname = arg->argv[1];
	for (bit=0; bit<32; ++bit)
	{
		if (strcasecmp (svcname, STR_SVC[bit]) == 0)
		{
			// FIXME add null-termination
			svc_match *m = (svc_match *) malloc (2 * sizeof (svc_match));
			if (! m)
			{
				fputs ("% Malloc failure\n", stderr);
				exit (1);
			}
			
			m[0].name = procname;
			m[0].owner = user;
			m[0].port = port;
			m[1].name = NULL;
			m[1].owner = NULL;
			m[1].port = 0;
			
			CONF.matches[bit] = m;
			return;
		}
	}
	
	fprintf (stderr, "%% Unknwon service '%s'\n", svcname);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group (args)                                                *
\* ------------------------------------------------------------------------- */
void conf_group (n2arglist *arg)
{
	if (arg->argc > 1)
	{
		strncpy (CONF.group, arg->argv[1], 15);
		CONF.group[15] = 0;
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<group> statement\n");
		exit (1);
	}
}

void conf_monitor_host (n2arglist *arg)
{
	/* monitor-host 1.2.3.4 ignore-loss */
	unsigned long addr;
	unsigned long mask;
	int i;
	acl *myacl;
	
	
	if (arg->argc >= 3)
	{
		addr = atoip (arg->argv[1]);
		mask = atomask ("0.0.0.0");
		
		myacl = acl_match_mask (addr, mask);
		if (myacl)
		{
			while (myacl)
			{
				if ((myacl->addr == addr) && (myacl->mask == mask)) break;
				if (! myacl->next)
				{
					myacl = acl_create (addr, mask);
					break;
				}
				myacl = myacl->next;
			}
		}
		else
		{
			myacl = acl_create (addr, mask);
		}
		
		if (myacl)
		{
			for (i=2; i<arg->argc; ++i)
			{
				if (strcmp (arg->argv[i], "ignore-loss") == 0)
				{
					myacl->loss_warning = 10500;
					myacl->loss_alert = 11000;
				}
				else if (strcmp (arg->argv[i], "ignore-diskspace") == 0)
				{
					myacl->diskspace_warning = 1050;
					myacl->diskspace_alert = 1100;
				}
			}
		}
		else
		{
			fprintf (stderr, "%% Syntax error in monitor-host %s\n", arg->argv[1]);
		}
	}
	else
	{
		fprintf (stderr, "%% Syntax error in monitor-host\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_group (args)                                        *
\* ------------------------------------------------------------------------- */
void conf_monitor_group (n2arglist *arg)
{
	unsigned long addr;
	unsigned long mask;
	
	if (arg->argc == 3)
	{
		addr = atoip (arg->argv[1]);
		mask = atomask (arg->argv[2]);
		
		if (! addr)
		{
			fprintf (stderr, "%% Invalid monitor-group ip address %s\n", 
					 arg->argv[1]);
		}
		else if (! mask)
		{
			fprintf (stderr, "%% Invalid monitor-group netmask %s\n",
					 arg->argv[2]);
		}
		else
		{
			curacl = acl_match_mask (addr, mask);
			while (curacl)
			{
				if ( (curacl->addr == addr) && (curacl->mask == mask) )
				{
					CROOT = CONF_MONITOR_GROUP;
					return;
				}
				curacl = curacl->next;
			}
			curacl = acl_create (addr, mask);
			CROOT = CONF_MONITOR_GROUP;
		}
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<monitor-group> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_key (args)                                          *
\* ------------------------------------------------------------------------- */
void conf_monitor_key (n2arglist *arg)
{
	if (arg->argc > 1)
	{
		strncpy (curacl->key, arg->argv[1], 63);
		curacl->key[63] = 0;
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<key> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_contact (args)                                      *
\* ------------------------------------------------------------------------- */
void conf_monitor_contact (n2arglist *arg)
{
	if (arg->argc > 1)
	{
		acl_add_contact (curacl, arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_rtt_warning (args)                                  *
\* ------------------------------------------------------------------------- */
void conf_monitor_rtt_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		d = atof (arg->argv[1]);
		curacl->rtt_warning = (unsigned short) (d * 10);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_rtt_alert (args)                                    *
\* ------------------------------------------------------------------------- */
void conf_monitor_rtt_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		d = atof (arg->argv[1]);
		curacl->rtt_alert = (unsigned short) (d * 10);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_loadavg_warning (args)                              *
\* ------------------------------------------------------------------------- */
void conf_monitor_loadavg_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		d = atof (arg->argv[1]);
		curacl->loadavg_warning = (unsigned short) (d * 100);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_loadavg_alert (args)                                *
\* ------------------------------------------------------------------------- */
void conf_monitor_loadavg_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		d = atof (arg->argv[1]);
		curacl->loadavg_alert = (unsigned short) (d * 100);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_loss_warning (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_monitor_loss_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		d = atof (arg->argv[1]);
		curacl->loss_warning = (unsigned short) (d * 100);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_loss_alert (args)                                   *
\* ------------------------------------------------------------------------- */
void conf_monitor_loss_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		d = atof (arg->argv[1]);
		curacl->loss_alert = (unsigned short) (d * 100);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_sock_warning (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_monitor_sock_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->sockstate_warning = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_sock_alert (args)                                   *
\* ------------------------------------------------------------------------- */
void conf_monitor_sock_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->sockstate_alert = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_cpu_warning (args)                                  *
\* ------------------------------------------------------------------------- */
void conf_monitor_cpu_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->cpu_warning = (atoi (arg->argv[1]) * 255) / 100;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_cpu_alert (args)                                    *
\* ------------------------------------------------------------------------- */
void conf_monitor_cpu_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->cpu_alert = (atoi (arg->argv[1]) * 255) / 100;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_diskspace_warning (args)                            *
\* ------------------------------------------------------------------------- */
void conf_monitor_diskspace_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->diskspace_warning = atoi (arg->argv[1]) * 10;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_diskspace_alert (args)                              *
\* ------------------------------------------------------------------------- */
void conf_monitor_diskspace_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->diskspace_alert = atoi (arg->argv[1]) * 10;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_ram_warning (args)                                  *
\* ------------------------------------------------------------------------- */
void conf_monitor_ram_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->ram_warning = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_ram_alert (args)                                    *
\* ------------------------------------------------------------------------- */
void conf_monitor_ram_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->ram_alert = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_swap_warning (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_monitor_swap_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->swap_warning = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_swap_alert (args)                                   *
\* ------------------------------------------------------------------------- */
void conf_monitor_swap_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->swap_alert = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_netin_warning (args)                                *
\* ------------------------------------------------------------------------- */
void conf_monitor_netin_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->netin_warning = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_netin_alert (args)                                  *
\* ------------------------------------------------------------------------- */
void conf_monitor_netin_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->netin_alert = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_netout_warning (args)                               *
\* ------------------------------------------------------------------------- */
void conf_monitor_netout_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->netout_warning = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_netout_alert (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_monitor_netout_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->netout_alert = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_netout_warning (args)                               *
\* ------------------------------------------------------------------------- */
void conf_monitor_diskio_warning (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->diskio_warning = atoi (arg->argv[1]);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_netout_alert (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_monitor_diskio_alert (n2arglist *arg)
{
	double d;
	if (arg->argc > 1)
	{
		curacl->diskio_alert = atoi (arg->argv[1]);
	}
}

/* Handy macro to redirect default declarations to host-group commands */
#define REDIR(foo,bar,baz) if (! strcmp (arg->argv[1], foo)) bar (baz)

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_default (args)                                      *
\* ------------------------------------------------------------------------- */
void conf_monitor_default (n2arglist *arg)
{
	n2arglist *targ;
	if (arg->argc < 3)
	{
		fprintf (stderr, "%% Syntax error in default\n");
		return;
	}
	
	targ = new_args ();
	add_args (targ, arg->argv[1]);
	add_args (targ, arg->argv[2]);
	
	curacl = ACL;
	
	REDIR("rtt-warning", conf_monitor_rtt_warning, targ);
	REDIR("rtt-alert", conf_monitor_rtt_alert, targ);
	REDIR("loadavg-warning", conf_monitor_loadavg_warning, targ);
	REDIR("loadavg-alert", conf_monitor_loadavg_alert, targ);
	REDIR("loss-warning", conf_monitor_loss_warning, targ);
	REDIR("loss-alert", conf_monitor_loss_alert, targ);
	REDIR("sockstate-warning", conf_monitor_sock_warning, targ);
	REDIR("sockstate-alert", conf_monitor_sock_alert, targ);
	REDIR("cpu-warning", conf_monitor_cpu_warning, targ);
	REDIR("cpu-alert", conf_monitor_cpu_alert, targ);
	REDIR("ram-warning", conf_monitor_ram_warning, targ);
	REDIR("ram-alert", conf_monitor_ram_alert, targ);
	REDIR("swap-warning", conf_monitor_swap_warning, targ);
	REDIR("swap-alert", conf_monitor_swap_alert, targ);
	REDIR("netin-warning", conf_monitor_netin_warning, targ);
	REDIR("netin-alert", conf_monitor_netin_alert, targ);
	REDIR("netout-warning", conf_monitor_netout_warning, targ);
	REDIR("netout-alert", conf_monitor_netout_alert, targ);
	REDIR("diskio-warning", conf_monitor_diskio_warning, targ);
	REDIR("diskio-alert", conf_monitor_diskio_alert, targ);
	REDIR("diskspace-warning", conf_monitor_diskspace_warning, targ);
	REDIR("diskspace-alert", conf_monitor_diskspace_alert, targ);
	
	destroy_args (targ);
}

void conf_alias (n2arglist *arg)
{
	if (arg->argc < 3)
	{
		fprintf (stderr, "%% Syntax error in alias\n");
		return;
	}
	
	n2alias *nalias = (n2alias *) malloc (sizeof (n2alias));
	nalias->from_addr = atoip (arg->argv[1]);
	nalias->to_addr = atoip (arg->argv[2]);
	nalias->next = NULL;
	
	if ((! nalias->from_addr) || (! nalias->to_addr)) return;
	
	n2alias *c = ALIASES;
	if (! c)
	{
		ALIASES = nalias;
		return;
	}
	
	while (c->next) c = c->next;
	c->next = nalias;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_server (args)                                               *
\* ------------------------------------------------------------------------- */
void conf_server (n2arglist *arg)
{
	unsigned long addr;
	int port;
	n2server *srv;
	n2server *crs;
	
	if (arg->argc > 1)
	{
		addr = atoip (arg->argv[1]);
		if (! addr) fprintf (stderr, "%% Invalid server ip address %s\n",
							 arg->argv[1]);
		else
		{
			if ((arg->argc > 3) && (! strcasecmp (arg->argv[2], "port")))
			{
				port = atoi (arg->argv[3]);
			}
			else
			{
				port = 444;
			}
			
			srv = (n2server *) pool_alloc (sizeof (n2server));
			srv->host = addr;
			srv->port = port;
			srv->next = NULL;
			srv->lastpacket = NULL;
			srv->key[0] = 0;
			
			if (CONF.servers)
			{
				crs = CONF.servers;
				while (crs->next) crs = crs->next;
				crs->next = srv;
			}
			else
			{
				CONF.servers = srv;
			}
			
			CROOT = CONF_SERVER;
			curserver = srv;
		}		
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<server> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_server_key (args)                                           *
\* ------------------------------------------------------------------------- */
void conf_server_key (n2arglist *arg)
{
	if (arg->argc > 1)
	{
		strncpy (curserver->key, arg->argv[1], 63);
		curserver->key[63] = 0;
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<key> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_iflist (args)                                               *
\* ------------------------------------------------------------------------- */
void conf_iflist (n2arglist *arg)
{
	int i;
	CONF.ifcount = arg->argc - 1;
	CONF.interfaces = pool_calloc (CONF.ifcount * sizeof (n2if));
	for (i=0; i<CONF.ifcount; ++i)
	{
		strncpy (CONF.interfaces[i].ifname, arg->argv[i+1], 31);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_iolist (args)                                               *
\* ------------------------------------------------------------------------- */
void conf_iolist (n2arglist *arg)
{
	int i;
	CONF.iocount = arg->argc - 1;
	CONF.iodevices = pool_calloc (CONF.iocount * sizeof (n2io));
	for (i=0; i<CONF.iocount; ++i)
	{
		strncpy (CONF.iodevices[i].devname, arg->argv[i+1], 31);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_modstatus (args)                                            *
\* ------------------------------------------------------------------------- */
void conf_modstatus (n2arglist *arg)
{
	CONF.modstatus = 1;
	fprintf (stderr, "%% WARNING: modstatus statement in configuration is deprecated. Please use\n"
					 "  encoding-options.");
	strncpy (CONF.statusurl, arg->argv[1], 63);
	CONF.statusurl[63] = 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_encode_modstatus (args)                                     *
\* ------------------------------------------------------------------------- */
void conf_encode_modstatus (n2arglist *arg)
{
	if (arg->argc < 3)
	{
		fprintf (stderr, "%% ERROR: Could not parse modstatus encoding statement\n");
		exit (1);
	}
	CONF.modstatus = 1;
	strncpy (CONF.statusurl, arg->argv[2], 63);
	CONF.statusurl[63] = 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_xenvps (args)                                               *
\* ------------------------------------------------------------------------- */
void conf_xenvps (n2arglist *arg)
{
	fprintf (stderr, "%% WARNING: xen statement in configuration is deprecated. Please use\n"
					 "  encoding-options.");
	CONF.xen = 1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_encode_xen (args)                                           *
\* ------------------------------------------------------------------------- */
void conf_encode_xen (n2arglist *arg)
{
	CONF.xen = 1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_init (void)                                                 *
 * -------------------------                                                 *
 * Initializes configuration-related globals.                                *
\* ------------------------------------------------------------------------- */
void conf_init (void)
{
	struct svc_match *staticmatches[32] = {
		MATCH_NETLOAD,
		MATCH_SSH,
		MATCH_HTTP,
		MATCH_SNMP,
		MATCH_SMTP,
		MATCH_IMAP,
		MATCH_POP3,
		MATCH_FTP,
		MATCH_NNTP,
		MATCH_CRON,
		MATCH_HTTPADMIN,
		MATCH_SQLDB,
		MATCH_NFS,
		MATCH_CIFS,
		MATCH_ATALK,
		MATCH_DNS,
		MATCH_LDAP,
		MATCH_SPAMD,
		MATCH_ROUTING,
		MATCH_INETD,
		MATCH_DHCP,
		MATCH_FIREWALL,
		MATCH_SYSLOG,
		MATCH_PRINTER,
		MATCH_VM,
		MATCH_CHAT,
		MATCH_NONE,
		MATCH_NONE,
		MATCH_NONE,
		MATCH_NONE,
		MATCH_NONE,
		MATCH_NONE
	};
	
	CONF.logfile = NULL;
	CONF.servers = NULL;
	CONF.ifcount = 0;
	CONF.interfaces = NULL;
	CONF.iocount = 0;
	CONF.iodevices = NULL;
	CONF.encoding = ENCODE_LOGINS | ENCODE_TCPSTAT;
	CONF.modstatus = 0;
	CONF.statusurl[0] = 0;
	ACKED = NULL;
	
	memcpy (CONF.matches, staticmatches, sizeof (staticmatches));
	
	config_changed = 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_service (args)                                              *
\* ------------------------------------------------------------------------- */
void conf_service (n2arglist *arg)
{
	unsigned int pos;
	svc_match *sm = NULL;

	if (arg->argc < 5)
	{
		fprintf (stderr, "%% Error in service statement\n");
		return;
	}
	
	for (pos=0; pos<32; ++pos)
	{
		if (strcmp (STR_SVC[pos], arg->argv[1]) == 0) break;
	}
	
	if (pos == 32)
	{
		fprintf (stderr, "%% Unknown service '%s'\n", arg->argv[1]);
		return;
	}
	
	sm = malloc (2*sizeof (svc_match));
	CONF.matches[pos] = sm;
	sm[1].name = NULL;
	sm[1].owner = NULL;
	sm[1].port = 0;
	
	sm[0].name = strdup (arg->argv[2]);
	sm[0].owner = strdup (arg->argv[3]);
	sm[0].port = atoi (arg->argv[4]);
	
	// FIXME: implement
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_host_group (args)                                           *
\* ------------------------------------------------------------------------- */
void conf_host_group (n2arglist *arg)
{
	if (arg->argc == 2)
	{
		curhostgroup = hostgroup_resolve (arg->argv[1]);
		if (! curhostgroup)
		{
			curhostgroup = hostgroup_create (arg->argv[1]);
		}
		if (! curhostgroup)
		{
			fprintf (stderr, "%% Error accessing host-group\n");
		}
		else
		{
			CROOT = CONF_HOST_GROUP;
		}
	}
	else
	{
		fprintf (stderr, "%% Syntax error in configuration file "
						 "<host-group> statement\n");
		exit (1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_member_host (args)                                    *
\* ------------------------------------------------------------------------- */
void conf_group_member_host (n2arglist *arg)
{
	unsigned long addr;

	if (arg->argc == 3)
	{
		addr = atoip (arg->argv[2]);
		hostgroup_acl_create (curhostgroup, addr, 0xffffffff);
	}
	else
	{
		fprintf (stderr, "%% Syntax error <member host>\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_member_network (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_group_member_network (n2arglist *arg)
{
	unsigned long addr;
	unsigned long mask;
	
	if (arg->argc == 4)
	{
		addr = atoip (arg->argv[2]);
		mask = atomask (arg->argv[3]);
		hostgroup_acl_create (curhostgroup, addr, mask);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION argprint (into, maxsz, arglist, startpos)                        *
 * --------------------------------------------------                        *
 * Prints a number of arguments (starting at startpos) into a string.        *
\* ------------------------------------------------------------------------- */
void argprint (char *str, int sz, n2arglist *arg, int pos)
{
	int c;
	
	for (c=pos; c<arg->argc; ++c)
	{
		strncat (str, arg->argv[c], sz-1);
		if ((c+1) < (arg->argc)) strncat (str, " ", sz-1);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_email_addr (args)                                     *
\* ------------------------------------------------------------------------- */
void conf_group_email_addr (n2arglist *arg)
{
	if (arg->argc > 3)
	{
		argprint (curhostgroup->emailaddr, 96, arg, 3);
	}
	else
	{
		fprintf (stderr, "%% Syntax error\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_email_subject (args)                                  *
\* ------------------------------------------------------------------------- */
void conf_group_email_subject (n2arglist *arg)
{
	if (arg->argc > 3)
	{
		argprint (curhostgroup->emailsubject, 96, arg, 3);
	}
	else
	{
		fprintf (stderr, "%% Syntax error\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_email_sender (args)                                   *
\* ------------------------------------------------------------------------- */
void conf_group_email_sender (n2arglist *arg)
{
	if (arg->argc > 3)
	{
		argprint (curhostgroup->emailfrom, 96, arg, 3);
	}
	else
	{
		fprintf (stderr, "%% Syntax error\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_madnotify_url (args)                                  *
\* ------------------------------------------------------------------------- */
void conf_group_madnotify_url (n2arglist *arg)
{
	if (arg->argc > 3)
	{
		argprint (curhostgroup->madurl, 128, arg, 3);
	}
	else
	{
		fprintf (stderr, "%% Syntax error\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_madnotify_user (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_group_madnotify_user (n2arglist *arg)
{
	if (arg->argc > 3)
	{
		argprint (curhostgroup->maduser, 48, arg, 3);
	}
	else
	{
		fprintf (stderr, "%% Syntax error\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_madnotify_pass (args)                                 *
\* ------------------------------------------------------------------------- */
void conf_group_madnotify_pass (n2arglist *arg)
{
	if (arg->argc > 3)
	{
		argprint (curhostgroup->madpass, 48, arg, 3);
	}
	else
	{
		fprintf (stderr, "%% Syntax error\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_alert_trigger (args)                                  *
\* ------------------------------------------------------------------------- */
void conf_group_alert_trigger (n2arglist *arg)
{
	if (arg->argc == 2)
	{
		curhostgroup->trigger = atoi (arg->argv[1]);
	}
	else
	{
		fprintf (stderr, "%% Syntax error\n");
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_group_description (args)                                    *
\* ------------------------------------------------------------------------- */
void conf_group_description (n2arglist *arg)
{
	int pos = 1;
	curhostgroup->description[0] = 0;
	curhostgroup->description[255] = 0;
	
	if (arg->argc < 2) return;
	while (pos < arg->argc)
	{
		if (pos>1)
		{
			strncat (curhostgroup->description, " ", 254);
		}
		strncat (curhostgroup->description, arg->argv[pos], 254);
		pos++;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_encode_logins (args)                                        *
\* ------------------------------------------------------------------------- */
void conf_encode_logins (n2arglist *arg)
{
	CONF.encoding = CONF.encoding | ENCODE_LOGINS;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_no_encode_logins (args)                                     *
\* ------------------------------------------------------------------------- */
void conf_no_encode_logins (n2arglist *arg)
{
	CONF.encoding = CONF.encoding & (! ENCODE_LOGINS);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_encode_tcpstat (args)                                       *
\* ------------------------------------------------------------------------- */
void conf_encode_tcpstat (n2arglist *arg)
{
	CONF.encoding = CONF.encoding | ENCODE_TCPSTAT;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_no_encode_tcpstat (args)                                    *
\* ------------------------------------------------------------------------- */
void conf_no_encode_tcpstat (n2arglist *arg)
{
	CONF.encoding = CONF.encoding & (! ENCODE_TCPSTAT);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_no_host_group (arg)                                         *
\* ------------------------------------------------------------------------- */
void conf_no_host_group (n2arglist *arg)
{
	hostgroup *c, *nc;
	if (arg->argc < 3)
	{
		printf ("%% Not enough arguments for 'no host-group'\n");
		return;
	}
	c = GROUPS.groups;
	nc = c->next;
	
	if (! strcmp (c->name, arg->argv[2]))
	{
		GROUPS.groups = nc;
		pool_free (c);
		return;
	}

	while (nc)
	{
		if (! strcmp (nc->name, arg->argv[2]))
		{
			c->next = nc->next;
			pool_free (nc);
			return;
		}
		c = nc;
		nc = c->next;
	}
	printf ("%% No such host-group: %s\n", arg->argv[2]);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_no_monitor_group (arg)                                      *
\* ------------------------------------------------------------------------- */
void conf_no_monitor_group (n2arglist *arg)
{
	unsigned int addr;
	unsigned int mask;
	acl *c, *pc;
	
	if (arg->argc < 4)
	{
		printf ("%% Not enough arguments for 'no monitor-group'\n");
		return;
	}
	
	addr = atoip (arg->argv[2]);
	mask = atomask (arg->argv[3]);
	
	pc = NULL;
	c = ACL;
	
	while (c)
	{
		if ( (c->addr == addr) && (c->mask == mask) )
		{
			if (pc)
			{
				pc->next = c->next;
			}
			else
			{
				ACL = c->next;
			}
			pool_free (c);
			return;
		}
		pc = c;
		c = pc->next;
	}
	
	printf ("%% No such monitor-group\n");
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_host_group_no (arg)                                         *
 * ---------------------------------                                         *
 * Reset parameters having to do with a host-group.                          *
\* ------------------------------------------------------------------------- */
#define HGNUKE(foo) (curhostgroup->foo[0]=0)

void conf_host_group_no (n2arglist *arg)
{
	char *cmd;
	char *sub;
	char *leaf;
	unsigned int addr;
	unsigned int mask;
	hostgroup_acl *ha, *nha;
	int i;
	
	if (! curhostgroup)
	{
		printf ("%% Not in host-group context\n");
		return;
	}
	if (arg->argc < 4)
	{
		printf ("%% Insufficient arguments\n");
		return;
	}

	cmd = arg->argv[1];
	sub = arg->argv[2];
	leaf = arg->argv[3];
	
	if (! strcmp (cmd, "notification"))
	{
		if (! strcmp (sub, "email"))
		{
			if (! strcmp (leaf, "address")) { HGNUKE(emailaddr); return; }
			if (! strcmp (leaf,"subject")) { HGNUKE(emailsubject); return; }
			if (! strcmp (leaf, "sender")) { HGNUKE(emailfrom); return; }
			printf ("%% Unknown parameter %s %s\n", sub, leaf);
			return;
		}
		else if (! strcmp (sub, "madnotify"))
		{
			if (! strcmp (leaf, "url")) { HGNUKE(madurl); return; }
			if (! strcmp (leaf, "username")) { HGNUKE(maduser); return; }
			if (! strcmp (leaf, "password")) { HGNUKE(madpass); return; }
			printf ("%% Unknown parameter %s %s\n", sub, leaf);
			return;
		}
		else
		{
			printf ("%% Unknown notification category %s\n", sub);
			return;
		}
	}
	else if (! strcmp (cmd, "member"))
	{
		if (! strcmp (sub, "host"))
		{
			addr = atoip (leaf);
			mask = 0xffffffff;
		}
		else if (! strcmp (sub, "network"))
		{
			addr = atoip (leaf);
			if (arg->argc < 5)
			{
				printf ("%% Insufficient arguments\n"); return;
			}
			mask = atomask (arg->argv[4]);
		}
		else
		{
			printf ("%% Unknown member specification\n"); return;
		}
		for (i=0; i<256; ++i)
		{
			ha = NULL;
			nha = GROUPS.hash[i];
			while (nha)
			{
				if (nha->group == curhostgroup)
				{
					if ((nha->addr == addr) && (nha->mask == mask))
					{
						if (ha)
						{
							ha->next = nha->next;
						}
						else
						{
							GROUPS.hash[i] = nha->next;
						}
						pool_free (nha);
						return;
					}
				}
				ha = nha;
				nha = ha->next;
			}
		}
		printf ("%% Member not found\n"); return;
	}
	printf ("%% Syntax error: no %s\n", cmd);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION conf_monitor_no                                                  *
 * ------------------------                                                  *
 * Negate/remove parameters having to do with a monitor-group.               *
\* ------------------------------------------------------------------------- */
void conf_monitor_no (n2arglist *arg)
{
	const char *item;
	if (arg->argc < 2)
	{
		printf ("%% Insufficient arguments\n"); return;
	}
	if (! curacl)
	{
		printf ("%% Not in monitor-group context\n"); return;
	}
	
	item = arg->argv[1];
	
	if (!strcmp (item, "rtt-warning"))
	{
		curacl->rtt_warning = 0; return;
	}
	if (!strcmp (item, "rtt-alert"))
	{
		curacl->rtt_alert = 0; return;
	}
	if (!strcmp (item, "loadavg-warning"))
	{
		curacl->loadavg_warning = 0; return;
	}
	if (!strcmp (item, "loadavg-alert"))
	{
		curacl->loadavg_alert = 0; return;
	}
	if (!strcmp (item, "loss-warning"))
	{
		curacl->loss_warning = 0; return;
	}
	if (!strcmp (item, "loss-alert"))
	{
		curacl->loss_alert = 0; return;
	}
	if (!strcmp (item, "sockstate-warning"))
	{
		curacl->sockstate_warning = 0; return;
	}
	if (!strcmp (item, "sockstate-alert"))
	{
		curacl->sockstate_alert = 0; return;
	}
	if (!strcmp (item, "cpu-warning"))
	{
		curacl->cpu_warning = 0; return;
	}
	if (!strcmp (item, "cpu-alert"))
	{
		curacl->cpu_alert = 0; return;
	}
	if (!strcmp (item, "ram-warning"))
	{
		curacl->ram_warning = 0; return;
	}
	if (!strcmp (item, "ram-alert"))
	{
		curacl->ram_alert = 0; return;
	}
	if (!strcmp (item, "swap-warning"))
	{
		curacl->swap_warning = 0; return;
	}
	if (!strcmp (item, "swap-alert"))
	{
		curacl->swap_alert = 0; return;
	}
	if (!strcmp (item, "netin-warning"))
	{
		curacl->netin_warning = 0; return;
	}
	if (!strcmp (item, "netin-alert"))
	{
		curacl->netin_alert = 0; return;
	}
	if (!strcmp (item, "netout-warning"))
	{
		curacl->netout_warning = 0; return;
	}
	if (!strcmp (item, "netout-alert"))
	{
		curacl->netout_alert = 0; return;
	}
	if (!strcmp (item, "key"))
	{
		curacl->key[0] = 0; return;
	}
	printf ("%% Unknown host-group option %s\n", item);
}

void conf_version (n2arglist *arg)
{
}
