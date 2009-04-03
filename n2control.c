#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "version.h"

int   show_subsystem_status (void);
pid_t get_subsystem_pid (const char *);
int   get_subsystem_status (const char *);
int   start_subsystem (const char *);
int   stop_subsystem (const char *);
int   reload_subsystem (const char *);
int   restart_subsystem (const char *);
int   get_subsystem_configured (const char *);

/* ------------------------------------------------------------------------- *\
 * FUNCTION show_subsystem_status (void)                                     *
\* ------------------------------------------------------------------------- */
int   show_subsystem_status (void)
{
	printf ("n2rxd: ");
	if (get_subsystem_configured ("n2rxd"))
	{
		if (get_subsystem_status ("n2rxd"))
		{
			printf ("up\n");
		}
		else
		{
			printf ("down\n");
		}
		printf ("n2ping: ");
		if (get_subsystem_status ("n2ping"))
		{
			printf("up\n");
		}
		else
		{
			printf ("down\n");
		}
	}
	else
	{
		printf ("disabled\n");
		printf ("n2ping: disabled\n");
	}
	printf ("n2txd: ");
	if (get_subsystem_configured ("n2txd"))
	{
		if (get_subsystem_status ("n2txd"))
		{
			printf ("up\n");
		}
		else
		{
			printf ("down\n");
		}
	}
	else
	{
		printf ("disabled\n");
	}
	return 0;
}

typedef enum {
    SCOPE_ERR,
	SCOPE_TXD,
	SCOPE_RXD,
	SCOPE_ALL
} scope_t;

#define ISTXD(foo) ((foo==SCOPE_ALL)||(foo==SCOPE_TXD))
#define ISRXD(foo) ((foo==SCOPE_ALL)||(foo==SCOPE_RXD))

/* ------------------------------------------------------------------------- *\
 * FUNCTION main (argc, argv)                                                *
\* ------------------------------------------------------------------------- */
int main (int argc, char *argv[])
{
	scope_t scope = SCOPE_ERR;
	
	if (argc == 1)
	{
		show_subsystem_status ();
		return 0;
	}
	
	if (! strcmp (argv[1], "version"))
	{
		printf ("%s\n", NETLOAD_VERSION);
		return 0;
	}
	
	if (argc > 2)
	{
		if (! strcmp (argv[2], "n2txd")) scope = SCOPE_TXD;
		else if (! strcmp (argv[2], "n2rxd")) scope = SCOPE_RXD;
		else if (! strcmp (argv[2], "all")) scope = SCOPE_ALL;
	}
	else
	{
		if (argc > 1) scope = SCOPE_ALL;
	}
	
	if (scope == SCOPE_ERR)
	{
		fprintf (stderr, "Usage: %s\n"
						 "       %s start|stop|reload [service]\n"
						 "\n"
						 "service: n2txd|n2rxd|all (default: all)\n",
						 argv[0], argv[0]);
		return 1;
	}
	
	if (strcmp (argv[1], "start") == 0)
	{
		if (ISRXD(scope))
		{
			if (get_subsystem_configured ("n2rxd"))
			{
				if (! get_subsystem_status ("n2rxd"))
					start_subsystem ("n2rxd");
				
				if (! get_subsystem_status ("n2ping"))
					start_subsystem ("n2ping");
			}
			else
			{
				fprintf (stderr, "%% Service n2rxd not configured\n");
			}
		}
		if (ISTXD(scope))
		{
			if (get_subsystem_configured ("n2txd"))
			{
				if (! get_subsystem_status ("n2txd"))
					start_subsystem ("n2txd");
			}
			else
			{
				fprintf (stderr, "%% Service n2txd not configured\n");
			}
		}
		return 0;
	}

	if (strcmp (argv[1], "stop") == 0)
	{
		if (ISRXD(scope))
		{
			if (get_subsystem_configured ("n2rxd"))
			{
				if (get_subsystem_status ("n2rxd"))
					stop_subsystem ("n2rxd");
				
				if (get_subsystem_status ("n2ping"))
					stop_subsystem ("n2ping");
			}
			else
			{
				fprintf (stderr, "%% Service n2rxd not configured\n");
			}
		}
		if (ISTXD(scope))
		{
			if (get_subsystem_configured ("n2txd"))
			{
				if (get_subsystem_status ("n2txd"))
					stop_subsystem ("n2txd");
			}
			else
			{
				fprintf (stderr, "%% Service n2txd not configured\n");
			}
		}
		return 0;
	}
	if (strcmp (argv[1], "reload") == 0)
	{
		if (ISRXD(scope))
		{
			if (get_subsystem_configured ("n2rxd"))
			{
				if (get_subsystem_status ("n2rxd"))
					reload_subsystem ("n2rxd");
				else
					fprintf (stderr, "%% err\n");
			}
			else
			{
				fprintf (stderr, "%% Service n2rxd not configured\n");
			}
		}
		if (ISTXD(scope))
		{
			if (get_subsystem_configured ("n2txd"))
			{
				if (get_subsystem_status ("n2txd"))
					reload_subsystem ("n2txd");
				else
					fprintf (stderr, "%% err\n");
			}
			else
			{
				fprintf (stderr, "%% Service n2txd not configured\n");
			}
		}
		return 0;
	}

	if (strcmp (argv[1], "restart") == 0)
	{
		if (ISRXD(scope))
		{
			if (get_subsystem_configured ("n2rxd"))
			{
				if (get_subsystem_status ("n2rxd"))
					restart_subsystem ("n2rxd");
				
				if (get_subsystem_status ("n2ping"))
					restart_subsystem ("n2ping");
			}
			else
			{
				fprintf (stderr, "%% Service n2rxd not configured\n");
			}
		}
		if (ISTXD(scope))
		{
			if (get_subsystem_configured ("n2txd"))
			{
				if (get_subsystem_status ("n2txd"))
					restart_subsystem ("n2txd");
			}
			else
			{
				fprintf (stderr, "%% Service n2txd not configured\n");
			}
		}
		return 0;
	}
	fprintf (stderr, "Usage: %s\n"
					 "       %s start|stop|reload [service]\n"
					 "\n"
					 "service: n2txd|n2rxd|all (default: all)\n",
					 argv[0], argv[0]);
	return 1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION get_subsystem_pid (name)                                         *
\* ------------------------------------------------------------------------- */
pid_t get_subsystem_pid (const char *name)
{
	FILE 	*f;
	char 	 buf[256];
	pid_t	 result;
	
	result = 0;
	sprintf (buf, "/var/run/%s.pid", name);
	if (f = fopen (buf, "r"))
	{
		buf[0] = 0;
		fgets (buf, 255, f);
		result = strtoul (buf, NULL, 10);
		fclose (f);
	}
	return result;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION get_subsystem_status (name)                                      *
\* ------------------------------------------------------------------------- */
int get_subsystem_status (const char *name)
{
	pid_t pid;

	pid = get_subsystem_pid (name);
	if (! pid) return 0;	
	if (! kill (pid, 0)) return 1;
	return 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION start_subsystem (name)                                           *
\* ------------------------------------------------------------------------- */
int start_subsystem (const char *name)
{
	const char *flags;
	if (get_subsystem_status (name))
	{
		fprintf (stderr, "%% Subsystem %s already running\n", name);
		return 0;
	}
	if (! strcmp (name, "n2txd"))
	{
		flags = getenv("N2TXD_ROOT");
		if (system (flags ? "/usr/sbin/n2txd -r" : "/usr/sbin/n2txd"))
		{
			return 0;
		}
		return 1;
	}
	if (! strcmp (name, "n2rxd"))
	{
		if (system ("/usr/sbin/n2rxd"))
		{
			return 0;
		}
		return 1;
	}
	if (! strcmp (name, "n2ping"))
	{
		if (system ("/usr/sbin/n2ping"))
		{
			return 0;
		}
		return 1;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION stop_subsystem (name)                                            *
\* ------------------------------------------------------------------------- */
int stop_subsystem (const char *name)
{
	pid_t pid;
	
	if (get_subsystem_status (name))
	{
		pid = get_subsystem_pid (name);
		if (pid)
		{
			if (kill (pid, SIGTERM))
			{
				fprintf (stderr, "%% Subsystem %s could not be stopped\n", name);
				return 0;
			}
		}
	}
	else
	{
		fprintf (stderr, "%% Subsystem %s was already stopped\n", name);
	}
	return 1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION reload_subsystem (name)                                          *
\* ------------------------------------------------------------------------- */
int reload_subsystem (const char *name)
{
	pid_t pid;
	
	if (get_subsystem_status (name))
	{
		pid = get_subsystem_pid (name);
		if (pid)
		{
			if (kill (pid, SIGHUP))
			{
				fprintf (stderr, "%% Failed\n");
				return 0;
			}
			return 1;
		}
	}
	fprintf (stderr, "%% Subsystem %s could not be contacted\n", name);
	return 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION restart_subsystem (name)                                         *
\* ------------------------------------------------------------------------- */
int restart_subsystem (const char *name)
{
	if (! stop_subsystem (name))
	{
		return 0;
	}
	return start_subsystem (name);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION get_subsystem_confiugred (name)                                  *
\* ------------------------------------------------------------------------- */
int get_subsystem_configured (const char *name)
{
	struct stat st;
	char        fnam[256];
	
	if (strlen (name) > 16) return 0;
	sprintf (fnam, "/etc/n2/%s.conf", name);
	if (stat (fnam, &st)) return 0;
	return 1;
}
