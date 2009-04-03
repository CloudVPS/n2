#include "datatypes.h"
#include "n2diskdb.h"
#include "n2encoding.h"
#include "iptypes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum
{
	SEARCH_USER,
	SEARCH_PID,
	SEARCH_NAME
};

int main (int argc, char *argv[])
{
	unsigned long ipaddr;
	netload_rec **rec;
	netload_info inf;
	unsigned int dt;
	unsigned int addr;
	int offs;
	int search;
	const char *pat;
	unsigned int intpat;
	const char *field;
	int matches;
	int mincpu;
	int i;
	struct tm *ltm;
	time_t ti;

	/* n2pgrep <date> <user|pid|name> <string> */
	
	if (argc<5)
	{
		fprintf (stderr, "%% Usage: %s <addr> <date> user|pid|name <word>"
						 " [mincpu <percentage>]\n"
						 "         <date> := YYYYMMDD | today | yesterday\n",
				 argv[0]);
		return 1;
	}
	
	addr = atoip (argv[1]);
	if (! addr)
	{
		fprintf (stderr, "%% Illegal host description.\n");
		return 1;
	}
	
	dt = strtoul (argv[2], NULL, 10);
	if (! dt)
	{
		if (! strcmp (argv[2], "today"))
		{
			ti = time (NULL);
		}
		else if (! strcmp (argv[2], "yesterday"))
		{
			ti = time (NULL) - 86400;
		}
		else
		{
			fprintf (stderr, "%% Invalid date spec: %s\n", argv[2]);
			return 1;
		}
		ltm = localtime (&ti);
		dt = (10000 * (ltm->tm_year+1900)) + (100 * (ltm->tm_mon+1)) +
			 ltm->tm_mday;
	}
	pat = argv[4];
	intpat = strtoul (pat, NULL, 10);
	mincpu = 0;

	if (! strcmp (argv[3], "user")) search = SEARCH_USER;
	else if (! strcmp (argv[3], "pid")) search = SEARCH_PID;
	else if (! strcmp (argv[3], "name")) search = SEARCH_NAME;
	else
	{
		fprintf (stderr, "%% Error in field argument\n");
		return 1;
	}
	
	if (argc>6)
	{
		if (strcmp (argv[5], "mincpu"))
		{
			fprintf (stderr, "%% Unrecognized option '%s'\n", argv[5]);
			return 1;
		}
		mincpu = 100 * atoi (argv[6]);
	}
	
	rec = diskdb_get_range (addr, dt, 0, 1439);
	for (offs=0; offs<1440; ++offs)
	{
		if (rec[offs] && decode_rec_inline (rec[offs], &inf))
		{
			for (i=0; i<inf.ntop; ++i)
			{
				matches = 0;
				switch (search)
				{
					case SEARCH_USER:
						field = inf.tprocs[i].username;
						if (strstr (field, pat)) matches = 1;
						break;
					
					case SEARCH_PID:
						if (intpat == inf.tprocs[i].pid)
							matches = 1;
						break;
					
					case SEARCH_NAME:
						field = inf.tprocs[i].ptitle;
						if (strstr (field, pat)) matches = 1;
						break;
				}
				if (matches && (inf.tprocs[i].pcpu >= mincpu))
				{
					printf ("%2i:%02i ", offs/60, offs % 60);
					printf ("%7u %-9s %5.2f %s\n", 
							inf.tprocs[i].pid,
							inf.tprocs[i].username,
							(double) inf.tprocs[i].pcpu / 100.0,
							inf.tprocs[i].ptitle);
				}
			}
		}
	}
}
