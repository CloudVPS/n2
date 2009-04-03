#include "datatypes.h"
#include "n2diskdb.h"
#include "n2encoding.h"
#include "iptypes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION main (argc, argv)                                                *
 * --------------------------                                                *
 * Loads the current record for a host and prints it out in either a human   *
 * readable or an XML format (with -x).                                      *
\* ------------------------------------------------------------------------- */
extern const char *DECODE_ERROR;

int main (int argc, char *argv[])
{
	char filename[256];
	unsigned long ipaddr;
	netload_rec *rec;
	netload_info *inf;
	unsigned int dt;
	int offs;
	const char *ipstr;
	int xml = 0;
	int printsz = 0;
	unsigned int ondate = 0;
	int attime = 0;
	char *t;
	int i;
	
	if (argc < 2)
	{
		fprintf (stderr, "%% Usage: n2hstat [-x] <ipaddress> [hh:mm [yyyymmdd]]\n");
		return 1;
	}
	if (argc > 2)
	{
		if ((argv[1][0] == '-')&&(argv[1][1] == 'x'))
		{
			xml = 1;
		}
		else if ((argv[1][0] == '-')&&(argv[1][1] == 's'))
		{
			xml = 1;
			printsz = 1;
		}
	}
	
	ipstr = xml ? argv[2] : argv[1];
	ipaddr = atoip (ipstr);
	
	if ((argc-xml) > 2)
	{
		t = strchr (argv[xml+2], ':');
		if (! t)
		{
			fprintf (stderr, "%% Illegal time spec\n");
			return 1;
		}
		
		attime = atoi (t+1) + (60 * atoi (argv[xml+2]));
		if ((argc+xml) > 3)
		{
			ondate = strtoul (argv[xml+3], NULL, 10);
		}
		else
		{
			diskdb_now (&ondate, &i);
		}
	}
	
	if (! ondate) rec = diskdb_get_current (ipaddr);
	else
	{
		rec = diskdb_get (ipaddr, ondate, attime);
	}
	if (! rec)
	{
		fprintf (stderr, "%% Could not load disk record\n");
		return 1;
	}
	
	if (printsz)
	{
		printf ("%i\n", rec->pos);
		free (rec);
		return 0;
	}
	
	inf = decode_rec (rec);
	if (! inf)
	{
		fprintf (stderr, "%% Error decoding record: %s\n", DECODE_ERROR);
		return 1;
	}
	
	if (xml)
	{
		print_info_xml (inf, ipaddr, dt, offs);
	}
	else
	{
		print_info (inf, ipaddr);
	}
	pool_free (inf);
	free (rec);
	return 0;
}
