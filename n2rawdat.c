#include "datatypes.h"
#include "n2diskdb.h"
#include "n2encoding.h"
#include "iptypes.h"
#include "n2malloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  CPU,
  LOAD,
  NETIN,
  NETOUT,
  RTT,
  DISKIO,
  KMEMFREE,
  KSWAPFREE,
  KMEMTOTAL,
  NPROC,
  IOWAIT
} stype;

/* ------------------------------------------------------------------------- *\
 * FUNCTION main (argc, argv)                                                *
 * --------------------------                                                *
 * Goes over an hour, a day or a week of data and spews out data about the   *
 * usage of a particular resource for the provided host.                     *
\* ------------------------------------------------------------------------- */

int main (int argc, char *argv[])
{
	unsigned int data[512];
	char filename[256];
	unsigned long ipaddr;
	netload_rec *rec;
	netload_info *inf;
	double maxdivider = 1.0;
	unsigned int dt;
	int offs;
	int i, j;
	int ii;
	int step;
	const char *ipstr;
	int xml = 0;
	unsigned int max = 0;
	unsigned int thresh;
	unsigned int ival;
	unsigned int datum;
	unsigned long long dtotal;
	stype what = CPU;
	double divider;
	char *t;
	
	if (argc < 2)
	{
		fprintf (stderr, "%% Usage: n2rawdat <ipaddress>\n");
		return 1;
	}
	
	if (argc > 2)
	{
		if (! strcmp (argv[2], "cpu")) { what = CPU; divider = 2.56;}
		else if (! strcmp (argv[2], "load")) { what = LOAD; divider = 100.0; }
		else if (! strcmp (argv[2], "netin"))
		{
			what = NETIN; divider = 1024.0;
		}
		else if (! strcmp (argv[2], "netout"))
		{
			what = NETOUT; divider = 1024.0;
		}
		else if (! strcmp (argv[2], "rtt")) { what = RTT; divider = 10.0; }
		else if (! strcmp (argv[2], "diskio")) { what = DISKIO; divider = 1.0; }
		else if (! strcmp (argv[2], "ram")) { what = KMEMFREE; divider = 1024.0; }
		else if (! strcmp (argv[2], "swap")) { what = KSWAPFREE; divider = 1024.0; }
		else if (! strcmp (argv[2], "totalmem")) { what = KMEMTOTAL; divider = 1024.0; }
		else if (! strcmp (argv[2], "nproc")) { what = NPROC; divider = 1.0; }
		else if (! strcmp (argv[2], "iowait")) { what = IOWAIT; divider = 1.0; }
	}
	
	step = 1;
	
	if (argc > 3)
	{
		step = atoi (argv[3]);
	}
	
	if (argc > 4)
	{
		t = strchr (argv[4], ':');
		if (! t)
		{
			fprintf (stderr, "%% Illegal timespec\n");
			return 1;
		}
		
		offs = atoi (t+1) + (60 * atoi (argv[4]));
		if (argc > 5)
		{
			dt = strtoul (argv[5], NULL, 10);
		}
		else
		{
			diskdb_now (&dt, &i);
		}
	}
	else
	{
		diskdb_now (&dt, &offs);
	}
	
	ipstr = argv[1];
	ipaddr = atoip (ipstr);
	
	for (i=0; i<320; ++i)
	{
		dtotal = 0;
		for (ii=0; ii<step; ++ii)
		{
			--offs;
			if (offs < 0)
			{
				offs = 1439;
				dt = tdate_sub (dt, 1);
			}
			rec = diskdb_get (ipaddr, dt, offs);
			if (rec)
			{
				inf = decode_rec (rec);
				if (inf)
				{
					switch (what)
					{
						case CPU:
							dtotal += inf->cpu; break;
						
						case LOAD:
							dtotal += inf->load1; break;
						
						case NETIN:
							dtotal += inf->netin; break;
						
						case NETOUT:
							dtotal += inf->netout; break;
						
						case RTT:
							dtotal += inf->ping10; break;
						
						case DISKIO:
							dtotal += inf->diskio; break;
						
						case KMEMFREE:
							dtotal += inf->kmemfree; break;
							
						case KSWAPFREE:
							dtotal += inf->kswapfree; break;
							
						case KMEMTOTAL:
							dtotal += inf->kmemfree + inf->kswapfree;
							break;
						
						case NPROC:
							dtotal += inf->nproc; break;
						
						case IOWAIT:
							dtotal += inf->iowait; break;
						
						default:
							break;
					}
					
					pool_free (inf);
				}
				free (rec);
			}
		}
		dtotal = dtotal / step;
		datum = dtotal & 0xffffffff;
		if (datum > max) max = datum;
		data[319-i] = datum;
	}
	
	if (what == CPU) max = 256;
	if (what == IOWAIT) max = 100;
	else if (max < 128) max = 128;
	maxdivider = ((double)max) / 128.0;

	printf ("%f\n", ((double) max) / divider);

	for (i=0; i<320; ++i)
	{
		printf ("%i\n", (int)(((double)data[i]) / maxdivider));
	}
	
	return 0;
}
