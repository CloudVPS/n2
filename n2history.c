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
  NPROC
} stype;

/* ------------------------------------------------------------------------- *\
 * FUNCTION main (argc, argv)                                                *
 * --------------------------                                                *
 * Goes over an hour, a day or a week of data and spews out data about the   *
 * usage of a particular resource for the provided host.                     *
\* ------------------------------------------------------------------------- */

int main (int argc, char *argv[])
{
	unsigned int data[80];
	char filename[256];
	unsigned long ipaddr;
	netload_rec *rec;
	netload_info *inf;
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
	unsigned long long dsum;
	stype what = CPU;
	double divider;
	
	if (argc < 2)
	{
		fprintf (stderr, "%% Usage: n2history <ipaddress>\n");
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
	}
	
	step = 1;
	
	if (argc > 3)
	{
		if (! strcmp (argv[3], "hour")) step = 1;
		else if (! strcmp (argv[3], "day")) step = 24;
		else if (! strcmp (argv[3], "week")) step = 144;
		else if (! strcmp (argv[3], "month")) step = 720;
	}
	
	ipstr = argv[1];
	ipaddr = atoip (ipstr);
	diskdb_now (&dt, &offs);
	dsum = 0;
	
	for (i=0; i<65; ++i)
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
						
						default:
							break;
					}
					
					pool_free (inf);
				}
				free (rec);
			}
		}
		
		dsum += dtotal;
		
		dtotal = dtotal / step;
		datum = dtotal & 0xffffffff;
		if (datum > max) max = datum;
		data[64-i] = datum;
	}
	if (max < 11) max = 11;
	ival = max / 10;
	thresh = max - (ival/2);
	
	printf ("         ,______________________________________________"
			"__________________.\n");
	for (i=0; i<10; ++i)
	{
		printf ("        %c|", (i&1) ? ' ' : '-');
		for (j=1; j<65; ++j)
		{
			if (data[j] >= thresh) fputc ('#', stdout);
			else fputc ((i<9) ? ((j % 5) ? ' ' : '.') : '_', stdout);
		}
		if (! (i&1)) printf ("|-\r%.2f\n", (double) thresh / divider);
		else printf ("|\n");
		thresh -= ival;
	}
	printf ("         `----|----:----|----:----|----:----|----:----|----:"
			"----|----:----'\n");

	switch (step)
	{
		case 24:
			printf ("            -1 day   -20:00    -16:00    -12:00"
					"     -8:00     -4:00\n"); break;
					
		case 144:
			printf ("            -6 days   -5 days   -4 days   -3 days"
					"   -2 days   -1 day\n"); break;
					
		case 720:
			printf ("            -30 days -25 days  -20 days  -15 days"
					"  -10 days   -5 days\n"); break;
					
		default:
			printf ("            -1:00     -0:50     -0:40     -0:30"
					"     -0:20     -0:10\n"); break;
	}
	
	printf ("\n");
	printf ("sum: %llu\n", dsum);
	
	return 0;
}
