#include "datatypes.h"
#include "n2diskdb.h"
#include "n2encoding.h"
#include "iptypes.h"
#include "n2malloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	double divider;
	int h, m;
	
	float s_cpu, s_load1, s_netin, s_netout, s_ping10, s_diskio;
	float s_kmemfree, s_kswapfree;
	
	if (argc < 3)
	{
		fprintf (stderr, "%% Usage: n2dump <ipaddress> <days>\n");
		return 1;
	}
	
	step = 1;
	
	if (argc > 3)
	{
		step = atoi (argv[3]);
	}
	
	printf ("\"Timestamp\",\"CPU %%\",\"LoadAvg\",\"Mbit/s in\","
			"\"Mbit/s out\",\"RTT (ms)\",\"Disk i/o ops/sec\", \"MB Free RAM\", "
			"\"MB Free Swap\"\n");
	
	ipstr = argv[1];
	ipaddr = atoip (ipstr);
	diskdb_now (&dt, &offs);
	
	for (i=0; i<((1440 * atoi (argv[2]))/step); ++i)
	{
		s_cpu = s_load1 = s_netin = s_netout = s_ping10 = s_diskio = 0.0;
		s_kmemfree = s_kswapfree = 0.0;
		
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
					s_cpu += inf->cpu / 2.56;
					s_load1 += inf->load1 / 100.0;
					s_netin += inf->netin / 1024.0;
					s_netout += inf->netout / 1024.0;
					s_ping10 += inf->ping10 / 10.0;
					s_diskio += inf->diskio / 1.0;
					s_kmemfree += inf->kmemfree / 1024.0;
					s_kswapfree += inf->kswapfree / 1024.0;
					
					pool_free (inf);
				}
				
				free (rec);
			}
		}
			
		h = offs/60;
		m = offs%60;
		printf ("\"%i %02i:%02i\",", dt, h, m);
		printf ("%.2f,", s_cpu / (double) step);
		printf ("%.2f,", s_load1 / (double) step);
		printf ("%.3f,", s_netin / (double) step);
		printf ("%.3f,", s_netout / (double) step);
		printf ("%.1f,", s_ping10 / (double) step);
		printf ("%.1f,", s_diskio / (double) step);
		printf ("%.2f,", s_kmemfree / (double) step);
		printf ("%.2f\n", s_kswapfree / (double) step);
	}
	
	return 0;
}
