#include "n2ping.h"
#include "n2malloc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION read_ping_data (address)                                         *
 * ---------------------------------                                         *
 * Utility function for the main process that reads the stored ping log for  *
 * the provided address from /var/state/n2/ping.                             *
\* ------------------------------------------------------------------------- */
ping_log *read_ping_data (unsigned long addr)
{
	char fname[256];
	ping_log *res;
	FILE *F;
	
	sprintf (fname, "/var/state/n2/ping/%d.%d.%d.%d",
					 (addr & 0xff000000) >> 24,
					 (addr & 0x00ff0000) >> 16,
					 (addr & 0x0000ff00) >> 8,
					 (addr & 0x000000ff));
	
	res = NULL;
	
	F = fopen (fname, "r");
	if (F)
	{
		res = (ping_log *) pool_alloc (sizeof (ping_log));
		fread (res, sizeof (ping_log), 1, F);
		fclose (F);
	}
	
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION calc_ping10 (pinglog)                                            *
 * ------------------------------                                            *
 * Calculates a pingtime average for a backlog of packets from the current   *
 * position of the provided ping_log structure.                              *
\* ------------------------------------------------------------------------- */
unsigned short calc_ping10 (ping_log *r)
{
	int crsr;
	int count;
	int total;
	int done = 0;
	
	total = 0;
	crsr = r->pos & 0xff;
	for (count=0; count<10; ++count)
	{
		crsr = (crsr-1) & 0xff;
		if (r->times[crsr])
		{
			total += r->times[crsr];
			++done;
		}
	}
	if (!done) return 0;
	return (total/done);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION calc_loss (pinglog)                                              *
 * ----------------------------                                              *
 * Calculates the packet loss from the provided ping_log, measured for a     *
 * number of packets backwards from the current position.                    *
\* ------------------------------------------------------------------------- */
unsigned short calc_loss (ping_log *r)
{
	int crsr;
	int count;
	unsigned short total;
	
	total = 0;
	crsr = r->pos & 0xff;
	for (count=0; count<20; ++count)
	{
		crsr = (crsr-1) & 0xff;
		if (r->times[crsr] == 0) total += (10000/20);
	}
	
	return (total);
}
