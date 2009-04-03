#include "tproc.h"
#include "n2malloc.h"
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <sys/types.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION procrun_init (procrun)                                           *
 * -------------------------------                                           *
 * Initializes the memory of a procrun structure.                            *
\* ------------------------------------------------------------------------- */

void procrun_init (procrun *p)
{
	p->count = 0;
	p->arraysz = 16;
	p->array = (tproc *) pool_alloc (16 * sizeof (tproc));
	bzero (p->array, 16 * sizeof (tproc));
	p->ti_start = time (NULL);
	p->ti_now = time (NULL);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION procrun_findproc (procrun, pid)                                  *
 * ----------------------------------------                                  *
 * Finds the index of a process reference by its process-id.                 *
\* ------------------------------------------------------------------------- */

int procrun_findproc (procrun *p, pid_t pid)
{
	int crsr = 0;
	
	while (crsr < p->count)
	{
		if (p->array[crsr].pid == pid) return crsr;
		++crsr;
	}
	return -1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION procrun_alloc (procrun)                                          *
 * --------------------------------                                          *
 * Looks through the array for a free slot and returns the index, or allocat *
 * a new index at the end and returns that.                                  *
\* ------------------------------------------------------------------------- */

int procrun_alloc (procrun *p)
{
	int crsr = 0;
	
	/* First be on the lookout for a reaped slot */
	while (crsr < p->count)
	{
		/* This slot has been de-allocated */
		if (p->array[crsr].pid == 0)
		{
			p->array[crsr].beat = p->ti_now;
			return crsr;
		}
		++crsr;
	}
	
	if (p->count < p->arraysz)
	{
		crsr = p->count;
		p->array[crsr].beat = p->ti_now;
		p->count++;
		return crsr;
	}
	
	p->arraysz = p->arraysz * 2;
	p->array = (tproc *) pool_realloc (p->array, p->arraysz * sizeof (tproc));
	
	crsr = p->count;
	p->array[crsr].beat = p->ti_now;
	p->count++;
	return crsr;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION procrun_setproc (procrun, pid, utime, stime, uid, gid, title)    *
 * ----------------------------------------------------------------------    *
 * Adds a process to the list or updates the statistics of an already runnin *
 * process.                                                                  *
\* ------------------------------------------------------------------------- */

void procrun_setproc (procrun *p, pid_t pid, unsigned long utime,
					  unsigned long stime, uid_t uid, gid_t gid,
					  const char *ptitle, unsigned short pmem)
{
	int ipos;
	
	ipos = procrun_findproc (p, pid);
	if (ipos < 0)
	{
		ipos = procrun_alloc (p);
		p->array[ipos].pid = pid;
		p->array[ipos].utime_start = utime;
		p->array[ipos].stime_start = stime;
		p->array[ipos].utime_run = 0;
		p->array[ipos].stime_run = 0;
		p->array[ipos].uid = uid;
		p->array[ipos].gid = gid;
		p->array[ipos].beat = p->ti_now;
		p->array[ipos].pcpu = 0;
		p->array[ipos].pmem = pmem;
		strncpy (p->array[ipos].ptitle, ptitle, 47);
		p->array[ipos].ptitle[47] = 0;
	}
	else
	{
		/* Calculate total time spent during sample period */
		p->array[ipos].utime_run = utime - p->array[ipos].utime_start;
		p->array[ipos].stime_run = stime - p->array[ipos].stime_start;
		
		p->array[ipos].pmem = pmem;
		
		p->array[ipos].beat = p->ti_now;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION procrun_calc (procrun)                                           *
 * -------------------------------                                           *
 * Runs through the process table and calculates cpu usage percentages.      *
\* ------------------------------------------------------------------------- */

void procrun_calc (procrun *p)
{
	int crsr;
	unsigned long  ustime;
	unsigned short tdelta;
	
	p->total_ticks = 0;
	tdelta = (p->ti_now - p->ti_start) * CLK_TCK;
	if (tdelta == 0)
	{
		tdelta = 1;
		printf ("CLK_TCK madness!! CLK_TCK=%i\n", CLK_TCK);
	}
	
	for (crsr = 0; crsr < p->count; ++crsr)
	{
		if (p->array[crsr].pid)
		{
			ustime = p->array[crsr].stime_run +
					 p->array[crsr].utime_run;
			
			if (ustime > tdelta) ustime = tdelta;
			p->total_ticks += ustime;
			p->array[crsr].pcpu = (10000 * ustime) / tdelta;
		}
	}
	if (p->total_ticks > (tdelta * p->ncpu))
	{
		p->total_ticks = tdelta * p->ncpu;
	}
	p->pcpu = ((255 * p->total_ticks) / tdelta) / p->ncpu;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION procrun_initsample (procrun)                                     *
 * -------------------------------------                                     *
 * Initializes the timer for a new sample run.                               *
\* ------------------------------------------------------------------------- */

void procrun_initsample (procrun *p)
{
	p->ti_now = time (NULL);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION procrun_newround (procrun)                                       *
 * -----------------------------------                                       *
 * Resets timers and counters for all processes to prep for a new round.     *
\* ------------------------------------------------------------------------- */

void procrun_newround (procrun *p)
{
	int crsr;
	
	for (crsr = 0; crsr < p->count; ++crsr)
	{
		if (p->array[crsr].pid)
		{
			/* expire processes that disappeared */
			if ((p->ti_now - p->array[crsr].beat) > 10)
			{
				p->array[crsr].pid = 0;
			}
			else
			{
				p->array[crsr].utime_start += p->array[crsr].utime_run;
				p->array[crsr].stime_start += p->array[crsr].stime_run;
				p->array[crsr].utime_run    = 0;
				p->array[crsr].stime_run    = 0;
				p->array[crsr].pcpu         = 0;
				p->array[crsr].beat			= p->ti_now;
			}
		}
	}
	
	p->ti_start = p->ti_now;
}
