#include "n2hostlog.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION load_hostlog (address)                                           *
 * -------------------------------                                           *
 * Loads the eventlog for a host from disk.                                  *
\* ------------------------------------------------------------------------- */
n2hostlog *load_hostlog (unsigned int addr)
{
	n2hostlog 	*log;
	FILE       	*fno;
	char      	 fname[256];
	struct stat	 st;
	const char 	*newlogtxt = "Logfile created";
	int          createnew = 0;
	
	log = (n2hostlog *) calloc (sizeof (n2hostlog), 1);
	
	sprintf (fname, "/var/state/n2/events/%d.%d.%d.%d",
					 (addr & 0xff000000) >> 24,
					 (addr & 0x00ff0000) >> 16,
					 (addr & 0x0000ff00) >> 8,
					 (addr & 0x000000ff));
	
	if (stat (fname, &st)) createnew = 1;
	else
	{
		/* Get rid of old 16-record logs with no oflags */
		if (st.st_size == 2052)
		{
			createnew = 1;
			newlogtxt = "New version 2 logfile created (64 entries)";
		}
	}
	
	if (! createnew)
	{
		fno = fopen (fname, "r");
		if (! fno) createnew = 1;
	}
	
	if (createnew)
	{
		log->entries[63].ts = time (NULL);
		log->entries[63].len = strlen (newlogtxt);
		strcpy (log->entries[63].text, newlogtxt);
		log->pos = 62;
		return log;
	}
	
	fread (log, sizeof (n2hostlog), 1, fno);
	fclose (fno);
	return log;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION save_hostlog (address, log)                                      *
 * ------------------------------------                                      *
 * Saves the hostlog structure for the provided address to disk.             *
\* ------------------------------------------------------------------------- */
void save_hostlog (unsigned int addr, n2hostlog *log)
{
	FILE	*fno;
	char	 fname[256];
	char	 tname[256];

	sprintf (fname, "/var/state/n2/events/%d.%d.%d.%d",
					 (addr & 0xff000000) >> 24,
					 (addr & 0x00ff0000) >> 16,
					 (addr & 0x0000ff00) >> 8,
					 (addr & 0x000000ff));
					 
	strcpy (tname, fname);
	strcat (tname, ".tmp");

	fno = fopen (tname, "w");
	if (! fno) return;
	if (fwrite (log, sizeof(n2hostlog), 1, fno) > 0)
	{
		rename (tname, fname);
	}
	fclose (fno);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hostlog (address, oldstatus, newstatus, logtext)                 *
 * ---------------------------------------------------------                 *
 * Adds a log entry to the event log for the provided host, or creates a new *
 * logfile if there was none.                                                *
\* ------------------------------------------------------------------------- */
void hostlog (unsigned int addr, status_t ostat, status_t nstat,
			  oflag_t oflags, const char *logtext)
{
	n2hostlog *log;
	int		   sl;
	int		   pos;

	log = load_hostlog (addr);
	if (! log) return;
	
	pos = log->pos = (log->pos +1) & 63;
	memset (log->entries[pos].text, 0, 117);
	sl = strlen (logtext);
	if (sl > 116) sl = 116;
	
	log->entries[pos].ts = time (NULL);
	log->entries[pos].ostatus = ostat;
	log->entries[pos].nstatus = nstat;
	log->entries[pos].oflags = oflags;
	log->entries[pos].len = sl;
	strncpy (log->entries[pos].text, logtext, sl);
	log->entries[pos].text[sl] = 0;
	save_hostlog (addr, log);
	free (log);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION make_flag_string (outstr, status, oflags)                        *
 * --------------------------------------------------                        *
 * Builds a string pointing out all the problems recorded in the status.     *
\* ------------------------------------------------------------------------- */
void make_flag_string (char *flagstr, status_t st, oflag_t oflags)
{
	int bit;
	flagstr[0] = 0;
	for (bit=0; bit<3; ++bit)
	{
		if (st & (1 << (bit+4)))
		{
			if (*flagstr) strcat (flagstr, ",");
			strcat (flagstr, STR_STATUSFLAGS[bit]);
		}
	}
	for (bit=0; bit<32; ++bit)
	{
		if (oflags & (1 << bit))
		{
			if (*flagstr) strcat (flagstr, ",");
			strcat (flagstr, STR_OFLAGS[bit]);
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION print_hostlog (addr)                                             *
 * -----------------------------                                             *
 * Loads and prints out the eventlog file for the provided host.             *
\* ------------------------------------------------------------------------- */
void print_hostlog (unsigned int addr)
{
	n2hostlog	*log;
	int			 crsr;
	int			 count;
	status_t	 st;
	time_t		 ti;
	char		 dstr[32];
	char		 flagstr[512];
	
	log = load_hostlog (addr);
	if (! log) return;
	
	crsr = (log->pos) & 63;
	
	for (count=0; count<64; ++count)
	{
		if ((ti = log->entries[crsr].ts))
		{
			ctime_r (&ti, dstr);
			dstr[19] = 0;
			st = log->entries[crsr].nstatus;
			
			printf ("%s [%5s] %s",
					dstr+4,
					STR_STATUS[RDSTATUS(st)],
					log->entries[crsr].text);
			
			if ((RDSTATUS(st) > ST_OK) && (RDSTATUS(st) < ST_STALE))
			{
				if (st & 0xf0)
				{
					make_flag_string (flagstr, st, log->entries[crsr].oflags);
					printf (" (Problems: %s)", flagstr);
				}
			}
			printf ("\n");
		}
		crsr = (crsr - 1) & 15;
	}
	free (log);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION print_hostlog (addr)                                             *
 * -----------------------------                                             *
 * Loads and prints out the eventlog file for the provided host as xml.      *
\* ------------------------------------------------------------------------- */
void print_hostlog_xml (unsigned int addr)
{
	struct tm	*ttm;
	time_t		 ti;
	n2hostlog	*log;
	int			 crsr;
	int			 count;
	char		 dstr[32];
	char		 flagstr[512];
	int			 bit;
	char		 encbuffer[1024];
	int			 i,j;
	char		 c;
	
	log = load_hostlog (addr);
	if (! log)
	{
		printf ("  <events/>\n");
		return;
	}
	
	crsr = (log->pos +1) & 63;
	printf ("  <events>\n");
	
	for (count=0; count<64; ++count)
	{
		if ((ti = log->entries[crsr].ts))
		{
			encbuffer[0] = 0;
			j = 0;
			for (i=0; (j<1000) && log->entries[crsr].text[i]; ++i)
			{
				c = log->entries[crsr].text[i];
				if (c == '<')
				{
					encbuffer[j++] = '&';
					encbuffer[j++] = 'l';
					encbuffer[j++] = 't';
					encbuffer[j++] = ';';
				}
				else if (c == '>')
				{
					encbuffer[j++] = '&';
					encbuffer[j++] = 'g';
					encbuffer[j++] = 't';
					encbuffer[j++] = ';';
				}
				else if (c == '&')
				{
					encbuffer[j++] = '&';
					encbuffer[j++] = 'a';
					encbuffer[j++] = 'm';
					encbuffer[j++] = 'p';
					encbuffer[j++] = ';';
				}
				else
				{
					encbuffer[j++] = c;
				}
			}
			
			encbuffer[j] = 0;
			
			ttm = localtime (&ti);
			sprintf (dstr, "%4i-%02i-%02iT%02i:%02i:%02i",
						   ttm->tm_year + 1900,
						   ttm->tm_mon + 1,
						   ttm->tm_mday,
						   ttm->tm_hour,
						   ttm->tm_min,
						   ttm->tm_sec);
						   
			make_flag_string (flagstr, log->entries[crsr].nstatus,
							  log->entries[crsr].oflags);

			printf ("    <event ts=\"%s\" oldstatus=\"%s\" "
			        "newstatus=\"%s\" flagged=\"%s\">%s</event>\n",
			        dstr, STR_STATUS[log->entries[crsr].ostatus & 15],
			        STR_STATUS[log->entries[crsr].nstatus & 15],
			        flagstr, encbuffer);
		}
		crsr = (crsr + 1) & 63;
	}
	free (log);
	printf ("  </events>\n");
}
