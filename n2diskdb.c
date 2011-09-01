#include "n2diskdb.h"
#include "datatypes.h"
#include "iptypes.h"
#include "n2encoding.h"

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_now (date, index)                                         *
 * ---------------------------------                                         *
 * Gathers the current time and turns it into an apropriate integer          *
 * representing the date (in the format YYYYMMDD) and an index of the        *
 * current minute (ranging from 0 to 1439 inclusive).                        *
\* ------------------------------------------------------------------------- */
void diskdb_now (unsigned int *tdate, int *tindex)
{
	time_t ti;
	struct tm tim;
	
	ti = time (NULL);
	localtime_r (&ti, &tim);
	
	*tdate = (10000 * (tim.tm_year + 1900)) +
			 (100 * (tim.tm_mon+1)) + tim.tm_mday;
	
	*tindex = (60 * (tim.tm_hour)) + tim.tm_min;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION tdate_sub (date, amount)                                         *
 * ---------------------------------                                         *
 * Subtract a number of days from a tdate.                                   *
\* ------------------------------------------------------------------------- */
unsigned int tdate_sub (unsigned int tdate, int amount)
{
	struct tm tim;
	time_t ti;

	tim.tm_sec = 0;
	tim.tm_min = 0;
	tim.tm_hour = 4;
	tim.tm_mday = tdate % 100;
	tim.tm_mon = ((tdate % 10000) / 100) -1;
	tim.tm_year = (tdate / 10000) - 1900;
	ti = mktime (&tim);
	ti = ti - (amount * 86400);
	localtime_r (&ti, &tim);
	
	return (10000 * (tim.tm_year + 1900)) + 
		   (100 * (tim.tm_mon+1)) + tim.tm_mday;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_setlck (rec)                                              *
 * ----------------------------                                              *
 * Sets the header/trailer lock bytes in a netload_rec structure. A record   *
 * will be written to the diskdb twice. The first time with the lock bytes   *
 * active, the second time with them removed. Another process attempting to  *
 * read a record will notice that either the heading or the trailing lock    *
 * byte has been set if the data was altered by this process at the same     *
 * time it was reading. It can then retry the read operation to fetch the    *
 * updated record.                                                           *
 *                                                                           *
 * The netload_rec size data will be unscrewed if it has a bogus value.      *
 * Purely for integrity's sake it might be better to bitch out loud and stop *
 * acting on the record, but that kind of checking may be better done at     *
 * the receive stage.                                                        *
\* ------------------------------------------------------------------------- */
void diskdb_setlck (netload_rec *rec)
{
	unsigned char hiby, loby;
	unsigned char lockid;
	int sz;
	
	hiby = rec->data[3];
	loby = rec->data[2];
	
	sz = loby + (hiby << 8);
	if (sz > 640)
	{
		hiby = 2;
		loby = 128;
		
		rec->data[3] = hiby;
		rec->data[2] = loby;
		sz = 640;
	}
	
	lockid = rand() & 0xff;

	rec->data[0] = lockid;
	rec->data[sz-1] = lockid;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_locked (rec)                                              *
 * ----------------------------                                              *
 * Determines whether a loaded record was locked.                            *
\* ------------------------------------------------------------------------- */
int diskdb_locked (netload_rec *rec)
{
	unsigned char hiby, loby;
	int sz;
	
	hiby = rec->data[3];
	loby = rec->data[2];
	
	sz = loby + (hiby << 8);
	if (sz > 640)
	{
		hiby = 2;
		loby = 128;
		
		rec->data[3] = hiby;
		rec->data[2] = loby;
		sz = 640;
	}
	
	if (rec->data[0] != rec->data[sz-1]) return 1;
	return 0;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_open (host, date)                                         *
 * ---------------------------------                                         *
 * Looks for a diskdb in /var/state/n2/log matching the provided host        *
 * address and date. If none was found, this function will attempt to create *
 * a fresh database file with the required filename.                         *
\* ------------------------------------------------------------------------- */
FILE *diskdb_open (unsigned long host, unsigned int date)
{
	char filename[256];
	char dirname[256];
	char ipstr[32];
	struct stat statbuf;
	char *nullblock;
	FILE *res;
	int i;
	
	printip (host, ipstr);
	sprintf (dirname, "/var/state/n2/log/%s", ipstr);
	sprintf (filename, "/var/state/n2/log/%s/%s-%u.n2db", ipstr, ipstr, date);

	if (stat (dirname, &statbuf) != 0) mkdir (dirname, 0750);	
	
	if (stat (filename, &statbuf)) /* true if the file doesn't exist */
	{
		res = fopen (filename, "a+");
		if (! res)
		{
			fprintf (stderr, "diskdb_open: Could not create: %s: %s\n",
					 filename, strerror (errno));
			return NULL;
		}
		
		nullblock = (char *) calloc (1, (size_t) 92160);
		
		for (i=0; i<10; ++i)
		{
			fwrite (nullblock, (size_t) 92160, 1, res);
		}
		
		free (nullblock);
		fclose (res);
		res = fopen (filename, "r+");
		fseek (res, 0, SEEK_SET);
	}
	else
	{
		res = fopen (filename, "r+");
		if (! res)
		{
			fprintf (stderr, "diskdb_open: Could not open: %s: %s\n",
					 filename, strerror (errno));
			return NULL;
		}
		fseek (res, 0, SEEK_SET);
	}
	
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_setcurrent (host, rec)                                    *
 * --------------------------------------                                    *
 * Writes the provided record to /var/state/n2/current atomically, then      *
 * calls diskdb_store to write the record to the database as well, using     *
 * the current date/time as an index reference.                              *
\* ------------------------------------------------------------------------- */
void diskdb_setcurrent (unsigned long host, netload_rec *rec)
{
	char tempfilename[256];
	char permfilename[256];
	char ipstr[32];
	FILE *f;
	unsigned int date;
	int index;
	
	diskdb_now (&date, &index);
	
	printip (host, ipstr);
	sprintf (tempfilename, "/var/state/n2/tmp/%s", ipstr);
	sprintf (permfilename, "/var/state/n2/current/%s", ipstr);
	
	f = fopen (tempfilename, "w");
	if (! f)
	{
		fprintf (stderr, "diskdb_setcurrent: Could not open: %s: %s\n",
				 tempfilename, strerror (errno));
		return;
	}
	
	fwrite (rec, (size_t) 640, 1, f);
	fclose (f);
	rename (tempfilename, permfilename);

	diskdb_store (host, rec, date, index);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_store (host, rec, date, index)                            *
 * ----------------------------------------------                            *
 * Writes a record to the apropriate database file.                          *
\* ------------------------------------------------------------------------- */
void diskdb_store (unsigned long host, netload_rec *rec,
				   unsigned int date, int index)
{
	FILE *f;
	
	f = diskdb_open (host, date);
	if (! f)
	{
		fprintf (stderr, "diskdb_store: Could not open diskdb\n");
		return;
	}
	
	if (fseek (f, 640 * index, SEEK_SET))
	{
		fprintf (stderr, "diskdb_store: Failed seek offset=%i\n", 640*index);
		fclose (f);
		return;
	}
	
	diskdb_setlck (rec);
	fwrite (rec, (size_t) 640, 1, f);
	fclose (f);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_get (host, date, index)                                   *
 * ---------------------------------------                                   *
 * Reads a record from the disk database. If it runs into a lock it will     *
 * retry a number of times.                                                  *
\* ------------------------------------------------------------------------- */
netload_rec *diskdb_get (unsigned long host, unsigned int date, int index)
{
	int valid;
	int retries;
	FILE *f;
	size_t sz;
	struct stat st;
	char filename[256];
	char oldfilename[256];
	char dirname[256];
	char ipstr[32];
	netload_rec *rec;
	
	valid = 0;
	retries = 0;
	printip (host, ipstr);
	sprintf (filename, "/var/state/n2/log/%s/%s-%u.n2db", ipstr, ipstr, date);
	
	f = fopen (filename, "r");
	if (! f)
	{
		return NULL;
	}
	
	while (! valid)
	{
		if (fseek (f, 640 * index, SEEK_SET))
		{
			fprintf (stderr, "diskdb_get: Failed seek offset=%i\n", 640 * index);
			fclose (f);
			return NULL;
		}
	
		rec = (netload_rec *) calloc (1, sizeof (netload_rec));
	
		if ((sz = fread (rec, 1, 640, f) != 640))
		{
			fprintf (stderr, "diskdb_get: Short read sz=%u\n", sz);
			fclose (f);
			free (rec);
			return NULL;
		}
		
		rec->pos = 4;
		rec->rpos = 2;
		rec->eof = 0;
		sz = rec_read16 (rec);
		rec->pos = sz;
		rec->rpos = 0;
		rec->eof = 0;
		
		if (! diskdb_locked (rec))
		{
			valid = 1;
		}
		else
		{
			++retries;
			if (retries > 8)
			{
				fprintf (stderr, "diskdb_get: Stale lock, overriding\n");
				valid = 1;
			}
			else
			{
				free (rec);
				usleep (100);
			}
		}
	}
	
	fclose (f);
	return rec;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_get_current (host)                                        *
 * ----------------------------------                                        *
 * Reads the current from the disk database. If it runs into a lock it will  *
 * retry a number of times.                                                  *
\* ------------------------------------------------------------------------- */
netload_rec *diskdb_get_current (unsigned long host)
{
	int valid;
	int retries;
	FILE *f;
	size_t sz;
	char filename[256];
	char ipstr[32];
	netload_rec *rec;
	
	valid = 0;
	retries = 0;
	printip (host, ipstr);
	sprintf (filename, "/var/state/n2/current/%s", ipstr);
	
	f = fopen (filename, "r");
	if (! f)
	{
		fprintf (stderr, "diskdb_get_current: Could not open: %s: %s\n",
				 filename, strerror (errno));
		return NULL;
	}
	
	rec = (netload_rec *) calloc (1, sizeof (netload_rec));

	if ((sz = fread (rec, 1, 640, f) != 640))
	{
		fprintf (stderr, "diskdb_get: Short read sz=%u\n", sz);
		fclose (f);
		free (rec);
		return NULL;
	}
	
	rec->pos = 4;
	rec->rpos = 2;
	rec->eof = 0;
	sz = rec_read16 (rec);
	rec->pos = sz;
	rec->rpos = 0;
	rec->eof = 0;
	
	fclose (f);
	return rec;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION diskdb_get_range (host, date, first, last)                       *
 * ---------------------------------------------------                       *
 * Reads a consecutive list of records from a single database file and       *
 * returns it as an array of netload_rec pointers.                           *
\* ------------------------------------------------------------------------- */
netload_rec **diskdb_get_range (unsigned long host, unsigned int date,
								int first, int last)
{
	int i;
	
	netload_rec **res = (netload_rec **)
		calloc ((last+1-first), sizeof (netload_rec *));

	for (i=first; i<=last; ++i)
	{
		res[i] = diskdb_get (host, date, i);
	}
	
	return res;
}
