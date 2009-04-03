#include "xenvps.h"
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "xenvps.h"

void vpslist_init (vpslist *v)
{
	v->array = NULL;
	v->arraysz = 0;
	v->count = 0;
	v->lastround = 0;
}

void vpslist_setvps (vpslist *v, const char *vpsid, unsigned short pcpu,
					 unsigned int mem, unsigned int iops)
{
	int pos;
	
	pos = vpslist_findvps (v, vpsid);
	if (pos >= 0)
	{
		v->array[pos].pcpu = pcpu;
		v->array[pos].memory = mem;
		v->array[pos].iops = iops;
		v->array[pos].active = 1;
		return;
	}
	
	pos = vpslist_alloc (v);
	if (pos < 0) exit (1);
	
	strncpy (v->array[pos].id, vpsid, 16);
	v->array[pos].id[15] = 0;
	v->array[pos].pcpu = pcpu;
	v->array[pos].memory = mem;
	v->array[pos].iops = iops;
	v->array[pos].active = 1;
}

int vpslist_findvps (vpslist *v, const char *vpsid)
{
	int crsr = 0;
	
	while (crsr < v->count)
	{
		if (! strcmp (v->array[crsr].id, vpsid)) return crsr;
		++crsr;
	}
	
	return -1;
}

int vpslist_alloc (vpslist *v)
{
	if (v->count < v->arraysz) return (v->count++);
	
	if (! v->arraysz)
	{
		v->arraysz = 4;
		v->array = (xenvps *) malloc (4 * sizeof (xenvps));
		v->count = 1;
		return 0;
	}
	
	v->arraysz <<= 1;
	v->array = (xenvps *) realloc (v->array, v->arraysz * sizeof (xenvps));
	if (! v->array) exit (42);
	
	return (v->count++);
}

void vpslist_sweep (vpslist *v, int seconds)
{
	double dsecs;
	double d;
	int c;
	
	dsecs = seconds;
	
	for (c = 0; c < v->count; c++)
	{
		if (v->array[c].active == 0)
		{
			v->array[c].memory = 0;
			v->array[c].pcpu = 0;
			v->array[c].iops = 0;
		}
		v->array[c].active = 0;
	}
}

vpslist *VPS;

void init_xenvps (void)
{
	VPS = (vpslist *) malloc (sizeof (vpslist));
	vpslist_init (VPS);
	VPS->lastround = time (NULL);
}

void insert_vps (netload_info *inf, xenvps *vps)
{
	int i;
	
	for (i=0; i<inf->nxenvps; ++i)
	{
		if (inf->xenvps[i].pcpu <= vps->pcpu)
		{
			if ((i+1) < NR_XENVPS)
			{
				memmove (inf->xenvps+i, inf->xenvps+i+1,
						 (NR_XENVPS-i-1) * sizeof (netload_xenvps));
			}
			
			break;
		}
	}
	
	if (i<NR_XENVPS)
	{
		/*printf ("inserting vps <%s> at pos %i pcpu %i\n", vps->id, i, vps->pcpu);*/
		inf->xenvps[i].pcpu = vps->pcpu;
		strncpy (inf->xenvps[i].id, vps->id, 16);
		inf->xenvps[i].id[15] = 0;
		inf->xenvps[i].iops = vps->iops;
		inf->xenvps[i].memory = vps->memory;
	}
	
	if (i>= inf->nxenvps) inf->nxenvps = i+1;
}


void gather_xenvps (netload_info *inf)
{
	FILE *fxm;
	char buf[512];
	char *c;
	char *cc;
	char curvps[16];
	int curcpu = 0;
	int curmem = 0;
	int curiops = 0;
	time_t now;
	int tdiff;
	int i;

	now = time (NULL);
	tdiff = now - VPS->lastround;
	if (tdiff<0) tdiff = 1;
	VPS->lastround = now;

	curvps[0] = 0;	
	inf->nxenvps = 0;
	
	fxm = fopen ("/var/run/zero1-guestinfo.xml", "r");
	if (! fxm) return;
	
	while (! feof (fxm))
	{
		buf[0] = 0;
		fgets (buf, 512, fxm);
		buf[511] = 0;
		
		if (strlen (buf))
		{
			if ((! strncmp (buf, "\t</dict>", 8)) && (*curvps))
			{
				if (strlen (curvps) && curmem && (curcpu >= 0))
				{
					vpslist_setvps (VPS, curvps, curcpu, curmem, curiops);
				}
				curvps[0] = 0;
				curmem = curcpu = 0;
				curcpu = 0;
				curiops = 0;
				continue;
			}
			
			c = buf;
			while (isspace (*c)) c++;
			
			if (! strncmp (c, "<dict id=\"", 10))
			{
				c += 10;
				cc = strchr (c, '\"');
				if (cc)
				{
					*cc = 0;
					strncpy (curvps, c, 16);
					curvps[15] = 0;
					continue;
				}
			}
			
			if (! strncmp (c, "<integer id=\"cpu\">", 18))
			{
				curcpu = atoi (c+18);
				continue;
			}
			
			if (! strncmp (c, "<integer id=\"memory\">", 21))
			{
				curmem = atoi (c+21);
				continue;
			}
			
			if (! strncmp (c, "<ulong id=\"ioblkps\">", 20))
			{
				curiops = atoi (c+20);
			}
			
		}
	}
	
	fclose (fxm);
	
	for (i=0; i<VPS->count; ++i)
	{
		if (VPS->array[i].active)
			insert_vps (inf, VPS->array+i);
	}

	vpslist_sweep (VPS, tdiff);
}
