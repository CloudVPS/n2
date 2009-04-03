#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

int main (int argc, char *argv[])
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

	//now = time (NULL);
	//tdiff = now - VPS->lastround;
	if (tdiff<0) tdiff = 1;
	//VPS->lastround = now;

	curvps[0] = 0;	
	inf->nxenvps = 0;
	
	fxm = fopen ("/var/run/zero1-guestinfo.xml", "r");
	if (! fxm) return 1;
	
	while (! feof (fxm))
	{
		buf[0] = 0;
		fgets (buf, 512, fxm);
		buf[511] = 0;
		
		if (strlen (buf))
		{
			if ((! strncmp (buf, "\t</dict>", 8)) && (*curvps))
			{
				if (strlen (curvps))
				{
					printf ("setvps %s %i %i %i\n", curvps,curcpu,curmem,curiops);
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
			
			if (! strncmp (c, "<integer id=\"ioblkps\">", 22))
			{
				curiops = atoi (c+22);
			}
			
		}
	}
	
	fclose (fxm);
	return 0;
}