#include "iptypes.h"
#include "n2hostlog.h"
#include <stdio.h>
#include <string.h>

int main (int argc, char *argv[])
{
	unsigned long ipaddr;
	char logtext[1024];
	logtext[0] = 0;
	logtext[1023] = 0;
	int i;
	
	if (argc<3)
	{
		fprintf (stderr, "Usage: %s <ip> <text>", argv[0]);
		return 1;
	}
	
	ipaddr = atoip (argv[1]);
	if (! ipaddr)
	{
		fprintf (stderr, "Unknown address: %s\n", argv[1]);
		return 1;
	}
	
	for (i=2; i<argc; ++i)
	{
		if (i>2) strncat (logtext, " ", 1023);
		strncat (logtext, argv[i], 1023);
	}
	
	hostlog (ipaddr, ST_UNSET, ST_UNSET, 0, logtext);
	return 0;
}
