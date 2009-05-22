#include "datatypes.h"
#include "n2diskdb.h"
#include "n2encoding.h"
#include "iptypes.h"
#include "n2acl.h"
#include "n2config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

int usage (const char *cmd)
{
	fprintf (stderr, "Usage: %s <ip>\n", cmd);
	return 1;
}

int main (int argc, char *argv[])
{
	acl *a;
	unsigned long addr;
	acl_contact *c = NULL;
	
	if (argc < 2) return usage(argv[0]);
	addr = atoip (argv[1]);
	if (! addr) return 0;
	
	acl_init ();
	load_config ("/etc/n2/n2rxd.conf");
	a = acl_match (addr);
	if (! a) return 0;
	
	c = acl_get_contacts (a);
	while (c)
	{
		printf ("%s\n", c->contacturl);
		c = c->next;
	}
	return 0;
}
