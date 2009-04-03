#include "iptypes.h"
#include "n2config.h"
#include "n2acl.h"

int main (int argc, char *argv[])
{
	int i;
	FILE *o;
	load_config ("/etc/n2/n2rxd.conf");
	for (i=1; i<argc; ++i)
	{
		parse_cmd (argv[i]);
	}
	o = fopen ("/etc/n2/n2rxd.conf","w");
	if (! o)
	{
		printf ("%% Could not write to configuration\n");
		return 1;
	}
	print_running_rxd (o);
	fclose (o);
	return 0;
}
