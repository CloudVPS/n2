#include "datatypes.h"
#include "n2diskdb.h"
#include "n2encoding.h"
#include "iptypes.h"
#include "n2acl.h"
#include "n2config.h"
#include "n2malloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION main (argc, argv)                                                *
 * --------------------------                                                *
 * Goes over configured host-groups and fishes for hosts in /var/state/n2    *
 * for some summary information. Prints out the information either in a CSV  *
 * format (default), in XML (with -x) or as tabulated human-readable data    *
 * (with -f). An optional groupname argument will limit the scope of the     *
 * search to a single host-group.                                            *
\* ------------------------------------------------------------------------- */
int main (int argc, char *argv[])
{
	DIR *dir;
	struct dirent *de;
	char *name;
	unsigned int addr;
	hostgroup *grp;
	int first=1;
	netload_rec *rec;
	netload_info *info;
	unsigned long long netin, netout;
	int numwarn, numalert, numcrit;
	int rtt, count;
	int asxml;
	int ascsv;
	int op;
	char outline[256];
	const char *groupname = NULL;
	
	asxml = 0;
	ascsv = 1;
	
	while ((op = getopt (argc, argv, "xfg:")) > 0)
	{
		switch (op)
		{
			case 'x': asxml=1; ascsv=0; break;
			case 'f': ascsv=0; asxml=0; break;
			case 'g': groupname=optarg; break;
		}
	}
	
	conf_init ();
	acl_init ();
	load_config ("/etc/n2/n2rxd.conf");
	
	if (asxml)
	{
		printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
		printf ("<nl.madscience.svc.n2.groups>\n");
	}
	else if (! ascsv)
	{
		printf ("Host              Status   Load      CPU    RTT   "
				"Loss  Net In/    Out     i/o\n");
				//                    Kb/s   "
	}
	
	grp = GROUPS.groups;
	
	while (grp)
	{
		if ((! groupname) || (! strcmp (groupname, grp->name)))
		{
			netin = netout = 0;
			numwarn = numalert = numcrit = rtt = count = 0;
			if (ascsv)
			{
				if (ascsv) printf ("%s:", grp->name);
			}
			else if (asxml)
			{
				printf ("  <group name=\"%s\" description=\"%s\">\n",
											grp->name, grp->description);
				printf ("    <members>\n");
			}
			first = 1;
			dir = opendir ("/var/state/n2/current");
			while (de = readdir (dir))
			{
				if (strlen (de->d_name) > 4)
				{
					addr = atoip (de->d_name);
					if (grp == hostgroup_acl_resolve (addr))
					{
						if (asxml)
						{
							printf ("      <member ip=\"%s\"", de->d_name);
						}
						else if (ascsv)
						{
							printf ("%s%s", first ? "" : " ", de->d_name);
						}
						first = 0;
						info = NULL;
						rec = diskdb_get_current (addr);
						if (rec) info = decode_rec (rec);
						if (info)
						{
							if (asxml)
							{
								printf (" netin=\"%u\" netout=\"%u\" "
										"rtt=\"%.1f\" cpu=\"%.2f\" "
										"loadavg=\"%.2f\" status=\"%s\" "
										"diskio=\"%u\"",
										info->netin, info->netout,
										((double) info->ping10) / 10.0,
										((double) info->cpu) / 2.56,
										((double) info->load1) / 100.0,
										STR_STATUS[info->status & 15],
										info->diskio);
							}
							else if (! ascsv)
							{
								sprintf (outline, "%-17s                  ",
										 de->d_name);
								sprintf (outline+18, "%s        ",
										 STR_STATUS[info->status&15]);
								if (info->status == ST_DEAD)
								{
									sprintf (outline+24, "   -.--   -.-- %% "
											 "%6.1f  %3i %%       -/      -"
											 "       -",
											 ((double)info->ping10) / 10.0,
											 info->loss/100
											);
								}
								else sprintf (outline+24, " %6.2f %6.2f %% "
										 "%6.1f  %3i %% %7i/%7i %7i",
										 ((double) info->load1) / 100.0,
										 ((double) info->cpu) / 2.56,
										 ((double) info->ping10) / 10.0,
										 info->loss/100,
										 info->netin, info->netout,
										 info->diskio);
										 
								printf ("%s\n", outline); 
							}
							netin += info->netin;
							netout += info->netout;
							rtt += info->ping10;
							if (ascsv)
							{
								switch (RDSTATUS(info->status))
								{
									case ST_WARNING:
										printf ("=WARNING");
										++numwarn; break;
									
									case ST_STALE:
									case ST_ALERT:
									case ST_DEAD:
										printf ("=ALERT");
										++numalert; break;
									
									case ST_CRITICAL:
										printf ("=CRITICAL");
										++numcrit; break;
									
									default:
										printf ("=OK");
										break;
								}
							}
							pool_free (info);
						}
						else
						{
							free (rec);
						}
						if (asxml) printf ("/>\n");
						++count;
					}
				}
			}
			if (! asxml)
			{
				if (! count) count=1;
				if (ascsv)
				{
					printf (":%i:%llu:%llu:%.1f:%i:%i:%i\n",
							count, netin, netout,
							((double) rtt / (10.0 * ((double) count))),
							numwarn, numalert, numcrit);
				}
			}
			else if (! ascsv)
			{
				printf ("    </members>\n");
				printf ("    <summary>\n");
				printf ("      <netin>%u</netin>\n", netin);
				printf ("      <netout>%u</netout>\n", netout);
				printf ("      <rtt>%.1f</rtt>\n",
						((double) rtt / (10.0 * ((double) count))));
				printf ("      <counts.warning>%i</counts.warning>\n", numwarn);
				printf ("      <counts.alert>%i</counts.alert>\n", numalert);
				printf ("      <counts.critical>%i</counts.critical>\n",
						numcrit);
				printf ("    </summary>\n");
				printf ("  </group>\n");
			}
		}
		grp = grp->next;
	}
	if (asxml)
	{
		printf ("</nl.madscience.svc.n2.groups>\n");
	}
	exit(0);
}
