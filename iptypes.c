#include "iptypes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION atoip (string)                                                   *
 * -----------------------                                                   *
 * Converts a dotted quad notation ip address into a 32 bit integer.         *
\* ------------------------------------------------------------------------- */

unsigned int atoip (const char *str)
{
	char *oct2;
	char *oct3;
	char *oct4;
	unsigned long res;
	
	oct2 = strchr (str, '.');
	if (! oct2) return 0;
	oct2++;
	
	oct3 = strchr (oct2, '.');
	if (! oct3) return 0;
	oct3++;
	
	oct4 = strchr (oct3, '.');
	if (! oct4) return 0;
	oct4++;
	
	res = (atoi (str) & 255) << 24 |
		  (atoi (oct2) & 255) << 16 |
		  (atoi (oct3) & 255) << 8 |
		  (atoi (oct4) & 255);
	
	return res;
}

unsigned long cidrmask[33] =
	{0x00000000,
	 0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
	 0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
	 0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
	 0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
	 0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
	 0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
	 0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
	 0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff};

/* ------------------------------------------------------------------------- *\
 * FUNCTION atomask (mask)                                                   *
 * -----------------------                                                   *
 * Converts an ascii indication of a netmask into a proper filtermask.       *
 * It allows any of three styles of mask:                                    *
 * - netmask (255.255.240.0)                                                 *
 * - aclmask (0.0.15.255)                                                    *
 * - cidr (/20)                                                              *
\* ------------------------------------------------------------------------- */

unsigned int atomask (const char *msk)
{
	int cidrsz;
	unsigned long res;
	
	if (*msk == '/')
	{
		cidrsz = atoi (msk+1);
		if (cidrsz<1) return 0;
		if (cidrsz>32) return 0;
		return cidrmask[cidrsz];
	}
	
	res = atoip (msk);
	if ((res & 0x80000000) == 0)
	{
		res ^= 0xffffffff;
	}
	
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION printip (address, into)                                          *
 * --------------------------------                                          *
 * Prints an ip address as a dotted quad into a string array, which must     *
 * be at least be 16 in size.                                                *
\* ------------------------------------------------------------------------- */

void printip (unsigned int addr, char *into)
{
	sprintf (into, "%i.%i.%i.%i",
				   (addr & 0xff000000) >> 24,
				   (addr & 0x00ff0000) >> 16,
				   (addr & 0x0000ff00) >> 8,
				   addr & 0x000000ff);
}
