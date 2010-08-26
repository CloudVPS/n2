#define IMPLEMENT_ACLPROP 1
#include "n2acl.h"
#include "n2malloc.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

acl *ACL;
n2alias *ALIASES;

/* ------------------------------------------------------------------------- *\
 * FUNCTION init_acl (void)                                                  *
 * ------------------------                                                  *
 * Initializes all acl-related values.                                       *
\* ------------------------------------------------------------------------- */
void acl_init (void)
{
	int i;
	ACL = (acl *) calloc (1, sizeof (acl));
	GROUPS.groups = NULL;
	ALIASES = NULL;
	for (i=0; i<256; ++i) GROUPS.hash[i] = NULL;
	
	ACL->rtt_warning = DEF_RTT_WARNING;
	ACL->rtt_alert = DEF_RTT_ALERT;
	ACL->loadavg_warning = DEF_LOADAVG_WARNING;
	ACL->loadavg_alert = DEF_LOADAVG_ALERT;
	ACL->loss_warning = DEF_LOSS_WARNING;
	ACL->loss_alert = DEF_LOSS_ALERT;
	ACL->sockstate_warning = DEF_SOCKSTATE_WARNING;
	ACL->sockstate_alert = DEF_SOCKSTATE_ALERT;
	ACL->cpu_warning = DEF_CPU_WARNING;
	ACL->cpu_alert = DEF_CPU_ALERT;
	ACL->ram_warning = DEF_RAM_WARNING;
	ACL->ram_alert = DEF_RAM_ALERT;
	ACL->swap_warning = DEF_SWAP_WARNING;
	ACL->swap_alert = DEF_SWAP_ALERT;
	ACL->netin_warning = DEF_NETIN_WARNING;
	ACL->netin_alert = DEF_NETIN_ALERT;
	ACL->netout_warning = DEF_NETOUT_WARNING;
	ACL->netout_alert = DEF_NETOUT_ALERT;
	ACL->diskio_warning = DEF_DISKIO_WARNING;
	ACL->diskio_alert = DEF_DISKIO_ALERT;
	ACL->diskspace_warning = DEF_DISKSPACE_WARNING;
	ACL->diskspace_alert = DEF_DISKSPACE_ALERT;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION acl_match_mask (address,mask)                                    *
 * ----------------------------                                              *
 * Resolves an address+mask to a monitor-group acl.                          *
\* ------------------------------------------------------------------------- */
acl *acl_match_mask (unsigned long addr, unsigned long mask)
{
	acl *res = ACL;
	if (res == NULL) return res;
	
	while (res)
	{
		if ((addr & res->mask) == res->addr)
		{
			if (res->mask == mask) return res;
			res = res->first;
		}
		else res = res->next;
	}
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION acl_match (address)                                              *
 * ----------------------------                                              *
 * Resolves an address to a monitor-group acl.                               *
\* ------------------------------------------------------------------------- */
acl *acl_match (unsigned long addr)
{
	acl *res = NULL;
	acl *crsr = ACL;
	
	if (crsr == NULL) return crsr;
	
	while (crsr)
	{
		if ((addr & crsr->mask) == crsr->addr)
		{
			/* don't break the loop here, we'll just jump to the children to
			   find a more specific match, if none were found we'll bounce off
			   on the crsr->next chain and still have a valid non-NULL res */
			res = crsr;
			crsr = crsr->first;
		}
		else crsr = crsr->next;
	}
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hostgroup_create (name)                                          *
 * --------------------------------                                          *
 * Creates a new named hostgroup and links it in.                            *
\* ------------------------------------------------------------------------- */
hostgroup *hostgroup_create (const char *name)
{
	hostgroup *crsr;
	hostgroup *res = (hostgroup *) pool_calloc (sizeof (hostgroup));

	strncpy (res->name, name, 47);
	res->description[0] = 0;
	crsr = GROUPS.groups;
	if (! crsr)
	{
		GROUPS.groups = res;
		return res;
	}
	while (crsr->next) crsr = crsr->next;
	crsr->next = res;
	return res;
}

unsigned long translate_alias (unsigned long addr)
{
	n2alias *a = ALIASES;
	while (a)
	{
		if (a->from_addr == addr) return a->to_addr;
		a = a->next;
	}
	return addr;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hostgroup_resolve (name)                                         *
 * ---------------------------------                                         *
 * Looks up a hostgroup by its name.                                         *
\* ------------------------------------------------------------------------- */
hostgroup *hostgroup_resolve (const char *name)
{
	hostgroup *crsr;
	
	crsr = GROUPS.groups;
	while (crsr)
	{
		if (! strcmp (name, crsr->name)) return crsr;
		crsr = crsr->next;
	}
	return NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hostgroup_acl_create (group, address, mask)                      *
 * ----------------------------------------------------                      *
 * Creates a membership acl for the provided hostgroup.                      *
\* ------------------------------------------------------------------------- */
void hostgroup_acl_create (hostgroup *grp, unsigned long addr, unsigned long mask)
{
	hostgroup_acl *crsr;
	hostgroup_acl *res;
	int hidx;
	
	res = (hostgroup_acl *) calloc (sizeof (hostgroup_acl), 1);
	res->addr = addr;
	res->mask = mask;
	res->group = grp;
	res->next = NULL;
	
	hidx = (((addr & 0xff000000) >> 24) ^ ((addr & 0xff0000) >> 16)) & 0xff;
	
	crsr = GROUPS.hash[hidx];
	if (crsr == NULL)
	{
		GROUPS.hash[hidx] = res;
		return;
	}
	while (crsr->next != NULL)
	{
		crsr = crsr->next;
	}
	crsr->next = res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hostgroup_acl_resolve (address)                                  *
 * ----------------------------------------                                  *
 * Resolves an address membership to a hostgroup.                            *
\* ------------------------------------------------------------------------- */
hostgroup *hostgroup_acl_resolve (unsigned long addr)
{
	hostgroup_acl *crsr;
	int hidx;
	
	hidx = (((addr & 0xff000000) >> 24) ^ ((addr & 0xff0000) >> 16)) & 0xff;
	crsr = GROUPS.hash[hidx];
	if (! crsr) return NULL;
	
	while (crsr)
	{
		if ( (addr & crsr->mask) == crsr->addr )
		{
			return crsr->group;
		}
		crsr = crsr->next;
	}
	return NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION acl_unlink (acl)                                                 *
 * -------------------------                                                 *
 * Unlinks a linked acl object from its parent and siblings.                 *
\* ------------------------------------------------------------------------- */
void acl_unlink (acl *a)
{
	/* acl has to be a member of something for there to be something
	   to unlink it from */
	if (! a->parent) return;
	
	if (a->prev)
	{
		if (a->next)
		{
			a->prev->next = a->next;
			a->next->prev = a->prev;
			a->next = a->prev = NULL;
		}
		else
		{
			a->prev->next = NULL;
			a->parent->last = a->prev;
			a->next = a->prev = NULL;
		}
	}
	else
	{
		if (a->next)
		{
			a->next->prev = NULL;
			a->parent->first = a->next;
			a->next = a->prev = NULL;
		}
		else
		{
			a->parent->first = a->parent->last = NULL;
			a->next = a->prev = NULL;
		}
	}
}

/*
void acl_dump (void)
{
	acl *c;
	c = ACL;
	while (c)
	{
		printf ("%08x/%08x\n", res->addr, res->mask);
		printf ("  key <%s>\n", res->key);
	}
} */

/* ------------------------------------------------------------------------- *\
 * FUNCTION acl_create (address, bitmask)                                    *
 * --------------------------------------                                    *
 * Allocates and initializes a new monitorgroup acl structure.               *
\* ------------------------------------------------------------------------- */
acl *acl_create (unsigned long addr, unsigned long netmask)
{
	acl *crs = NULL;
	acl *res;
	acl *ncrs; /* Pointer to next-in-list during certain iterations */
	acl *addto = NULL; /* Pointer for potential new parent node */
	
	/* Initialize the new acl structure */
	res 					= (acl *) pool_alloc (sizeof (acl));
	res->prev				= NULL;
	res->next 				= NULL;
	res->parent				= NULL;
	res->first				= NULL;
	res->last				= NULL;
	res->contacts			= 0;
	res->key[0] 			= 0;
	res->flags 				= 0;
	res->rtt_warning		= 0xffff;
	res->rtt_alert			= 0xffff;
	res->loadavg_warning	= 0xffff;
	res->loadavg_alert		= 0xffff;
	res->loss_warning		= 0xffff;
	res->loss_alert			= 0xffff;
	res->sockstate_warning	= 0xffff;
	res->sockstate_alert	= 0xffff;
	res->cpu_warning		= 0xffff;
	res->cpu_alert			= 0xffff;
	res->diskio_warning		= 0xffffffff;
	res->diskio_alert		= 0xffffffff;
	res->ram_warning		= 0xffffffff;
	res->ram_alert			= 0xffffffff;
	res->swap_warning		= 0xffffffff;
	res->swap_alert			= 0xffffffff;
	res->netin_warning		= 0xffffffff;
	res->netin_alert		= 0xffffffff;
	res->netout_warning		= 0xffffffff;
	res->netout_alert		= 0xffffffff;
	res->diskspace_warning	= 0xffff;
	res->diskspace_alert	= 0xffff;
	
	res->addr 				= addr;
	res->mask 				= netmask;
	
	crs = ACL;
	while (crs)
	{
		if (netmask < crs->mask) /* are we a potential supernet? */
		{
			/* Are we _the_ supernet? */
			if ((crs->addr & netmask) == addr)
			{
				/* If res turns out to be root node's supernet, we are
				   handling the devil's spawn, so abort. */
				if (crs->parent == NULL) return NULL;
				
				/* We'll hang the result node under the current parent */
				res->parent = crs->parent;
				
				/* Reset the cursor to the first node of the parent's
				   child list */
				crs = crs->parent->first;
				
				/* Link res at the start of this list, keeping crs pointed
				   at the former first child */
				crs->prev = res;
				res->next = crs;
				crs->parent->first = res;
				
				/* Now we'll go over the rest of the list and take custody
				   of any node that turns out to be a subnet of res, lreaving
				   the rest untouched. */
				while (crs)
				{
					ncrs = crs->next;
					if ((crs->addr & netmask) == addr)
					{
						acl_unlink (crs);
						if (res->last)
						{
							res->last->next = crs;
							crs->prev = res->last;
							res->last = crs;
							crs->parent = res;
						}
						else
						{
							res->first = res->last = crs;
						}
					}
					crs = ncrs;
				}
				return res;
			}
			else crs = crs->next;
		}
		else /* So we're dealing with a (sibling of a) potential supernet
		        of res */
		{
			if ((addr & crs->mask) == crs->addr) /* our supernet? */
			{
				/* iterate down */
				addto = crs;
				if (crs->first) crs = crs->first;
				else crs = NULL;
			}
			else crs = crs->next; /* no, iterate next */
		}
	}
	
	
	
	/* If we arrived here, that means we're to be stuffed under a supernet
	   of res we found in the loop above, assuming we found one (which we
	   should, since the root node at ACL will match 0/0) */
	if (addto != NULL)
	{
		res->parent = addto;
		if (addto->last)
		{
			addto->last->next = res;
			res->prev = addto->last;
			addto->last = res;
		}
		else
		{
			addto->first = addto->last = res;
		}
	}
	
	return res;
}

acl_contact *acl_get_contacts (acl *a)
{
	acl *crsr = a;
	while (crsr)
	{
		if (crsr->contacts) return crsr->contacts;
		crsr = crsr->parent;
	}
	return NULL;
}

void acl_add_contact (acl *a, const char *url)
{
	acl_contact *newc, *c;
	newc = (acl_contact *) malloc (sizeof (acl_contact));
	if (! newc) return;
	
	newc->next = NULL;
	strncpy (newc->contacturl, url, 255);
	newc->contacturl[255] = 0;
	
	c = a->contacts;
	if (! c)
	{
		a->contacts = newc;
		return;
	}
	
	while (c->next) c = c->next;
	c->next = newc;
}

void alias_clear (void)
{
	n2alias *crs;
	n2alias *next;
	
	crs = ALIASES;
	while (crs)
	{
		next = crs->next;
		free (crs);
	}
	
	ALIASES = NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION acl_clear (void)                                                 *
 * -------------------------                                                 *
 * Removes all acl structures from memory.                                   *
\* ------------------------------------------------------------------------- */
void acl_clear (void)
{
	acl *crs;
	acl *next;
	
	crs = ACL;
	while (crs)
	{
		while (crs->first) crs = crs->first;
		next = crs->next;
		if (! next)
		{
			next = crs->parent;
			if (next) next->first = next->last = NULL;
		}
		
		/* Remove all but the root node */
		if (crs != ACL) pool_free (crs);
		else
		{
			/* For the root node, just nuke all links. */
			crs->next = NULL;
			crs->first = NULL;
			crs->last = NULL;
		}
		crs = next;
	}
	
	alias_clear ();
}

#ifdef UNIT_TEST

groupdb GROUPS;

int main (int argc, char *argv[])
{
	#define GENIP(oc1,oc2,oc3,oc4) ((oc1<<24)|(oc2<<16)|(oc3<<8)|oc4)
	acl *a;
	acl_init ();
	a = acl_create (GENIP(10,42,0,0), 0xffff0000);
	a->rtt_warning = 100;
	a->rtt_alert = 120;
	a->ram_warning = 100;
	a->ram_alert = 20;
	a = acl_create (GENIP(10,43,0,0), 0xffffff00);
	a->rtt_warning = 110;
	a->rtt_alert = 130;
	a = acl_create (GENIP(10,44,0,0), 0xffffff00);
	a->ram_warning = 200;
	a->ram_alert = 40;
	a = acl_create (GENIP(10,43,1,1), 0xffffffff);
	a->rtt_warning = 500;
	a->rtt_alert = 800;
	a = acl_create (GENIP(172,16,0,0), 0xfff00000);
	a->diskio_warning = 5000;
	a->diskio_alert = 7000;
	a = acl_create (GENIP(10,0,0,0), 0xff000000);
	a->rtt_warning = 80;
	a->rtt_alert = 100;
	
	acl_clear ();
	a = acl_create (GENIP(10,42,0,0), 0xffff0000);
		a->rtt_warning = 100;
		a->rtt_alert = 120;
		a->ram_warning = 100;
		a->ram_alert = 20;
	a = acl_create (GENIP(10,43,0,0), 0xffffff00);
		a->rtt_warning = 110;
		a->rtt_alert = 130;
		a = acl_create (GENIP(10,44,0,0), 0xffffff00);
		a->ram_warning = 200;
		a->ram_alert = 40;
	a = acl_create (GENIP(10,43,1,1), 0xffffffff);
		a->rtt_warning = 500;
		a->rtt_alert = 800;
		a = acl_create (GENIP(172,16,0,0), 0xfff00000);
		a->diskio_warning = 5000;
		a->diskio_alert = 7000;
	a = acl_create (GENIP(10,0,0,0), 0xff000000);
		a->rtt_warning = 80;
		a->rtt_alert = 100;
	
	a = acl_match (GENIP(158,24,13,11));
	printf ("158.24.13.11 rtt_warning = %i\n", acl_get_rtt_warning (a));
	printf ("158.24.13.11 diskio_warning = %i\n", acl_get_diskio_warning (a));
	a = acl_match (GENIP(10,42,42,42));
	printf ("10.42.42.42 rtt_warning = %i\n", acl_get_rtt_warning (a));
	printf ("10.42.42.42 diskio_warning = %i\n", acl_get_diskio_warning (a));
	a = acl_match (GENIP(10,10,1,1));
	printf ("10.10.1.1 rtt_warning = %i\n", acl_get_rtt_warning (a));
	printf ("10.10.1.1 diskio_warning = %i\n", acl_get_diskio_warning (a));
	a = acl_match (GENIP(10,43,1,1));
	printf ("10.43.1.1 rtt_warning = %i\n", acl_get_rtt_warning (a));
	printf ("10.43.1.1 diskio_warning = %i\n", acl_get_diskio_warning (a));
	a = acl_match (GENIP(172,17,2,172));
	printf ("172.17.2.172 rtt_warning = %i\n", acl_get_rtt_warning (a));
	printf ("172.17.2.172 diskio_warning = %i\n", acl_get_diskio_warning (a));
	
	return 0;
}
#endif
