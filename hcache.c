#include "hcache.h"
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#ifdef DEBUG
 #define dprintf printf
#else
 #define dprintf //
#endif

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_create                                                    *
 * ----------------------                                                    *
 * Creates and initializes a host cache structure.                           *
\* ------------------------------------------------------------------------- */
hcache *hcache_create (void)
{
	hcache *cache = (hcache *) calloc (1, sizeof (hcache));
	pthread_mutexattr_init (&(cache->mutexattr));
	pthread_mutex_init (&(cache->mutex),&(cache->mutexattr));
	return cache;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_resolve (cache, addr)                                     *
 * -------------------------------------                                     *
 * Finds or creates a hcache_node for a specific IP address.                 *
\* ------------------------------------------------------------------------- */
hcache_node *hcache_resolve (hcache *cache, unsigned long addr)
{
	hcache_node *crsr;
	hcache_node *nod;
	
	dprintf ("hcache_resolve(%08x,%08x)\n", cache, addr);
	
	/* The resultcache is a pointer to the last item requested from the
	   cache. This speeds up consecutive calls to hcache_foo() functions
	   some more */
	
	crsr = cache->resultcache;
	if (crsr && (crsr->addr == addr))
	{
		dprintf ("--> in resultcache: %08x\n", cache->resultcache);
		return crsr;
	}

	pthread_mutex_lock (&(cache->mutex));
	
	/* Use the lower octet of the ip address as a hash key */
	crsr = cache->hash[addr & 0xff];
	if (crsr == NULL)
	{
		/* For that key there are no nodes, we will create the
		   first one for this entry */
		nod = (hcache_node *) calloc (1, sizeof (hcache_node));
		dprintf ("--> new hash\n");
		nod->addr = addr;
		nod->ctime = time (NULL);
		nod->isfresh = 1;
		
		cache->hash[addr & 0xff] = nod;
		cache->resultcache = nod;
		pthread_mutex_unlock (&(cache->mutex));
		return nod;
	}
	
	do /* iterate over the linked list */
	{
		if (crsr->addr == addr)
		{
			/* a match, return the happy news */
			dprintf ("--> found cached entry\n");
			cache->resultcache = crsr;
			if (crsr->isfresh)
			{
				if ((time (NULL) - crsr->ctime) > 60) crsr->isfresh = 0;
			}
			pthread_mutex_unlock (&(cache->mutex));
			return crsr;
		}
		if (crsr->next)
		{
			crsr = crsr->next;
		}
		else
		{
			/* No more next nodes, allocate a new one for this
			   entry. */
			dprintf ("--> new node in hash\n");
			nod = (hcache_node *) calloc (1, sizeof (hcache_node));
			nod->addr = addr;
			nod->isfresh = 1;
			nod->ctime = time (NULL);
			
			crsr->next = nod;
			cache->resultcache = nod;
			pthread_mutex_unlock (&(cache->mutex));
			return nod;
		}
	} while (1);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_getlast (cache, addr)                                     *
 * -------------------------------------                                     *
 * Retrieves the last recorded system time for a host at the specified       *
 * address.                                                                  *
\* ------------------------------------------------------------------------- */
unsigned int hcache_getlast (hcache *cache, unsigned long addr)
{
	hcache_node *node;
	
	dprintf ("hcache_getlast (%08x, %08x)\n", cache, addr);
	node = hcache_resolve (cache, addr);
	if (node == NULL) return 0;
	return node->lasttime;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_getstatus (cache, addr)                                   *
 * ---------------------------------------                                   *
 * Retrieves the last recorded status for a host at the specified address.   *
\* ------------------------------------------------------------------------- */
status_t hcache_getstatus (hcache *cache, unsigned long addr)
{
	hcache_node *node;
	
	dprintf ("hcache_getstatus (%08x, %08x)\n", cache, addr);
	node = hcache_resolve (cache, addr);
	if (node == NULL) return 0;
	return node->status;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_getuptime (cache, addr)                                   *
 * ---------------------------------------                                   *
 * Retrieves the last recorded uptime for a host at the specified address.   *
\* ------------------------------------------------------------------------- */
unsigned int hcache_getuptime (hcache *cache, unsigned long addr)
{
	hcache_node *node;
	
	dprintf ("hcache_getstatus (%08x, %08x)\n", cache, addr);
	node = hcache_resolve (cache, addr);
	if (node == NULL) return 0;
	return node->uptime;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_getservices (cache, addr)                                 *
 * -----------------------------------------                                 *
 * Retrieves the service status for a host at the specified address.         *
\* ------------------------------------------------------------------------- */
unsigned int hcache_getservices (hcache *cache, unsigned long addr)
{
	hcache_node *node;
	node = hcache_resolve (cache, addr);
	if (node == NULL) return 0;
	return node->services;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_getoflags (cache, addr)                                   *
 * ---------------------------------------                                   *
 * Retrieves the problem status for a host at the specified address.         *
\* ------------------------------------------------------------------------- */
oflag_t hcache_getoflags (hcache *cache, unsigned long addr)
{
	hcache_node *node = hcache_resolve (cache, addr);
	if (node == NULL) return 0;
	return node->oflags;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_setlast (cache, addr, lasttime)                           *
 * -----------------------------------------------                           *
 * Stores the last recorded system time for a host at the specified          *
 * address.                                                                  *
\* ------------------------------------------------------------------------- */
void hcache_setlast (hcache *cache, unsigned long addr, unsigned int last)
{
	hcache_node *node;
	
	dprintf ("hcache_setlast (%08x, %08x, %08x)\n", cache, addr, last);
	node = hcache_resolve (cache, addr);
	if (node == NULL) return;
	node->lasttime = last;
	node->lastseen = time (NULL);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_setstatus (cache, addr, status)                           *
 * -----------------------------------------------                           *
 * Stores the last recorded status for a host at the specified address.      *
\* ------------------------------------------------------------------------- */
void hcache_setstatus (hcache *cache, unsigned long addr, status_t status)
{
	hcache_node *node;
	
	dprintf ("hcache_setstatus (%08x, %08x, %08x)\n", cache, addr, status);
	node = hcache_resolve (cache, addr);
	if (node == NULL) return;
	node->status = status;
	node->lastseen = time (NULL);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION hcache_setuptime (cache, addr, status)                           *
 * -----------------------------------------------                           *
 * Stores the last recorded uptime for a host at the specified address.      *
\* ------------------------------------------------------------------------- */
void hcache_setuptime (hcache *cache, unsigned long addr, unsigned int upt)
{
	hcache_node *node;
	
	dprintf ("hcache_setuptime (%08x, %08x, %08x)\n", cache, addr, upt);
	node = hcache_resolve (cache, addr);
	if (node == NULL) return;
	node->uptime = upt;
	node->lastseen = time (NULL);
}

void hcache_setservices (hcache *cache, unsigned long addr, unsigned int s)
{
	hcache_node *node;
	node = hcache_resolve (cache, addr);
	if (node == NULL) return;
	node->services = s;
}

void hcache_setoflags (hcache *cache, unsigned long addr, oflag_t oflags)
{
	hcache_node *node = hcache_resolve (cache, addr);
	if (node == NULL) return;
	node->oflags = oflags;
}

