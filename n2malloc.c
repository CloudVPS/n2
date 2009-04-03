#include "n2malloc.h"
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------- *\
 * FUNCTION pool_init (void)                                                 *
 * -------------------------                                                 *
 * Initializes the global POOLS pointer.                                     *
\* ------------------------------------------------------------------------- */
void pool_init (void)
{
	POOLS = NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION mksizepool (roundedsize)                                         *
 * ---------------------------------                                         *
 * Allocates a 64KB pool of memory blocks of the same, rounded size. If the  *
 * size is larger than 64KB, 16 blocks are allocated. The n2blocks' header   *
 * structures are also initialized to point back to the pool.                *
\* ------------------------------------------------------------------------- */
n2sizepool *mksizepool (size_t rndsz)
{
	unsigned int count;
	n2sizepool *c;
	n2block *bl;
	unsigned int i;
	
	c = (n2sizepool *) malloc (sizeof (n2sizepool));
	if (c == NULL) return c;
	
	if (rndsz < 512) count = 8192/rndsz;
	else if (rndsz < 4096) count = 65536/rndsz;
	else count = 16;
	
	c->next = NULL;
	c->extend = NULL;
	c->count = count;
	c->sz = rndsz;
	c->blocks = (char *) calloc (count, rndsz);
	
	for (i=0; i<count; ++i)
	{
		bl = (n2block *) (c->blocks + (i*c->sz));
		bl->pool = c;
	}
	
	return c;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pool_alloc (sz)                                                  *
 * ------------------------                                                  *
 * Allocates at least sz bytes from a memory pool.                           *
\* ------------------------------------------------------------------------- */
void *pool_alloc (size_t sz)
{
	size_t rndsz;
	n2sizepool *c, *lastc, *tc;
	unsigned int i;
	n2block *b;
	
	rndsz = (sz + sizeof(n2block) + 7) & 0xfffffff8;
	
	c = lastc = POOLS;
	while (c)
	{
		lastc = c;
		if (c->sz == rndsz) break;
		c = c->next;
	}
	
	if (! c)
	{
		c = mksizepool (rndsz);
		if (! c) return c;
		
		b = (n2block *) c->blocks;
		b->status = blk_wired;
		if (lastc) lastc->next = c;
		else POOLS = c;
		
		return (void *) b->dt;
	}
	
	for (i=0; i<c->count; ++i)
	{
		b = (n2block *) (c->blocks + (i * c->sz));
		if (b->status == blk_free)
		{
			b->status = blk_wired;
			b->pool = c;
			return (void *) b->dt;
		}
	}
	
	while (1)
	{
		tc = c;
		if (c->extend) c = c->extend;
		else
		{
			c->extend = mksizepool (rndsz);
			c = c->extend;
			if (! c) return NULL;
		}
		
		for (i=0; i<c->count; ++i)
		{
			b = (n2block *) (c->blocks + (i * c->sz));
			if (b->status == blk_free)
			{
				b->status = blk_wired;
				b->pool = c;
				return (void *) b->dt;
			}
		}
	}
	
	return NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pool_calloc (sz)                                                 *
 * ------------------------                                                  *
 * Allocates at least sz zeroed bytes from a memory pool.                    *
\* ------------------------------------------------------------------------- */
void *pool_calloc (size_t sz)
{
	void *r;
	
	r = pool_alloc (sz);
	memset (r, 0, sz);
	return r;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pool_ree (ptr)                                                   *
 * -----------------------                                                   *
 * Free a pooled allocation.                                                 *
\* ------------------------------------------------------------------------- */
void pool_free (void *ptr)
{
	n2block *b;
	
	b = (n2block *) (((char*)ptr) - BLK_OFFSET);
	b->status = blk_free;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pool_realloc (ptr, sz)                                           *
 * -------------------------------                                           *
 * Resizes a prior allocation.                                               *
\* ------------------------------------------------------------------------- */
void *pool_realloc (void *ptr, size_t nsz)
{
	void *nw;
	size_t sz;
	sz = pool_getsize (ptr);
	
	nw = pool_alloc (nsz);
	memcpy (nw, ptr, sz);
	pool_free (ptr);
	return nw;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pool_getsize (ptr)                                               *
 * ---------------------------                                               *
 * Gets the pool size for a pool-allocated memory pointer.                   *
\* ------------------------------------------------------------------------- */
size_t pool_getsize (void *ptr)
{
	n2block *b;
	b = (n2block *) (((char*)ptr) - BLK_OFFSET);
	return b->pool->sz - sizeof (n2block);
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION pool_strdup (str)                                                *
\* ------------------------------------------------------------------------- */
char *pool_strdup (const char *orig)
{
	char *res;
	size_t ln;
	
	ln = strlen (orig);
	res = pool_alloc (ln+1);
	strcpy (res, orig);
	return res;
}
