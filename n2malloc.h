#ifndef N2MALLOC_H
#define N2MALLOC_H 1

#include <sys/types.h>

typedef struct n2sizepool
{
	struct n2sizepool	*next;
	size_t				 sz;
	unsigned int		 count;
	char				*blocks;
	struct n2sizepool	*extend;
} n2sizepool;

n2sizepool *POOLS;

typedef enum { blk_free = 0, blk_wired = 1 } n2blockstatus;

typedef struct n2block
{
	n2sizepool		*pool;
	n2blockstatus	 status;
	unsigned int	 pad;
	unsigned char	 dt[0];
} n2block;

#define BLK_OFFSET (sizeof(n2sizepool*)+sizeof(n2blockstatus)+sizeof(unsigned int))

void		 pool_init (void);
n2sizepool	*mksizepool (size_t sz);

void		*pool_alloc (size_t sz);
void		*pool_calloc (size_t sz);
void		*pool_realloc (void *ptr, size_t sz);
void		 pool_free (void *ptr);
size_t		 pool_getsize (void *ptr);
char		*pool_strdup (const char *orig);

#endif
