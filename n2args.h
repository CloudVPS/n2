#ifndef _N2ARGS_H
#define _N2ARGS_H 1

typedef struct
{
	int argc;
	char **argv;
} n2arglist;

int argcount (const char *);
n2arglist *new_args (void);
n2arglist *make_args (const char *);
void add_args (n2arglist *, const char *);
void destroy_args (n2arglist *);

#endif
