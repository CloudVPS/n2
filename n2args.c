#include "n2args.h"
#include "n2malloc.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define isspace(q) ((q==' ')||(q=='\t'))

/* ------------------------------------------------------------------------- *\
 * FUNCTION findspace (src)                                                  *
 * ------------------------                                                  *
 * Utility function to find the next whitespace character inside a string.   *
\* ------------------------------------------------------------------------- */
inline char *findspace (char *src)
{
	register char *t1;
	register char *t2;
	
	t1 = strchr (src, ' ');
	t2 = strchr (src, '\t');
	if (t1 && t2)
	{
		if (t1<t2) t2 = NULL;
		else t1 = NULL;
	}
	
	if (t1) return t1;
	return t2;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION argcount (string)                                                *
 * --------------------------                                                *
 * Counts the number of arguments inside a string (whitespace-separated).    *
\* ------------------------------------------------------------------------- */
int argcount (const char *string)
{
	int ln;
	int cnt;
	int i;
	
	cnt = 1;
	ln = strlen (string);
	i = 0;
	
	while (i < ln)
	{
		if (isspace(string[i]))
		{
			while (isspace(string[i])) ++i;
			if (string[i]) ++cnt;
		}
		++i;
	}
	
	return cnt;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION new_args (void)                                                  *
 * ------------------------                                                  *
 * Allocates and initializes an n2arglist structure.                         *
\* ------------------------------------------------------------------------- */
n2arglist *new_args (void)
{
	n2arglist *res;
	
	res = (n2arglist *) pool_alloc (sizeof (n2arglist));
	res->argc = 0;
	res->argv = NULL;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION add_args (arglist, element)                                      *
 * ------------------------------------                                      *
 * Adds an element to an n2arglist structure.                                *
\* ------------------------------------------------------------------------- */
void add_args (n2arglist *arg, const char *elm)
{
	if (arg->argc)
	{
		arg->argv = (char **) pool_realloc (arg->argv, (arg->argc + 1) * sizeof (char *));
		arg->argv[arg->argc++] = pool_strdup (elm);
	}
	else
	{
		arg->argc = 1;
		arg->argv = (char **) pool_alloc (sizeof (char *));
		arg->argv[0] = pool_strdup (elm);
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION make_args (string)                                               *
 * ---------------------------                                               *
 * Splices up a command string into an n2arglist.                            *
\* ------------------------------------------------------------------------- */
n2arglist *make_args (const char *string)
{
	n2arglist    *result;
	char		 *rightbound;
	char		 *word;
	char		 *crsr;
	int			  count;
	int			  pos;
	
	crsr = (char *) string;
	while ((*crsr == ' ')||(*crsr == '\t')) ++crsr;
	
	result = (n2arglist *) pool_alloc (sizeof (n2arglist));
	count = argcount (crsr);
	result->argc = count;
	result->argv = (char **) pool_alloc (count * sizeof (char *));
	
	pos = 0;
	
	while ((rightbound = findspace (crsr)))
	{
		word = (char *) pool_alloc ((rightbound-crsr+3) * sizeof (char));
		memcpy (word, crsr, rightbound-crsr);
		word[rightbound-crsr] = 0;
		result->argv[pos++] = word;
		crsr = rightbound;
		while (isspace(*crsr)) ++crsr;
	}
	if (*crsr)
	{
		word = pool_strdup (crsr);
		result->argv[pos++] = word;
	}
	
	return result;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION destroy_args (arglist)                                           *
 * -------------------------------                                           *
 * Frees up all memory associated to an n2arglist.                           *
\* ------------------------------------------------------------------------- */
void destroy_args (n2arglist *lst)
{
	int i;
	for (i=0;i<lst->argc;++i) pool_free (lst->argv[i]);
	pool_free (lst->argv);
	pool_free (lst);
}
