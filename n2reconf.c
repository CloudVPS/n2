#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAXLINESIZE 256

typedef struct confline_struc
{
	struct confline_struc *next;
	char line[MAXLINESIZE];
	struct confline_struc *first;
} confline;

void panic (const char *why)
{
	fprintf (stderr, "PANIC - %s\n", why);
	exit (1);
}

confline *read_conf (FILE *f)
{
	confline *res;
	confline *ln;
	int len;
	confline *oldln = NULL;
	confline *parent = NULL;
	int insub = 0;
	int makesibling = 1;
	
	res = ln = (confline *) malloc (sizeof (confline));
	if (! ln) panic ("malloc");
	
	while (fgets (ln->line, MAXLINESIZE-1, f) != NULL)
	{
		makesibling = 1;
		ln->line[MAXLINESIZE-1] = 0;
		if ((len = strlen (ln->line)))
		{
			ln->line[len-1] = 0;
		}
		if (ln->line[0] == ' ')
		{
			memmove (ln->line, ln->line+1, MAXLINESIZE-1);
			if (insub)
			{
				if (oldln) oldln->next = ln;
				oldln = ln;
				ln = (confline *) malloc (sizeof (confline));
				if (! ln) panic ("malloc");
			}
			else
			{
				if (! oldln) panic ("sub-statement without parent");
				insub = 1;
				oldln->first = ln;
				parent = oldln;
				oldln = ln;
				ln = (confline *) malloc (sizeof (confline));
				if (! ln) panic ("malloc");
			}
		}
		else if (ln->line[0] == '!')
		{
			if (insub)
			{
				insub = 0;
				oldln = parent;
				parent = NULL;
			}
			else
			{
				if (oldln) oldln->next = ln;
				oldln = ln;
				ln = (confline *) malloc (sizeof (confline));
				if (! ln) panic ("malloc");
			}
		}
		else
		{
			if (insub)
			{
				if (oldln) oldln->next = ln;
				insub = 0;
				oldln = parent;
				parent = NULL;
			}
			else
			{
				if (oldln) oldln->next = ln;
				oldln = ln;
			}
			ln = (confline *) malloc (sizeof (confline));
			if (! ln) panic ("malloc");
		}
		
		ln->line[0] = 0;
		ln->first = NULL;
		ln->next = NULL;
	}
	if (ln) free (ln);
	return res;
}

void write_conf (confline *conf, FILE *f)
{
	confline *c;
	confline *cc;
	
	if (! conf) return;
	if (! f) return;
	
	c = conf;
	while (c)
	{
		fprintf (f, "%s\n", c->line);
		if (c->first)
		{
			cc = c->first;
			while (cc)
			{
				if (cc->line[0])
				{
					fprintf (f, " %s\n", cc->line);
				}
				cc = cc->next;
			}
			fprintf (f, "!\n");
		}
		c = c->next;
	}
}

confline *findsub (confline *conf, const char *id)
{
	confline *crsr = conf;
	while (crsr)
	{
		if (strcmp (crsr->line, id) == 0)
			return crsr->first;
		
		crsr = crsr->next;
	}
	return NULL;
}

confline *findstatement (confline *conf, const char *stm)
{
	int ln;
	char tomatch[MAXLINESIZE+16];
	confline *crsr;
	
	strcpy (tomatch, stm);
	strcat (tomatch, " ");
	ln = strlen (tomatch);
	
	crsr = conf;
	while (crsr)
	{
		if (strncmp (crsr->line, tomatch, ln) == 0) return crsr;
		if (strcmp (crsr->line, stm) == 0) return crsr;
		crsr = crsr->next;
	}
	return NULL;
}

void free_conf (confline *c)
{
	confline *crsr;
	confline *next;
	
	crsr = c->first;
	while (crsr)
	{
		next = crsr->next;
		free (crsr);
		crsr = next;
	}
	
	if (c->next) free_conf (c->next);
	free (c);
}

confline *setstatement (confline *conf, const char *stm, const char *set)
{
	confline *c;
	
	if (! conf) return NULL;
	if ((c = findstatement (conf, stm)))
	{
		strncpy (c->line, set, MAXLINESIZE-1);
		c->line[MAXLINESIZE-1] = 0;
		return c;
	}
	
	c = conf;
	while (c->next) c = c->next;
	c->next = (confline *) malloc (sizeof (confline));
	if (! c->next) panic ("malloc");
	c = c->next;
	c->next = NULL;
	c->first = NULL;
	strncpy (c->line, set, MAXLINESIZE-1);
	c->line[MAXLINESIZE-1] = 0;
	return c;
}

void removestatement (confline *conf, const char *stm)
{
	confline *crsr;
	confline *prev;
	char tomatch[MAXLINESIZE+16];
	int ln;
	
	strcpy (tomatch, stm);
	strcat (tomatch, " ");
	ln = strlen (tomatch);
	
	prev = NULL;
	crsr = conf;
	
	while (crsr)
	{
		if (prev)
		{
			if ( (strcmp (crsr->line, stm) == 0) ||
				 (strncmp (crsr->line, tomatch, ln) == 0) )
			{
				prev->next = crsr->next;
				crsr->next = NULL;
				free_conf (crsr);
				return;
			}
		}		
		prev = crsr;
		crsr = crsr->next;
	}
}

confline *findormakesub (confline *conf, const char *stm)
{
	confline *res;
	res = findsub (conf, stm);
	if (res != NULL) return res;
	
	res = findstatement (conf, stm);
	if (! res)
	{
		res = setstatement (conf, stm, stm);
	}
	if (! res->first)
	{
		res->first = (confline *) malloc (sizeof (confline));
		if (! res->first) panic ("malloc");
		res = res->first;
		res->first = NULL;
		res->next = NULL;
		res->line[0] = 0;
		return res;
	}
	return res->first;
}

#define SHIFT { i++; if (i>argc) panic ("argument error"); }

int main (int argc, char *argv[])
{
	const char *left;
	const char *right;
	FILE *f;
	confline *conf;
	confline *c;
	int i = 1;
	if (argc < 2) return 1;
	
	f = fopen ("/etc/n2/n2rxd.conf","r");
	conf = read_conf (f);
	fclose (f);
	
	c = conf;
	
	if (strcmp (argv[i], "--group") == 0)
	{
		SHIFT;
		c = findormakesub (conf, argv[i]);
		SHIFT;
	}
	
	if (strcmp (argv[i], "--set") == 0)
	{
		SHIFT;
		left = argv[i];
		SHIFT;
		right = argv[i];
		setstatement (c, left, right);
	}
	else if (strcmp (argv[i], "--remove") == 0)
	{
		SHIFT;
		removestatement (c, argv[i]);
	}
	else
	{
		panic ("argument error");
	}
	
	f = fopen ("/etc/n2/n2rxd.conf.new","w");
	if (! f) panic ("open write");
	write_conf (conf, f);
	fclose (f);
	
	if (rename ("/etc/n2/n2rxd.conf.new", "/etc/n2/n2rxd.conf"))
	{
		panic ("install-file");
	}
	return 0;
}
