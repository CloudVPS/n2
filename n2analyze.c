#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include "datatypes.h"
#include "n2diskdb.h"
#include "n2encoding.h"

#define MAXAGE 2880

typedef struct samplecache_t
{
	struct samplecache_t	*next;
	unsigned int			 field;
	int						 start;
	int						 end;
	double					 average;
	double					 min;
	double					 max;
} samplecache;

samplecache *CACHE;
netload_info *DATA[MAXAGE];

/* ------------------------------------------------------------------------- *\
 * FUNCTION getinfofield (from, fieldid)                                     *
 * -------------------------------------                                     *
 * Represents a field of a netload_info struct as a lua-compatible double.   *
\* ------------------------------------------------------------------------- */
double getinfofield (netload_info *from, unsigned int fld)
{
	switch (fld)
	{
		case F_STATUS: return (double) from->status;
		case F_RTT: return from->ping10 * 0.1;
		case F_LOSS: return from->loss * 1.0;
		case F_UPTIME: return from->uptime * 1.0;
		case F_LOADAVG: return from->load1 * 0.01;
		case F_CPU: return from->cpu / 2.56;
		case F_DISKIO: return from->diskio * 1.0;
		case F_NPROC: return from->nproc * 1.0;
		case F_MEMFREE: return from->kmemfree / 1024.0;
		case F_SWAPFREE: return from->kswapfree / 1024.0;
		case F_TOTALMEM: return (from->kmemfree+from->kswapfree)/1024.0;
		case F_NETIN: return from->netin * 1.0;
		case F_NETOUT: return from->netout * 1.0;
		return 0.0;
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION getstats (fieldid, start, end)                                   *
 * ---------------------------------------                                   *
 * Gather (cached) statistics about a specific field (and range).            *
\* ------------------------------------------------------------------------- */
samplecache *getstats (unsigned int field, int start, int end)
{
	samplecache	*cnode, *lcnode;
	int i;
	lcnode = NULL;
	cnode = CACHE;
	double min = -1.0;
	double max = 0.0;
	double total = 0.0;
	netload_info *inf;
	double val;
	
	while (cnode)
	{
		lcnode = cnode;
		if (cnode->field == field && cnode->start == start && cnode->end == end)
		{
			return cnode;
		}
		cnode = cnode->next;
	}
	
	cnode = (samplecache *) malloc (sizeof (samplecache));
	cnode->next = NULL;
	cnode->field = field;
	cnode->start = start;
	cnode->end = end;
	cnode->average = 0.0;
	cnode->min = 0.0;
	cnode->max = 0.0;
	if (lcnode) lcnode->next = cnode;
	else CACHE = cnode;
	if (start<0) return cnode;
	if (end<start) return cnode;
	if (end>MAXAGE) end = MAXAGE;
	
	for (i=start; i<end; ++i)
	{
		inf = DATA[i];
		if (! inf) continue;
		val = getinfofield (inf, field);
		total += val;
		if (val < min || min < 0.0) min = val;
		if (val > max) max = val;
		total += val;
	}
	
	cnode->average = total / (double)(end - start);
	cnode->min = min;
	cnode->max = max;
	return cnode;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION n2lua_pcount                                                     *
 * ---------------------                                                     *
 * Backend implementation of the proc.pcount() function passed to the        *
 * analyze script.                                                           *
\* ------------------------------------------------------------------------- */
static int n2lua_pcount (lua_State *L)
{
	unsigned int argc;
	const char *usermatch = "*";
	const char *procname;
	double mincpu;
	int start = 0;
	int end = 1140;
	int nouser = 0;
	int i,j;
	netload_info *inf;
	int res = 0;
	
	argc = lua_gettop (L);
	if (argc < 3) return 0;
	
	usermatch = lua_tolstring (L, -argc, NULL);
	procname = lua_tolstring (L, -argc+1, NULL);
	mincpu = lua_tonumber (L, -argc+2);
	
	if (argc>3) end = lua_tointeger (L, -argc+3);
	if (argc>4) start = lua_tointeger (L, argc+4);
	
	if (strcmp (usermatch, "*") == 0) nouser = 1;
	
	for (i=start; i<end; ++i)
	{
		inf = DATA[i];
		if (!inf) continue;
		for (j=0; j<inf->ntop; ++j)
		{
			if ((inf->tprocs[j].pcpu / 100.0) < mincpu) continue;
			if (nouser == 0)
			{
				if (strcmp (inf->tprocs[j].username, usermatch)) continue;
			}
			if (strcmp (inf->tprocs[j].ptitle, procname)) continue;
			res++;
		}
	}
	
	lua_pop (L, argc);
	lua_pushinteger (L, res);
	return 1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION n2lua_getrecord                                                  *
 * ------------------------                                                  *
 * Takes an integer off the lua-stack, takes that as an index in the         *
 * history and creates a table on the stack with the netload_info record.    *
\* ------------------------------------------------------------------------- */
static int n2lua_getrecord (lua_State *L)
{
	unsigned int argc;
	int offset;
	netload_info *inf;
	char myip[32];
	int i;
	
	argc = lua_gettop (L);
	if (argc == 0) return 0;
	
	offset = lua_tointeger (L, -1);
	lua_pop (L, 1);
	
	if (offset<0 || offset>=MAXAGE) return 0;
	inf = DATA[offset];
	if (! inf) return 0;
	
	lua_newtable 	(L);
	lua_pushinteger	(L, offset);
	lua_setfield	(L, -2, "offset");
	lua_pushnumber	(L, inf->ping10 * 0.1);
	lua_setfield 	(L, -2, "rtt");
	lua_pushnumber	(L, inf->loss * 1.0);
	lua_setfield 	(L, -2, "loss");
	lua_pushnumber	(L, inf->load1 / 100.0);
	lua_setfield	(L, -2, "loadavg");
	lua_pushinteger (L, inf->uptime);
	lua_setfield 	(L, -2, "uptime");
	lua_pushnumber	(L, inf->cpu / 2.56);
	lua_setfield	(L, -2, "cpu");
	lua_pushinteger	(L, inf->diskio);
	lua_setfield	(L, -2, "diskio");
	lua_pushinteger	(L, inf->nproc);
	lua_setfield	(L, -2, "nproc");
	lua_pushnumber	(L, inf->kmemfree / 1024.0);
	lua_setfield	(L, -2, "memfree");
	lua_pushnumber	(L, inf->kswapfree / 1024.0);
	lua_setfield	(L, -2, "swapfree");
	lua_pushinteger	(L, inf->netin);
	lua_setfield	(L, -2, "netin");
	
	lua_newtable (L);
	for (i = 0; i<inf->nmounts; ++i)
	{
		lua_newtable 	(L);
		lua_pushstring 	(L, inf->mounts[i].device);
		lua_setfield 	(L, -2, "device");
		lua_pushstring 	(L, inf->mounts[i].mountpoint);
		lua_setfield 	(L, -2, "mountpoint");
		lua_pushstring 	(L, inf->mounts[i].fstype);
		lua_setfield 	(L, -2, "fstype");
		lua_pushnumber	(L, inf->mounts[i].usage / 10.0);
		lua_setfield	(L, -2, "usage");
		lua_rawseti 	(L, -2, i+1);
	}
	lua_setfield (L, -2, "mounts");

	lua_pushinteger (L, inf->ntop);
	lua_setfield (L, -2, "ntop");

	lua_newtable (L);
	for (i=0; i<inf->ntop; ++i)
	{
		lua_newtable	(L);
		lua_pushstring	(L, inf->tprocs[i].username);
		lua_setfield	(L, -2, "username");
		lua_pushinteger	(L, inf->tprocs[i].pid);
		lua_setfield	(L, -2, "pid");
		lua_pushnumber	(L, inf->tprocs[i].pcpu / 100.0);
		lua_setfield	(L, -2, "pcpu");
		lua_pushnumber	(L, inf->tprocs[i].pmem / 100.0);
		lua_setfield	(L, -2, "pmem");
		lua_pushstring	(L, inf->tprocs[i].ptitle);
		lua_setfield	(L, -2, "title");
		lua_rawseti		(L, -2, i+1);
	}
	lua_setfield (L, -2, "procs");
	
	lua_newtable (L);
	for (i=0; i<inf->nports; ++i)
	{
		lua_newtable	(L);
		lua_pushinteger	(L, inf->ports[i].port);
		lua_setfield	(L, -2, "port");
		lua_pushinteger	(L, inf->ports[i].nestab);
		lua_setfield	(L, -2, "established");
		lua_pushinteger	(L, inf->ports[i].nother);
		lua_setfield	(L, -2, "other");
		lua_rawseti		(L, -2, i+1);
	}
	lua_setfield (L, -2, "ports");

	lua_newtable (L);
	for (i=0; i<inf->ntty; ++i)
	{
		lua_newtable	(L);
		lua_pushstring	(L, inf->ttys[i].line);
		lua_setfield	(L, -2, "line");
		lua_pushstring	(L, inf->ttys[i].username);
		lua_setfield	(L, -2, "username");
		printip			(inf->ttys[i].host, myip);
		lua_pushstring	(L, myip);
		lua_setfield	(L, -2, "host");
		lua_rawseti		(L, -2, i+1);
	}
	lua_setfield (L, -2, "ttys");
	
	return 1;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION countmin                                                         *
 * -----------------                                                         *
 * Count the number of times a field's translated value is over a given      *
 * minimum within a given time range.                                        *
\* ------------------------------------------------------------------------- */
int countmin (unsigned int field, double minval, int start, int end)
{
	int res = 0;
	int i;
	double val;
	
	if (start<0) return 0;
	if (end<start) return 0;
	if (end>MAXAGE) end = MAXAGE;
	
	for (i=start; i<end; i++)
	{
		if (DATA[i] == NULL) continue;
		val = getinfofield (DATA[i], field);
		if (val >= minval) res++;
	}
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION loopmin                                                          *
 * ----------------                                                          *
 * Loops over a range of history, calling the lua function on top of the     *
 * stack for every value over a given minimum.                               *
\* ------------------------------------------------------------------------- */
void loopmin (lua_State *L, unsigned int field, double minval,
			  int start, int end)
{
	int i;
	double val;
	
	if (start<0) return;
	if (end<start) return;
	if (end>MAXAGE) return;
	
	for (i=start; i<end; i++)
	{
		if (DATA[i] == NULL) continue;
		val = getinfofield (DATA[i], field);
		if (val >= minval)
		{
			lua_pushvalue (L, -1);
			lua_pushinteger (L, i);
			n2lua_getrecord (L);
			lua_call (L, 1, 0);
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION loopmax                                                          *
\* ------------------------------------------------------------------------- */
void loopmax (lua_State *L, unsigned int field, double maxval,
			  int start, int end)
{
	int i;
	double val;
	
	if (start<0) return;
	if (end<start) return;
	if (end>MAXAGE) return;
	
	for (i=start; i<end; i++)
	{
		if (DATA[i] == NULL) continue;
		val = getinfofield (DATA[i], field);
		if (val <= maxval)
		{
			lua_pushvalue (L, -1);
			lua_pushinteger (L, i);
			n2lua_getrecord (L);
			lua_call (L, 1, 0);
		}
	}
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION countmax                                                         *
\* ------------------------------------------------------------------------- */
int countmax (unsigned int field, double maxval, int start, int end)
{
	int res = 0;
	int i;
	double val;
	
	if (start<0) return 0;
	if (end<start) return 0;
	if (end>MAXAGE) end = MAXAGE;
	
	for (i=start; i<end; i++)
	{
		if (DATA[i] == NULL) continue;
		val = getinfofield (DATA[i], field);
		if (val <= maxval) res++;
	}
	return res;
}

/* ------------------------------------------------------------------------- *\
 * FUNCTION load_host                                                        *
 * ------------------                                                        *
 * Loads a host's history data. Ideally we'll get a bit smarter abou this.   *
\* ------------------------------------------------------------------------- */
void load_host (unsigned int addr)
{
	int offs;
	unsigned int dt;
	netload_rec *rec;
	int i;
	diskdb_now (&dt, &offs);
	for (i=0; i<MAXAGE; ++i)
	{
		--offs;
		if (offs < 0)
		{
			offs = 1439;
			dt = tdate_sub (dt, 1);
		}
		
		rec = diskdb_get (addr, dt, offs);
		if (! rec)
		{
			DATA[i] = NULL;
		}
		else
		{
			DATA[i] = decode_rec (rec);
			free (rec);
		}
	}
}

/* Some metaprogramming to implement lua backend-functions for the
   different fields. */
#define REGLUAVALUE(xxtypexx,xxfieldnamexx) \
	static int n2lua_ ## xxtypexx ## _average (lua_State *L)\
	{\
		unsigned int argc = 0;\
		samplecache *c;\
		lua_Number res;\
		int start = 0;\
		int end = 1440;\
		\
		argc = lua_gettop (L);\
		if (argc>0) end = lua_tointeger (L, -argc);\
		if (argc>1) start = lua_tointeger (L, -argc+1);\
		lua_pop (L, argc);\
		end += start;\
		\
		c = getstats (xxfieldnamexx, start, end);\
		res = c->average;\
		\
		lua_pushnumber (L, res);\
		return 1;\
	}\
	\
	static int n2lua_ ## xxtypexx ## _max (lua_State *L)\
	{\
		unsigned int argc = 0;\
		samplecache *c;\
		lua_Number res;\
		int start = 0;\
		int end = 1440;\
		\
		argc = lua_gettop (L);\
		if (argc>0) end = lua_tointeger (L, -argc);\
		if (argc>1) start = lua_tointeger (L, -argc+1);\
		lua_pop (L, argc);\
		end += start;\
		\
		c = getstats (xxfieldnamexx, start, end);\
		res = c->max;\
		\
		lua_pushnumber (L, res);\
		return 1;\
	}\
	\
	static int n2lua_ ## xxtypexx ## _min (lua_State *L)\
	{\
		unsigned int argc = 0;\
		samplecache *c;\
		lua_Number res;\
		int start = 0;\
		int end = 1440;\
		\
		argc = lua_gettop (L);\
		if (argc>0) end = lua_tointeger (L, -argc);\
		if (argc>1) start = lua_tointeger (L, -argc+1);\
		lua_pop (L, -argc);\
		end += start;\
		\
		c = getstats (xxfieldnamexx, start, end);\
		res = c->min;\
		\
		lua_pushnumber (L, res);\
		return 1;\
	}\
	\
	static int n2lua_ ## xxtypexx ## _countmin (lua_State *L)\
	{\
		unsigned int argc = 0;\
		samplecache *c;\
		lua_Number res;\
		int start = 0;\
		int end = 1440;\
		double minval = 0.0;\
		\
		argc = lua_gettop (L);\
		if (argc>0) minval = lua_tonumber (L, -argc);\
		if (argc>1) end = lua_tointeger (L, -argc+1);\
		if (argc>2) start = lua_tointeger (L, -argc+2);\
		lua_pop (L, argc);\
		end += start;\
		\
		res = countmin (xxfieldnamexx, minval, start, end);\
		\
		lua_pushnumber (L, res);\
		return 1;\
	}\
	\
	static int n2lua_ ## xxtypexx ## _loopmax (lua_State *L) \
	{\
		unsigned int argc = 0;\
		samplecache *c;\
		int start = 0;\
		int end = 1440;\
		double maxval = 0.0;\
		\
		argc = lua_gettop (L);\
		if (argc>0) maxval = lua_tonumber (L, -argc);\
		if (argc>2) end = lua_tointeger (L, -argc+2);\
		if (argc>3) start = lua_tointeger (L, -argc+3);\
		lua_remove (L, -argc); \
		if (argc>2) lua_pop (L, argc-2); \
		end += start;\
		\
		loopmax (L, xxfieldnamexx, maxval, start, end);\
		return 0;\
	} \
	\
	static int n2lua_ ## xxtypexx ## _loopmin (lua_State *L) \
	{\
		unsigned int argc = 0;\
		samplecache *c;\
		int start = 0;\
		int end = 1440;\
		double minval = 0.0;\
		\
		argc = lua_gettop (L);\
		if (argc>0) minval = lua_tonumber (L, -argc);\
		if (argc>2) end = lua_tointeger (L, -argc+2);\
		if (argc>3) start = lua_tointeger (L, -argc+3);\
		lua_remove (L, -argc); \
		if (argc>2) lua_pop (L, argc-2); \
		end += start;\
		\
		loopmin (L, xxfieldnamexx, minval, start, end);\
		return 0;\
	} \
	\
	static int n2lua_ ## xxtypexx ## _countmax (lua_State *L)\
	{\
		unsigned int argc = 0;\
		samplecache *c;\
		lua_Number res;\
		int start = 0;\
		int end = 1440;\
		double maxval = 0.0;\
		\
		argc = lua_gettop (L);\
		if (argc>0) maxval = lua_tonumber (L, -1);\
		if (argc>1) end = lua_tointeger (L, -2);\
		if (argc>2) start = lua_tointeger (L, -3);\
		lua_pop (L, argc);\
		end += start;\
		\
		res = countmax (xxfieldnamexx, maxval, start, end);\
		\
		lua_pushnumber (L, res);\
		return 1;\
	}
	
	/* Who needs C++ templates when you can use hacky C-macro's? */
	REGLUAVALUE(rtt, F_RTT)
	REGLUAVALUE(loss, F_LOSS)
	REGLUAVALUE(uptime, F_UPTIME)
	REGLUAVALUE(cpu, F_CPU)
	REGLUAVALUE(loadavg, F_LOADAVG)
	REGLUAVALUE(diskio, F_DISKIO)
	REGLUAVALUE(nproc, F_NPROC)
	REGLUAVALUE(memfree, F_MEMFREE)
	REGLUAVALUE(swapfree, F_SWAPFREE)
	REGLUAVALUE(totalmem, F_TOTALMEM)
	REGLUAVALUE(netin, F_NETIN)
	REGLUAVALUE(netout, F_NETOUT)

int main (int argc, char *argv[])
{
	const char *ip = "127.0.0.1";
	char cachepath[1024];
	char buf[1024];
	struct stat st;
	FILE *cfile;
	time_t tnow;
	time_t tcache;
	uid_t myuid;
	struct passwd *pw;

	myuid = getuid();
	pw = getpwnam ("n2");

	if (argc>1) ip = argv[1];
	
	if (! mkdir ("/var/state/n2/analyze", 0750))
	{
		if (! myuid) chown ("/var/state/n2/analyze", pw->pw_uid, pw->pw_gid);
	}
	sprintf (cachepath, "/var/state/n2/analyze/%s", ip);
	if (stat (cachepath, &st) == 0)
	{
		tnow = time (NULL);
		tcache = st.st_mtime;
		
		/* cached file is fresh? */
		if ((tnow - tcache) < 600)
		{
			cfile = fopen (cachepath, "r");
			while (! feof (cfile))
			{
				buf[0] = 0;
				fgets (buf, 1023, cfile);
				fwrite (buf, 1, strlen (buf), stdout);
			}
			fclose (cfile);
			return 0;
		}
	}
	
	cfile = fopen (cachepath, "w");
	if (! cfile)
	{
		fprintf (stderr, "Could not open '%s' for writing\n", cachepath);
		return 1;
	}

	if (! myuid) chown (cachepath, pw->pw_uid, pw->pw_gid);
	
	load_host (atoip (ip));
	lua_State *L = lua_open ();
	luaL_openlibs (L);
	luaL_dofile (L, "/etc/n2/analyze.lua");
	
	lua_getfield (L, LUA_GLOBALSINDEX, "analyze");
	lua_newtable (L);
	
		/* Some more macro-magic, this time to fill the table we feed
		   the lua analyze script with goody branches of subtrees
		   filled with delicious functions. */
		#define PUSHLUAVALUE(nom) \
			lua_newtable (L); \
			lua_pushcfunction (L, n2lua_ ## nom ## _average); \
			lua_setfield (L, -2, "average"); \
			lua_pushcfunction (L, n2lua_ ## nom ## _max); \
			lua_setfield (L, -2, "max"); \
			lua_pushcfunction (L, n2lua_ ## nom ## _min); \
			lua_setfield (L, -2, "min"); \
			lua_pushcfunction (L, n2lua_ ## nom ## _countmin); \
			lua_setfield (L, -2, "countmin"); \
			lua_pushcfunction (L, n2lua_ ## nom ## _countmax); \
			lua_setfield (L, -2, "countmax"); \
			lua_pushcfunction (L, n2lua_ ## nom ## _loopmin); \
			lua_setfield (L, -2, "loopmin"); \
			lua_pushcfunction (L, n2lua_ ## nom ## _loopmax); \
			lua_setfield (L, -2, "loopmax"); \
			lua_setfield (L, -2, #nom);
			
		PUSHLUAVALUE(rtt);
		PUSHLUAVALUE(loss);
		PUSHLUAVALUE(uptime);
		PUSHLUAVALUE(cpu);
		PUSHLUAVALUE(loadavg);
		PUSHLUAVALUE(diskio);
		PUSHLUAVALUE(nproc);
		PUSHLUAVALUE(memfree);
		PUSHLUAVALUE(swapfree);
		PUSHLUAVALUE(totalmem);
		PUSHLUAVALUE(netin);
		PUSHLUAVALUE(netout);
		
		/* the proc table is different from the rest */
		lua_newtable (L);
		lua_pushcfunction (L, n2lua_pcount);
		lua_setfield (L, -2, "pcount");
		lua_setfield (L, -2, "proc");
		
		/* The generic getrecord function */
		lua_pushcfunction (L, n2lua_getrecord);
		lua_setfield (L, -2, "getrecord");
	
	/* The root of the table is on top of the stack, so let's call our
	   lua analyze function */
	lua_call (L, 1, 1);
	
	fprintf (cfile, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fprintf (cfile, "<n2analyze>\n");
	
	lua_pushnil (L);
	while (lua_next (L, -2) != 0)
	{
		/* Skip unkeyed entries */
		if (! lua_isstring (L, -2))
		{
			lua_pop (L, 1);
			continue;
		}
		
		if (lua_isstring (L, -1))
		{
			fprintf (cfile, "  <string id=\"%s\">", lua_tolstring (L, -2, NULL));
			fprintf (cfile, "%s", lua_tolstring (L, -1, NULL));
			fprintf (cfile, "</string>\n");
		}
		else if (lua_isboolean (L, -1))
		{
			fprintf (cfile, "  <bool id=\"%s\">", lua_tolstring (L, -2, NULL));
			if (lua_toboolean (L, -1) == 0) fprintf (cfile, "false");
			else fprintf (cfile, "true");
			fprintf (cfile, "</bool>\n");
		}
		lua_pop (L, 1);
	}
	
	fprintf (cfile, "</n2analyze>\n");
	lua_close (L);
	fclose (cfile);
	
	cfile = fopen (cachepath, "r");
	while (! feof (cfile))
	{
		buf[0] = 0;
		fgets (buf, 1023, cfile);
		fwrite (buf, 1, strlen (buf), stdout);
	}
	fclose (cfile);
	return 0;
}
