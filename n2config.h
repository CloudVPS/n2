#ifndef _N2CONFIG_H
#define _N2CONFIG_H 1

#include "n2args.h"
#include <stdio.h>

typedef void n2function (n2arglist *);

typedef struct n2command
{
	const char 			*name;
	struct n2command	*children;
	n2function			*function;
} n2command;

extern n2command *CROOT;

typedef enum
{
	LOG_NONE,
	LOG_EVENTS,
	LOG_MALFORMED,
	LOG_ALL
} logtype_t;

typedef struct n2server
{
	struct n2server		*next;
	unsigned long		 host;
	char				 key[64];
	int					 port;
	void				*lastpacket;
} n2server;

typedef struct n2if
{
	char		ifname[32];
} n2if;

typedef struct n2io
{
	char		devname[32];
} n2io;

enum
{
	ENCODE_LOGINS = 0x01,
	ENCODE_TCPSTAT = 0x02
};

typedef struct svc_match
{
	const char	*name;
	const char	*owner;
	int port;
} svc_match;

typedef unsigned int encoding_flag_t;

typedef struct n2config
{
	/* Parameters for n2rxd */
	unsigned int		 listenaddr;
	unsigned short		 listenport;
	encoding_flag_t		 encoding;
	
	/* Parameters for n2txd */
	n2server			*servers;
	int					 ifcount;
	n2if				*interfaces;
	int					 iocount;
	n2io				*iodevices;
	int					 modstatus;
	char				 statusurl[64];
	int					 xen;
	svc_match			*matches[32];
	
	/* Common parameters */
	char				*logfile;
	char				 user[16];
	char				 group[16];
	char				 hostname[32];
	logtype_t			 log;
} n2config;

extern n2config CONF;
extern int config_changed;
void load_config (const char *);
void conf_init (void);
void parse_cmd (const char *);
void print_running_rxd (FILE *);

#endif
