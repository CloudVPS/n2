#ifndef _NETLOAD2_H
#define _NETLOAD2_H 1

#include "datatypes.h"

void			 init_netload_info	(netload_info *);
netload_pkt		*encode_pkt			(netload_info *, const char *);
netload_rec		*encode_rec			(netload_pkt *, time_t, status_t,
									 unsigned short, unsigned short,
									 unsigned int);
int				 validate_pkt		(netload_pkt *, const char *);
int				 decode_rec_inline	(netload_rec *, netload_info *);
netload_info    *create_error_rec   ();
netload_info	*decode_rec			(netload_rec *);

void			 pkt_print8			(netload_pkt *, unsigned char);
void			 pkt_print16		(netload_pkt *, unsigned short);
void			 pkt_print24		(netload_pkt *, int);
void			 pkt_print32		(netload_pkt *, int);
void			 pkt_prints			(netload_pkt *, const char *, int);

unsigned int	 pkt_get_hosttime	(netload_pkt *);
unsigned int	 pkt_get_uptime		(netload_pkt *);
unsigned int	 pkt_get_services	(netload_pkt *);

unsigned char	 rec_read8			(netload_rec *);
unsigned short	 rec_read16			(netload_rec *);
int				 rec_read24			(netload_rec *);
int				 rec_read32			(netload_rec *);
int				 rec_reads			(netload_rec *, char *, size_t);

void			 print_info			(netload_info *, unsigned int);
void			 print_info_xml		(netload_info *, unsigned long,
									 unsigned int, int);

status_t		 rec_get_status		(netload_rec *);									 
void			 rec_set_status		(netload_rec *, status_t);
void			 rec_set_ping10		(netload_rec *, int);
void			 rec_set_loss		(netload_rec *, int);
void			 rec_set_oflags		(netload_rec *, oflag_t);
oflag_t			 rec_get_oflags		(netload_rec *);

const char		*get_servicename	(int);

extern const char *STR_STATUS[];
extern const char *STR_OFLAGS[];
#endif
