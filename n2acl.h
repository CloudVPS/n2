#ifndef _N2ACL_H
#define _N2ACL_H 1

#define FL_DONTPING		0x01

/* Default acl trigger levels */
#define DEF_RTT_WARNING  		 400 /* 40.0 ms */
#define DEF_RTT_ALERT    		1500 /* 150.0 ms */
#define DEF_LOADAVG_WARNING		 600 /* 6.0 */
#define DEF_LOADAVG_ALERT		2400 /* 24.0 */
#define DEF_LOSS_WARNING		 100 /* 1.00 % */
#define DEF_LOSS_ALERT           750 /* 7.50 % */
#define DEF_SOCKSTATE_WARNING	  80
#define DEF_SOCKSTATE_ALERT		 400
#define DEF_CPU_WARNING			 200 /* 78 % */
#define DEF_CPU_ALERT			 240 /* 93 % */
#define DEF_RAM_WARNING			4096 /* 4MB */
#define DEF_RAM_ALERT			1024 /* 1MB */
#define DEF_SWAP_WARNING		4096 /* 4MB */
#define DEF_SWAP_ALERT			1024 /* 1MB */
#define DEF_NETIN_WARNING		4096 /* 4Mb/s */
#define DEF_NETIN_ALERT        32768 /* 32Mb/s */
#define DEF_NETOUT_WARNING	   40960 /* 40Mb/s */
#define DEF_NETOUT_ALERT	   81920 /* 80Mb/s */
#define DEF_DISKIO_WARNING	   16384 /* 16MBblk/s */
#define DEF_DISKIO_ALERT       32768 /* 32Mblk/s */

/* ------------------------------------------------------------------------- *\
 * The acl structure as defined by a 'monitor-group' in the configuration    *
 * Defined as an IP subnet that has a number of trigger-values. Subnets      *
 * can contain smaller subnets and trigger-values can be left undefined      *
 * (all 1s in binary), referring that value up to a supernet definition.     *
\* ------------------------------------------------------------------------- */
typedef struct acl_struc
{
	struct acl_struc	*next;
	struct acl_struc	*prev;
	struct acl_struc	*first;
	struct acl_struc	*last;
	struct acl_struc	*parent;
	unsigned long		 addr, mask;
	char				 key[63];
	char				 flags;
	
	unsigned short		 rtt_warning, rtt_alert;
	unsigned short		 loadavg_warning, loadavg_alert;
	unsigned short		 loss_warning, loss_alert;
	unsigned short		 sockstate_warning, sockstate_alert;
	unsigned short		 cpu_warning, cpu_alert;
	unsigned int		 diskio_warning, diskio_alert;
	unsigned int		 ram_warning, ram_alert;
	unsigned int		 swap_warning, swap_alert;
	unsigned int		 netin_warning, netin_alert;
	unsigned int		 netout_warning, netout_alert;
} acl;

/* The global root node, this will be initialized to
   contain an acl object for 0/0 with the defaults filled
   in according to the #defines on top. Global configuration
   defaults can still override these values using the
   "default foobar-warning" statements. */
extern acl *ACL;

/* ------------------------------------------------------------------------- *\
 * The host-group is really not a structure that n2rxd involves itself with. *
 * It's a grouping defined purely for human consumption, allowing for a      *
 * secondary classification that has little to do with trigger-values and    *
 * more to do with organizational issues. The only real user of this is the  *
 * n2groups command, with the cli and n2view as its main consumers (until we *
 * figure out alert-notifications).                                          *
\* ------------------------------------------------------------------------- */
typedef struct hostgroup_struc
{
	struct hostgroup_struc	*next;
	char					 name[48];
	char					 emailaddr[96];
	char					 emailsubject[96];
	char					 emailfrom[96];
	char					 madurl[128];
	char					 maduser[48];
	char					 madpass[48];
	char					 description[256];
	int						 trigger;
} hostgroup;

/* ------------------------------------------------------------------------- *\
 * Like the monitor-group acls, host-group membership is also using an acl   *
 * structure, be it non-hierarchical and based on first-match.               *
\* ------------------------------------------------------------------------- */
typedef struct hostgroup_acl_struc
{
	struct hostgroup_acl_struc	*next;
	unsigned long				 addr, mask;
	hostgroup					*group;
} hostgroup_acl;

/* ------------------------------------------------------------------------- *\
 * Global structure containing 256 hash-buckets for hostgroup_acl references *
 * and a reference to the head of the linked list representing the           *
 * collection of host-groups.                                                *
\* ------------------------------------------------------------------------- */
typedef struct groupdb_struc
{
	hostgroup_acl	*hash[256];
	hostgroup		*groups;
} groupdb;

extern groupdb GROUPS;

/* ------------------------------------------------------------------------- *\
 * This voooo-macro creates accessor functions for the acl structure. It     *
 * allows some of the warning/alert values to be left as 'undefined', which  *
 * will signal the accessor to recurse up to the parent acl for a value. In  *
 * n2acl.c we define IMPLEMENT_ACLPROP before including this file to get     *
 * the proper function implementations.                                      *
 *                                                                           *
 * The following functions will be defined for each parameter, say           *
 * unsigned int foobar_warning, as declared through                          *
 *                                                                           *
 * -> DEFACLPROP (foobar_warning,unsigned int):                              *
 *                                                                           *
 *   unsigned int acl_get_foobar_warning (acl *a)                            *
 *      * Gets the acl-value                                                 *
 *                                                                           *
 *   int acl_isover_foobar_warning (acl *a, unsigned int val)                *
 *      * Returns 1 if val >= the acl-value                                  *
 * 	                                                                         *
 *   int acl_isunder_foobar_warning (acl *a, unsigned int val)               *
 *      * Returns 1 if val < the acl-value                                   *
\* ------------------------------------------------------------------------- */
#ifdef IMPLEMENT_ACLPROP
	#define DEFACLPROP(name,tp) tp acl_get_ ## name (acl *a) { \
			if (a->name == ((tp) -1)) { \
				if (a->parent) return acl_get_ ## name (a->parent); \
			} \
			return a->name; \
		} \
		int acl_isover_ ## name (acl *a, tp val) { \
			return (val >= acl_get_ ## name (a)) ? 1 : 0; \
		} \
		int acl_isunder_ ## name (acl *a, tp val) { \
			return (val < acl_get_ ## name (a)) ? 1 : 0; \
		}
#else
	#define DEFACLPROP(name,tp) tp acl_get_ ## name (acl *); \
							 int acl_isover_ ## name (acl *, tp); \
							 int acl_isunder_ ## name (acl *, tp);
#endif

/* Use the macro to implement the accessor functions */
DEFACLPROP (rtt_warning,unsigned short);
DEFACLPROP (rtt_alert,unsigned short);
DEFACLPROP (loadavg_warning,unsigned short);
DEFACLPROP (loadavg_alert,unsigned short);
DEFACLPROP (loss_warning,unsigned short);
DEFACLPROP (loss_alert,unsigned short);
DEFACLPROP (sockstate_warning,unsigned short);
DEFACLPROP (sockstate_alert,unsigned short);
DEFACLPROP (cpu_warning,unsigned short);
DEFACLPROP (cpu_alert,unsigned short);
DEFACLPROP (diskio_warning,unsigned int);
DEFACLPROP (diskio_alert,unsigned int);
DEFACLPROP (ram_warning,unsigned int);
DEFACLPROP (ram_alert,unsigned int);
DEFACLPROP (swap_warning,unsigned int);
DEFACLPROP (swap_alert,unsigned int);
DEFACLPROP (netin_warning,unsigned int);
DEFACLPROP (netin_alert,unsigned int);
DEFACLPROP (netout_warning,unsigned int);
DEFACLPROP (netout_alert,unsigned int);

#undef DEFACLPROP

/* ------------------------------------------------------------------------- *\
 * Other acl functions                                                       *
\* ------------------------------------------------------------------------- */
void		 acl_init (void);
const char	*acl_get_key (acl *a);
acl			*acl_create (unsigned long addr, unsigned long mask);
acl			*acl_match_mask (unsigned long addr, unsigned long mask);
acl			*acl_match (unsigned long addr);
void		 acl_clear (void);

/* ------------------------------------------------------------------------- *\
 * Hostgroup-related functions                                               *
\* ------------------------------------------------------------------------- */
hostgroup	*hostgroup_create (const char *);
hostgroup	*hostgroup_resolve (const char *);
void		 hostgroup_acl_create (hostgroup *, unsigned long, unsigned long);
hostgroup	*hostgroup_acl_resolve (unsigned long);

#endif
