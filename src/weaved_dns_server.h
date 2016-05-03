#ifndef __Y_DNS_SERVER_H__
#define __Y_DNS_SERVER_H__
//---------------------------------------------------------------------------
// Weeaved_dns_server.h - Weaved DNS server         						-
//---------------------------------------------------------------------------
// Version                                                                  -
//		0.1 Original Version Oct 5, 2014     							-
//																			-
// (c)2014 Yoics Inc. All Rights Reserved									-
//---------------------------------------------------------------------------
#include "config.h"
#include "mytypes.h"
#include "log.h"
#include "yhash.h"

#if defined(BACKTRACE_SYMBOLS)
#include <execinfo.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#endif


#if defined(WIN32)
#define DEFAULT_CONFIG_FILE			"c:/weaved/dns_config.txt"
#define DEFAULT_ZONE_FILE           "c:/weaved/dns_zones.txt"    
#define DEFAULT_NAME_FILE           "c:/weaved/dns_names.txt"
#define DEFAULT_FRACTION_FILE       "c:/weaved/dns_fractions.txt"
#else
#define DEFAULT_CONFIG_FILE			"/etc/weaved/dns_config.txt"
#define DEFAULT_ZONE_FILE           "/etc/weaved/dns_zones.txt"    
#define DEFAULT_NAME_FILE           "/etc/weaved/dns_names.txt"
#define DEFAULT_FRACTION_FILE       "/etc/weaved/dns_fractions.txt"
#endif

#if defined(WIN32)
#define DEFAULT_STATISTICS_FILE     "c:/weaved/dns_stats.txt"
#else
#define DEFAULT_STATISTICS_FILE     "/tmp/dns_stats.txt"
#endif
#define DEFAULT_STATISTICS_INTERVAL 15

#define MAX_PKT_SIZE			1600
#define MIN_PKT_SIZE			10							// Ignore packets smaller than this

#define	MAX_YOICSID_SIZE		127
#define	UID_LEN					8
#define MAX_SERVERS				128
#define READ_MAX_LINE_SIZE		128

#define DNS_DEFAULT_ZONE_SIZE       10                          /*optimized for 512 zones */
#define DNS_DEFAULT_NAME_SIZE       15                          /*optimized for 32K names */
#define DNS_DEFAULT_FRACTION_SIZE   10                          /*optimized for 512 fractions */


//
// GF flags, global flags
//
#define	GF_GO			0x01				/* go */
#define GF_DAEMON		0x02				/* we are a daemon */
#define GF_QUIET		0x08				/* no output */
#define GF_CMD_LINE		0x10				/*  */
#define GF_CMD_PROC		0x20				/* Turn on command line processor */
#define GF_BANG_STATUS	0x40				/* turn on stat output */


typedef struct dns_server_
{
    struct dns_server_     *next;
    char                    *name;
	IPADDR		            ip;
    int                     ttl;
}DNS_SERVER;

typedef struct service_of_authority_
{
    char        *zone;
    char        *email;
    char        *server;
    int         refresh;
    int         retry;
    int         expire;
    int         serial;
    int         ttl;
    DNS_SERVER *dns_servers;
}SOA;

typedef struct dns_record_
{
    char        *name;                          /* should we call this host */
    int         type;                           /* record type              */
    char        *value;                         /* for cname,txt or MX      */
    char        *host;
	IPADDR		ip;
                                                /* need to add IPV6 TYPE    */
    int         ttl;
}DNS_RECORD;

typedef struct dns_zone_record_
{
    char        *name;                          /* should we call this host */
    int         value;                          /* cname, txt, or mx        */
	IPADDR		ip;
    int         priority;
    int         type;
    int         ttl;
    char        *service;
    char        *protocol;
    char        *target;
    int         weight;
    int         port;
}DNS_ZONE_RECORD;

// Custom File config for each product here
typedef struct dns_config_
{
    U16			udp_control_port;
	U16			dns_udp_port;
	U16			dns_tcp_port;                         
	IPADDR		Bind_IP;

    SOCKET		udp_control_soc;
	SOCKET		udp_listen_soc;
	SOCKET		tcp_listen_soc;
    //
	int			verbose;
	int			log_level;
	int			auto_reload;

	// records
	YHASH		*names;	    					// Hash of names to lookup
    YHASH		*fractions;    					// Hash of fractional Names to lookup
    YHASH		*zones;    					    // Hash of zones to lookup
    //
    // sizes
    int         name_size;                      // default 15 optimized for 16K names
    int         fraction_size;                  // default 11 optimized for 1024 fractions
    int         zone_size;                      // default 10 optimized for 512 zoness

	// Zone File, only autority zones
	char		zone_file[MAX_PATH];
	struct stat zone_file_info;
	
    // Name File
	char		name_file[MAX_PATH];
	struct stat name_file_info;

	// Fractions File
	char		fraction_file[MAX_PATH];
	struct stat fraction_file_info;
	
	// stats file
    unsigned int stats_interval;
	char		stats_file[MAX_PATH];	
	char		last_msg[256];

	// stats
	long		records;
    // UDP
	long		rx_packets;                         
	long		tx_packets;
	long		tx_errors;
	long		rx_errors;
	
    long		requests;
	long		tcp_requests;
	long		udp_requests;
	long		direct_hits;
	long		fractional_hits;
	long		nomatch_hits;
	long		unknown_packets;
    long        rx_broadcast_packets;
	long		runt_packets;
    long        control_reqeusts;
	long		set_requests;
	long		get_requests;
	long		bad_requests;
	char		pidfile[MAX_PATH];
}DNS_CONFIG;






#endif

