/*!										
 *---------------------------------------------------------------------------
 *! \file control.c
 *  \brief DNS server control interface
 *
 *  Process DNS control requests here.
 *
 *																			
 *---------------------------------------------------------------------------
 * Version                                                                  -
 *		0.1 Original Version Oct 4 2014									-        
 *
 *---------------------------------------------------------------------------    
 *                                                             				-
 * Copyright (C) 2014, Weaved Inc, www.weaved.com							-
 *																			-
 *---------------------------------------------------------------------------
 */
#include "weaved_dns_server.h"
#include "arch.h"
#include "net.h"
#include "yselect.h"
#include "log.h"
#include "debug.h"


#include "dns.h"
#include "zones.h"
#include "control.h"




#define CONTROL_BUFFER_MAX 2048


//
// lookup [name]                        - searches names, then fractions for match
//
// Commands Possible:
// get zone [zone-name]
//     name [name]
//     fraction [name]
//     statistics
//
// set zone [zone info string]
//     name [name type info]
//     fraction [name type info]
//
// lookup [name]
//  
// reset zone
//       name
//       fraction
//       statistics
//
//


char *
control_process_message(DNS_CONFIG *dns, int len, char *in_buffer)
{
    char    *ret_message=0;
	char	*subst;
	char	*strt_p;

    // parse in_buffer for command, we use while here so we can break on end of parse or error
	while(strlen((char *) in_buffer)>0)
    {
        // Lets parse, if no subst, exit
        subst=strtok_r((char *) in_buffer," \n",&strt_p);
        if(0==subst)
            break;

        // Check Commands
        if(0==strcmp("get",subst))
        {
            dns->get_requests++;
            // Get commands
            subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
            
            if((0==strcmp("statistics",subst)) || (0==strcmp("stats",subst)) )
            {
                ret_message=control_statistics_return(dns);
            }else
            if((0==strcmp("name",subst)))
            {
                subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
                ret_message=control_get_name(dns,subst);
            }else
            if((0==strcmp("fraction",subst)) || (0==strcmp("frac",subst)) )
            {
                subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
                ret_message=control_get_fraction(dns,subst);
            }else
            if((0==strcmp("zone",subst)))
            {
                subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
                ret_message=control_get_zone(dns,subst);
            }
        }
        else if(0==strcmp("set",subst))
        {
            dns->set_requests++;
            subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
        }
        else if(0==strcmp("lookup",subst))
        {
            dns->get_requests++;
            subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
            ret_message=control_lookup(dns,subst);
        }
        else if(0==strcmp("zlookup",subst))
        {
            dns->get_requests++;
            subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
            ret_message=control_zone_lookup(dns,subst);
        }
        else if( (0==strcmp("reset",subst)) )
        {
            subst=strtok_r(NULL," \n",&strt_p);  if(0==subst) break;
            if((0==strcmp("statistics",subst)) || (0==strcmp("stats",subst)))
            {
                ret_message=control_statistics_reset(dns);
            }
        }
        else if( (0==strcmp("crash",subst)) )
        {
            // Force a crash of the server
                U8* crash;
				yprintf("Force SIG 11:\n");
                crash=0;
                *crash="c";  
        }
        break;  // we always exit here.
    }
    return(ret_message);
}


//
// All DNS UPD control traffic goes here
//

int
Handle_UDP_Control(DNS_CONFIG *dns)
{
    int ret,slen;
	struct sockaddr_in	server;				/* Information about the server */
    IPADDR  tip;
    char    in_buffer[CONTROL_BUFFER_MAX];
    char    *output;

    //
    // Receive the packet
    //
    memset(&server,'\0',sizeof(struct sockaddr));
    slen=sizeof(struct sockaddr_in);
    ret=recvfrom(dns->udp_control_soc, in_buffer, CONTROL_BUFFER_MAX-1, 0, (struct sockaddr *)&server, (socklen_t *) &slen);

    if(ret>0)
    {
        //
        // Check dest IP address, if broadcast.
        tip.ip32=server.sin_addr.s_addr;
        if(255==tip.ipb4)
        {
            dns->rx_broadcast_packets++;
            return(-1);
        }
        // zero term
        in_buffer[ret]=0;


        dns->control_reqeusts++;
        // process messages
        output=control_process_message(dns,ret,in_buffer);
        // If output send response
        if(0==output)
        {   
            dns->bad_requests++;
            output=(char*)malloc(strlen("bad request\n")+1);
            strcpy(output,"bad request\n");
        }
        if(output)
        {
            // Build send structure
            // Send it back, todo : if we send ouver 1500bytes for some reason, split it up into multiple dgrams (may not be necessary)
            ret=sendto(dns->udp_control_soc, output, strlen(output), 0, (struct sockaddr *)&server, sizeof(struct sockaddr));
            if(-1==ret)
                dns->tx_errors++;
            else
                dns->tx_packets++;
            // free buffer
            free(output);
        }
    }
	else if(SOCKET_ERROR==ret)
	{
		ret=get_last_error();
		if(ret!=EWOULDBLOCK)
        {
            //dns->rx_errors++;
			DEBUG3("Error %d on main read\n",ret);
        }
    }
    return(0);
}



char *
control_respond_lookup(DNS_RECORD *drec)
{
    char output[2048];
    char *ret=0;

    output[0]=0;

    if(DNS_TYPE_AAAA ==drec->type)
    {
        // Need to finish this
    }
    if(DNS_TYPE_A ==drec->type)
    {
        sprintf(output,"A %d.%d.%d.%d\n",drec->ip.ipb1,drec->ip.ipb2,drec->ip.ipb3,drec->ip.ipb4);
    }
    else if(DNS_TYPE_CNAME ==drec->type)
    {
        sprintf(output,"CNAME %s\n",drec->value);
    }
    else if(DNS_TYPE_NS ==drec->type)
    {
        sprintf(output,"NS %s\n",drec->value);
    }
    else
    {
        sprintf(output,"Lookup Failed\n");
    }
    if(strlen(output))
    {
        ret=(char *)malloc(strlen(output)+1);
        if(ret)
            strcpy(ret,output);
    }
    return(ret);
}

char *
control_respond_zone(SOA *zone)
{
    DNS_SERVER  *dns_server=0;
    char output[2048];
    char tbuff[2048];
    char *ret;

    ret=0;
    output[0]=0;
    dns_server=zone->dns_servers;

    // Build zone record [zone] [ns] [email] [serial] [refresh] [retry] [expire] [ttl]
    sprintf(output,"%s %s %d %d %d %d %d\n",zone->zone,zone->email,zone->serial,zone->refresh,zone->retry,zone->expire,zone->ttl);
    // Add name servers
    while(dns_server)
    {
        sprintf(tbuff,"%s\n",dns_server->name);
        if((strlen(output)+strlen(tbuff))<(2048-2))
            strcat(output,tbuff);
        dns_server=dns_server->next;
    }


    if(strlen(output))
    {
        ret=(char *)malloc(strlen(output)+1);
        if(ret)
            strcpy(ret,output);
    }
    return(ret);
}

//
// Look up a name, could be in any hash, lookup exact, then fraction last
//
char *
control_lookup(DNS_CONFIG *dns,char *name)
{
    DNS_RECORD *drec;
    char    fname[2048];
    char    *ret=0;

    // First look for exact match
    drec=(DNS_RECORD*)yhash_lookup_string(dns->names, name);
    if(0==drec)
    {
        if(strlen(name)<2047)
            if(create_fraction(fname,name))
                drec=(DNS_RECORD*)yhash_lookup_string(dns->fractions, fname);
    }
    if(drec)
        ret=control_respond_lookup(drec);
    else
    {
        ret=(char*)malloc(sizeof("Not Found\n")+1);
        if(ret)
            strcpy(ret,"Not Found\n");
    }

    return(ret);
}

//
// Look up a zone for a name
//
char *
control_zone_lookup(DNS_CONFIG *dns,char *name)
{
    SOA     *zone;
    char    *ret=0;

    // Find the zone for the name
    zone=dns_lookup_zone(dns, name);

    if(zone)
        ret=control_respond_zone(zone);
    else
    {
        ret=(char*)malloc(sizeof("Not Found\n")+1);
        if(ret)
            strcpy(ret,"Not Found\n");
    }

    return(ret);
}


//
// get a name must be exact hit, no fractions
//
char *
control_get_name(DNS_CONFIG *dns,char *name)
{
    DNS_RECORD *drec;
    char    *ret=0;

    // First look for exact match
    drec=(DNS_RECORD*)yhash_lookup_string(dns->names, name);

    if(drec)
        ret=control_respond_lookup(drec);
    else
    {
        ret=(char*)malloc(sizeof("Not Found\n")+1);
        if(ret)
            strcpy(ret,"Not Found\n");
    }

    return(ret);
}

//
// get a fraction, must be an exact hit
//
char *
control_get_fraction(DNS_CONFIG *dns,char *name)
{
    DNS_RECORD *drec;
    char    *ret=0;

    // First look for exact match
    drec=(DNS_RECORD*)yhash_lookup_string(dns->fractions, name);

    if(drec)
        ret=control_respond_lookup(drec);
    else
    {
        ret=(char*)malloc(sizeof("Not Found\n")+1);
        if(ret)
            strcpy(ret,"Not Found\n");
    }

    return(ret);
}

//
// Look up a name, could be in any hash, lookup exact, then fraction last
//
char *
control_get_zone(DNS_CONFIG *dns,char *name)
{
     SOA        *zone;
    char        *ret=0;

    zone=(SOA*)yhash_lookup_string(dns->zones, name);

    if(zone)
        ret=control_respond_zone(zone);
    else
    {
        ret=(char*)malloc(sizeof("Not Found\n")+1);
        if(ret)
            strcpy(ret,"Not Found\n");
    }

    return(ret);
}


char *
control_statistics_return(DNS_CONFIG *dns)
{
    char output[2048];
    char *ret;

    sprintf(output,
            "names=%ld\n"
            "fractions=%ld\n"
            "zones=%ld\n"
            "requests=%ld\n" 
            "direct_hits=%ld\n" 
            "fractional_hits=%ld\n" 
            "nomatch=%ld\n" 
            "unknown_pkts=%ld\n" 
            "runt_pkts=%ld\n" 
            "control_req=%ld\n" 
            "set_req=%ld\n" 
            "get_req=%ld\n" 
            "bad_req=%ld\n" 
            "rx_pkts=%ld\n" 
            "tx_pkts=%ld\n" 
            "tx_errors=%ld\n" 
            "rx_errors=%ld\n",
            dns->names->elements,
            dns->fractions->elements,
            dns->zones->elements,
             dns->requests,
             dns->direct_hits,
             dns->fractional_hits,
             dns->nomatch_hits,
             dns->unknown_packets,
             dns->runt_packets,
             dns->control_reqeusts,
             dns->set_requests,
             dns->get_requests,
             dns->bad_requests,
             dns->rx_packets,
             dns->tx_packets,
             dns->tx_errors,
             dns->rx_errors);

        ret=(char*)malloc(strlen(output)+1);
        if(ret)
            strcpy(ret,output);

        return(ret);
}


char *
control_statistics_reset(DNS_CONFIG *dns)
{
    char *ret;

    dns->requests=
    dns->direct_hits=
    dns->fractional_hits=
    dns->nomatch_hits=
    dns->unknown_packets=
    dns->runt_packets=
    dns->set_requests=
    dns->get_requests=
    dns->bad_requests=
    dns->rx_packets=
    dns->tx_packets=
    dns->tx_errors=
    dns->udp_requests=
    dns->tcp_requests=
    dns->rx_broadcast_packets=
    dns->control_reqeusts=
    dns->rx_errors=0;

    ret=(char*)malloc(sizeof("OK\n")+1);
    if(ret)
        strcpy(ret,"OK\n");
    return(ret);
}