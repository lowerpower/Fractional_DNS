/*!																			
 *---------------------------------------------------------------------------
 *! \file zones.c
 *  \brief zone file code
 *																			
 *---------------------------------------------------------------------------
 * Version                                                                  -
 *		0.1 Original Version June 3, 2009									-        
 *
 *---------------------------------------------------------------------------    
 *																			-
 * (c)2009 Yoics Inc. All Rights Reserved									-
 *---------------------------------------------------------------------------
 *
 */
#include "weaved_dns_server.h"
#include "arch.h"
#include	"debug.h"
#include	"yhash.h"
#include    "zones.h"




void
dns_zone_free(SOA *record)
{
    DNS_SERVER *tmp;

    if(record)
    {
        DEBUG1("free dns soa name %s\n",record->zone);
        // Free any strings
        if(record->zone) free(record->zone);
        if(record->email) free(record->email);
        if(record->server) free(record->server);
        while(record->dns_servers)
        {
            tmp=record->dns_servers->next;
            if(record->dns_servers->name) free(record->dns_servers->name);
            free(record->dns_servers);
            record->dns_servers=tmp;
        }
        // Finally free the record
        free(record);
    }

    return;
}

//
// Zone Record Parsing
//
//Contents of zone file will consist of multiple lines describing each server in the following format:
//
//[zone] [ns] [email] [serial] [refresh] [retry] [expire] [ttl]
//[autoritiative1 ns] [ip] [ttl]
//[autoritiative1 ns] [ip] [ttl]
//[blank line seperator]
//
// yoics.com ns1.yoics.com dns.jomax.net. 2014121000 28800 7200 604800 600
// ns1.yoics.com 192.168.2.5 ttl                                                    // we insert this as A types
// ns2.yoics.com 192.168.2.6 ttl
// [blank line to seperate zone records]
// ...
//
//typedef struct as112_zone {
//    ldns_rdf    *origin;
//    ldns_rr     *soa;
//    ldns_rr     *ns1;
//    ldns_rr     *ns2;
//} as112_zone;

//
int
dns_load_zones(DNS_CONFIG *dns)
{
FILE	    *fp;
char	    *subst;
char	    *strt_p;
int		    tret,ret=0,zone_process=0;
SOA         *soa=0,*tsoa=0;
DNS_SERVER  *dns_server=0; 
YHASH	    *new_zone_hash,*old_zone_hash;
char	    line[READ_MAX_LINE_SIZE];


	if(dns->verbose) printf("load zones from %s\n",dns->zone_file);

	// Read from file
	if(NULL == (fp = fopen( (char *) dns->zone_file, "r")) )
	{
		if(dns->verbose) printf("cannot open load zone file (%s).\n",dns->zone_file);
		return(-1);
	}
	else
	{	
		// File is open create a new filter
		new_zone_hash=yhash_init(dns->zone_size);

		if(NULL==new_zone_hash)
		{
			if(dns->verbose) printf("Failed to allocat hash in dns_load_zones\n");
			fclose(fp);
			return(-1);
		}


		// Read the Zone File Line
		while(readln_from_a_file(fp,  line, READ_MAX_LINE_SIZE-4))
		{
			// Blank Lines
			if(strlen((char *) line)==0)
            {
                if((dns->verbose) && (zone_process)) printf("done zone process\n");
                zone_process=0;
                tsoa=0;
				continue;           
            }
            // We have an entry, lets parse it, should be the same line as the UDP control
            // IE mycal.net ns1.mycal.net dns.mycal.net. 2014121000 28800 7200 604800 600

            DEBUG1("Zone Line Read %s\n",line);

            if(zone_process)
            {
                while(tsoa)
                {
                    // Malloc a NS
                    dns_server=(DNS_SERVER*)malloc(sizeof(DNS_SERVER));
                    if(0==dns_server) break;
                    // parse off ns name
                    subst=strtok_r(line," \n",&strt_p);
                    if(subst)
                    {
                        dns_server->name=(char*)malloc(strlen(subst)+1);
                        if(0==dns_server->name)
                            break;
                        strtolower(subst);
                        strcpy(dns_server->name,subst);
                    }
                    else
                        break;
                    // Parse off IP
                    subst=strtok_r(NULL," \n",&strt_p);
                    if(subst)
                    {
                        dns_server->ip.ip32=inet_addr(subst);
                    }
                    else
                        break;
                    // Parse off TTL
                    subst=strtok_r(NULL," \n",&strt_p);
                    if(subst)
                    {
                        dns_server->ttl=atoi(subst);
                    }
                    else
                        break;

                    // Good Parse, hook it up to zone
                    dns_server->next=tsoa->dns_servers;
                    tsoa->dns_servers=dns_server;
                    dns_server=0;
                    break;
                }
                if(dns_server)
                {
                    // Free
                    if(dns_server->name)
                        free(dns_server->name);
                    free(dns_server);
                    dns_server=0;
                }
                continue;
            }

            // Process Line, get zone header
            while(1)
            {
                // Malloc a zone container
                soa=(SOA*)malloc(sizeof(SOA));
                memset(soa,'\0',sizeof(SOA));
                tsoa=soa;

                if(0==soa)
                    break;

			    // Parse off zone
			    subst=strtok_r(line," \n",&strt_p);
                if(subst)
                {
                    soa->zone=(char*)malloc(strlen(subst)+1);
                    if(0==soa->zone)
                        break;
                    strtolower(subst);
                    strcpy(soa->zone,subst);
                }
                else
                    break;
                // Parse off server
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                {
                    soa->server=(char*)malloc(strlen(subst)+1);
                    if(0==soa->server)
                        break;
                    strtolower(subst);
                    strcpy(soa->server,subst);
                }
                else
                    break;
                // Parse off email
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                {
                    soa->email=(char*)malloc(strlen(subst)+1);
                    if(0==soa->server)
                        break;
                    strtolower(subst);
                    strcpy(soa->email,subst);
                }
                else
                    break;
                // Parse off serial
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                    soa->serial=atoi(subst);
                else
                    break;
                // Parse off refresh
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                    soa->refresh=atoi(subst);
                else
                    break;
                // Parse off retry
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                    soa->retry=atoi(subst);
                else
                    break;
                // Parse off  expire
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                    soa->expire=atoi(subst);
                else
                    break;
                // Parse off ttl
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                    soa->ttl=atoi(subst);
                else
                    break;

                // Good Parse, store
                if(dns->verbose) printf("insert %s into zone_hash\n",soa->zone);
                tret=yhash_insert_buffer_key(new_zone_hash, soa->zone, strlen(soa->zone),soa);
                if(tret<0)
			    {
				    if(dns->verbose) printf("insert fail error %d on inserting %s\n",tret,line);
			    }
                else
                {
                    zone_process=1;
                    soa=0;                  // Set this to zero so it doesnt get freeded below, sucessful insert
                    ret++;
                }
                break;
            }
            if(soa)
            {
                dns_zone_free(soa);
                soa=0;   
            }
		}
	}

	// Close the file
	fclose(fp);

	if(ret>0)
	{
		if(dns->verbose) printf("loaded %ld zones form %s\n",dns->zones->inserts,dns->zone_file);
		old_zone_hash=dns->zones;
		dns->zones=new_zone_hash;
		if(old_zone_hash)
		{
			// Destroy od hash no callback
			if(0>yhash_destroy(old_zone_hash,(void (*)(void *))&dns_zone_free))
			{
				if(dns->verbose) printf("Failed to destroy old hash\n");
			}			
		}
	}
	else
	{
		ret=0;
	}
	return(ret);
}


//
// Reload Zones from file
//
// Return -1 for error (no reload), 0 for no reload, 1 for reload
//
int
dns_reload_zone(DNS_CONFIG *dns)
{
	time_t old_time=dns->zone_file_info.st_mtime;

	if(-1!=stat(dns->zone_file,&dns->zone_file_info))
	{		
		// Must use difftime to be completly portable
		if( (difftime(old_time, dns->zone_file_info.st_mtime)) || (0==old_time) )
		{
			// File has changed, reload
            DEBUG1("Reload Zone File\n");
			if(dns->verbose) printf("Reload Zone File\n");
			return(dns_load_zones(dns));
		}
	}
	else
	{
		if(dns->verbose) printf("Failed stat %s\n",dns->zone_file);
	}
	return(0);
}


//
// Lookup to see if there is a zone
//
SOA*
dns_lookup_zone(DNS_CONFIG *dns, char *name)
{
    unsigned int i,sub_count=0;
    char *ptr;
    SOA* zone=0;

    // should assert 0==name or 0==dns here

    // Check the full name first
    zone=(SOA*)yhash_lookup_string(dns->zones, name);
    if(zone)
        return(zone);

    for(i=0;i<strlen(name);i++){
        if('.'==name[i])
            sub_count++;
    }
    // We checked the whole name above, now check the parts IE domain crap.crap.crap.com, we want to lookup crap.crap.com and crap.com to check zones
    ptr=name;
    while(sub_count>1)
    {
        while((*ptr) && ('.'!=*ptr))
            ptr++;
        if(0==*ptr)
            break;
        // Finally fixup and lookup
        ptr++;
        if(0==*ptr)
            break;
        zone=(SOA*)yhash_lookup_string(dns->zones, ptr);
        if(zone)
            break;
        sub_count--;
    }
    // Return zone if found
    return(zone);
}