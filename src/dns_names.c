/*!																			
 *---------------------------------------------------------------------------
 *! \file dns_names.c
 *  \brief dns name records
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
#include    "dns.h"
#include    "dns_names.h"

void
dns_name_free(DNS_RECORD *record)
{
    if(record)
    {
        DEBUG1("free dns name %s\n",record->name);
        // Free any strings
        if(record->name) free(record->name);
        if(record->value) free(record->value);
        if(record->host) free(record->host);

        // Finally free the record
        free(record);
    }
    return;
}


//
// Convert DNS ASCII types to there numeric value, IE. DNS_TYPE_TXT -->  16
//
int
dns_type_translate(char *string)
{
int ret=-1;

    strtolower(string);
    if(0==strcmp(string,"a"))
        ret=DNS_TYPE_A; 
    else if(0==strcmp(string,"cname"))
        ret=DNS_TYPE_CNAME; 
    else if(0==strcmp(string,"mx"))
        ret=DNS_TYPE_MX; 
    else if(0==strcmp(string,"txt"))
        ret=DNS_TYPE_TXT ; 
    else if(0==strcmp(string,"ns"))
        ret=DNS_TYPE_NS ; 
    else if(0==strcmp(string,"ptr"))
        ret=DNS_TYPE_PTR ; 

    return(ret);
}

//
// Return -1 for error 1 for reload
//
//Contents of names will consist of multiple lines, each describing a name and its associated value, the following formats are supported:
//
//[name] [type] [value] [ttl]
//
//
// example:
//
// dood.example.com a 192.168.2.5 600
// example.com cname google.com 600 
//
//
int
dns_load_names(DNS_CONFIG *dns)
{
FILE	*fp;
char	*subst;
char	*strt_p;
int		tret,ret=0;
DNS_RECORD *record=0;
YHASH	*new_name_hash,*old_name_hash;
char	line[READ_MAX_LINE_SIZE];


	if(dns->verbose) printf("load names from %s\n",dns->name_file);

	// Read from file
	if(NULL == (fp = fopen( (char *) dns->name_file, "r")) )
	{
		if(dns->verbose) printf("cannot open load zone file (%s).\n",dns->name_file);
		return(-1);
	}
	else
	{	
		// File is open create a new filter
		new_name_hash=yhash_init(dns->zone_size);

		if(NULL==new_name_hash)
		{
			if(dns->verbose) printf("Failed to allocat hash in dns_load_names\n");
			fclose(fp);
			return(-1);
		}


		// Read the Zone File Line
		while(readln_from_a_file(fp,  line, READ_MAX_LINE_SIZE-4))
		{
			// Blank Lines
			if(strlen((char *) line)==0)
				continue;           

            // We have an entry, lets parse it, should be the same line as the UDP control
            // IE mycal.net ns1.mycal.net dns.mycal.net. 2014121000 28800 7200 604800 600

            DEBUG1("Name Line Read %s\n",line);

            // Process Line
            while(1)
            {
                // Malloc a zone container
                record=(DNS_RECORD *)malloc(sizeof(DNS_RECORD));
                // clean it, we assume null pointers to start
                memset(record,'\0',sizeof(DNS_RECORD));

                if(0==record)
                    break;

			    // Parse off name
			    subst=strtok_r(line," \n",&strt_p);
                if(subst)
                {
                    record->name=(char*)malloc(strlen(subst)+1);
                    if(0==record->name)
                        break;
                    strcpy(record->name,subst);
                }
                else
                    break;
                // Parse off type
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                {
                    // Match Type
                    record->type=dns_type_translate(subst);
                    if(record->type<0)
                        break;
                }
                else
                    break;
                // Parse off value
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                {
                    int     err=1;
                    switch(record->type){
                    case DNS_TYPE_A:
                        record->ip.ip32=inet_addr(subst);
                        err=0;
                        break;
                    case DNS_TYPE_TXT:
                    case DNS_TYPE_CNAME:
                    case DNS_TYPE_MX:
                    case DNS_TYPE_NS:
                        err=0;
                        record->value=(char*)malloc(strlen(subst)+1);
                        if(0==record->value)
                            break;
                        strcpy(record->value,subst);
                        break;
                    default:
                        break;
                    }
                    if(err)
                        break;
                }
                else
                    break;
                // Parse off ttl
			    subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                    record->ttl=atoi(subst);
                else
                    break;

                // Good Parse, store
                if(dns->verbose) printf("insert %s into name_hash\n",record->name);
                tret=yhash_insert_buffer_key(new_name_hash, record->name, strlen(record->name),record);
                if(tret<0)
			    {
                    DEBUG1("insert fail error %d on inserting %s\n",tret,line);
				    if(dns->verbose) printf("insert fail error %d on inserting %s\n",tret,line);
			    }
                else
                {
                    record=0;                  // Set this to zero so it doesnt get freeded below, sucessful insert
                    ret++;
                }
                break;
            }
            if(record)
            {
                dns_name_free(record);
                record=0;   
            }
		}
	}

	// Close the file
	fclose(fp);

	if(ret>0)
	{
		if(dns->verbose) printf("loaded %ld zones form %s\n",dns->names->inserts,dns->name_file);
		old_name_hash=dns->names;
		dns->names=new_name_hash;
		if(old_name_hash)
		{
			// Destroy od hash no callback
			if(0>yhash_destroy(old_name_hash,(void (*)(void *))&dns_name_free))
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
// Return -1 for error (no reload), 0 for no reload, 1 for reload
//
int
dns_reload_names(DNS_CONFIG *dns)
{
	time_t old_time=dns->name_file_info.st_mtime;

	if(-1!=stat(dns->name_file,&dns->name_file_info))
	{		
		// Must use difftime to be completly portable
		if( (difftime(old_time, dns->name_file_info.st_mtime)) || (0==old_time) )
		{
			// File has changed, reload
            DEBUG1("Reload NAME File\n");
			if(dns->verbose) printf("Reload NAME File\n");
			return(dns_load_names(dns));
		}
	}
	else
	{
		if(dns->verbose) printf("Failed stat %s\n",dns->name_file);
	}
	return(0);
}




//
// Return -1 for error 1 for reload
//
//Contents of names will consist of multiple lines, each describing a fraction and its associated value, the following formats are supported:
//
//[fraction name] [type] [value] [ttl]
//
//
// example:
//
// S001.example.com a 192.168.2.5 600
// S010.example.com cname google.com 600 
//
//
int
dns_load_fractions(DNS_CONFIG *dns)
{
FILE	*fp;
char	*subst;
char	*strt_p;
int		tret,ret=0;
DNS_RECORD *record=0;
YHASH	*new_fraction_hash,*old_fraction_hash;
char	line[READ_MAX_LINE_SIZE];


	if(dns->verbose) printf("load fractions from %s\n",dns->fraction_file);

	// Read from file
	if(NULL == (fp = fopen( (char *) dns->fraction_file, "r")) )
	{
		if(dns->verbose) printf("cannot open load zone file (%s).\n",dns->fraction_file);
		return(-1);
	}
	else
	{	
		// File is open create a new filter
		new_fraction_hash=yhash_init(dns->fraction_size);

		if(NULL==new_fraction_hash)
		{
			if(dns->verbose) printf("Failed to allocat hash in dns_load_fractions\n");
			fclose(fp);
			return(-1);
		}


		// Read the Zone File Line
		while(readln_from_a_file(fp,  line, READ_MAX_LINE_SIZE-4))
		{
			// Blank Lines
			if(strlen((char *) line)==0)
				continue;           

            // We have an entry, lets parse it, should be the same line as the UDP control
            // IE mycal.net ns1.mycal.net dns.mycal.net. 2014121000 28800 7200 604800 600

            DEBUG1("Name Line Read %s\n",line);

            // Process Line
            while(1)
            {
                // Malloc a zone container
                record=(DNS_RECORD *)malloc(sizeof(DNS_RECORD));
                // clean it, we assume null pointers to start
                memset(record,'\0',sizeof(DNS_RECORD));

                if(0==record)
                    break;

			    // Parse off name
			    subst=strtok_r(line," \n",&strt_p);
                if(subst)
                {
                    record->name=(char*)malloc(strlen(subst)+1);
                    if(0==record->name)
                        break;
                    strtolower(subst);
                    strcpy(record->name,subst);
                }
                else
                    break;
                // Parse off type
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                {
                    // Match Type
                    record->type=dns_type_translate(subst);
                    if(record->type<0)
                        break;
                }
                else
                    break;
                // Parse off value
                subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                {
                    int     err=1;
                    switch(record->type){
                    case DNS_TYPE_A:
                        record->ip.ip32=inet_addr(subst);
                        err=0;
                        break;
                    case DNS_TYPE_TXT:
                    case DNS_TYPE_CNAME:
                    case DNS_TYPE_MX:
                    case DNS_TYPE_NS:
                        err=0;
                        record->value=(char*)malloc(strlen(subst)+1);
                        if(0==record->value)
                            break;
                        strtolower(subst);
                        strcpy(record->value,subst);
                        break;
                    default:
                        break;
                    }
                    if(err)
                        break;
                }
                else
                    break;
                // Parse off ttl
			    subst=strtok_r(NULL," \n",&strt_p);
                if(subst)
                    record->ttl=atoi(subst);
                else
                    break;

                // Good Parse, store
                if(dns->verbose) printf("insert %s into fraction_hash\n",record->name);
                tret=yhash_insert_buffer_key(new_fraction_hash, record->name, strlen(record->name),record);
                if(tret<0)
			    {
                    DEBUG1("insert fail error %d on inserting %s\n",tret,line);
				    if(dns->verbose) printf("insert fail error %d on inserting %s\n",tret,line);
			    }
                else
                {
                    record=0;                  // Set this to zero so it doesnt get freeded below, sucessful insert
                    ret++;
                }
                break;
            }
            if(record)
            {
                dns_name_free(record);
                record=0;   
            }
		}
	}

	// Close the file
	fclose(fp);

	if(ret>0)
	{
		if(dns->verbose) printf("loaded %ld fractions from %s\n",dns->fractions->inserts,dns->fraction_file);
		old_fraction_hash=dns->fractions;
		dns->fractions=new_fraction_hash;
		if(old_fraction_hash)
		{
			// Destroy od hash no callback
			if(0>yhash_destroy(old_fraction_hash,(void (*)(void *))&dns_name_free))
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

int
dns_reload_fractions(DNS_CONFIG *dns)
{
	time_t old_time=dns->fraction_file_info.st_mtime;

	if(-1!=stat(dns->fraction_file,&dns->fraction_file_info))
	{		
		// Must use difftime to be completly portable
		if( (difftime(old_time, dns->fraction_file_info.st_mtime)) || (0==old_time) )
		{
			// File has changed, reload
            DEBUG1("Reload Fraction File\n");
			if(dns->verbose) printf("Reload Fraction File\n");
			return(dns_load_fractions(dns));
		}
	}
	else
	{
		if(dns->verbose) printf("Failed stat %s\n",dns->fraction_file);
	}
	return(0);
}


