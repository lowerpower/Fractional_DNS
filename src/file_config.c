/* 																www.yoics.com
 *---------------------------------------------------------------------------
 *! \file file_config.c
 *  \brief Configuration file reader 
 *																			
 *---------------------------------------------------------------------------
 * Version                                                                  -
 *		0.1 Original Version June 3, 2006									-        
 *
 *---------------------------------------------------------------------------    
 *                                                             				-
 * Copyright (C) 2006, Yoics Inc, www.yoics.com								-
 *                                                                         	-
 * $Date: 2006/08/29 20:35:55 $
 *
 *---------------------------------------------------------------------------
 *
 * Notes:
 *
 * 
 *
*/

#include "config.h"
#include "file_config.h"
#include "log.h"
#include "arch.h"
#include "debug.h"

// config file strings

#define		DNS_LISTEN_IP				"listen_ip"
#define		DNS_UDP_LISTEN_PORT			"udp_dns_port"
#define		DNS_TCP_LISTEN_PORT			"tcp_dns_port"         
#define		DNS_UDP_CMD_PORT    		"udp_cmd_port"
#define		DNS_VERBOSE					"verbose"
#define		DNS_STAT_FILE				"stat_file"
#define		DNS_STAT_INTERVAL			"stat_interval"
#define		DNS_LOG_PORT				"udp_log_port"
#define		DNS_AUTO_RELOAD				"auto_reload"




#define MAX_LINE_SIZE	2048
//
//
//
int
read_file_config(char *file, DNS_CONFIG *config)
{
	U8		line[MAX_LINE_SIZE];
	char	*subst;
	char	*strt_p;
	int		ret=0;
	FILE	*fp;

	if(config->verbose) printf("config file %s\n",file);

	// Read from file
	if(NULL == (fp = fopen( (char *) file, "r")) )
	{
		if(config->verbose) printf("cannot open %s config file.\n",file);
		ret=0;
	}
	else
	{	
		while(readln_from_a_file(fp, (char *) line, MAX_LINE_SIZE-4))
		{
			if(strlen((char *) line)==0)
				continue;

			subst=strtok_r((char *) line," \n",&strt_p);

			// Get Rid of whitespace
			while(*subst==' ')
				subst++;

			DEBUG1("readcmd->%s\n",subst);


			if(strlen( (char *) subst)==0)
			{
				// do nothing
            }
			else if(0==strcmp((char *) subst,DNS_UDP_CMD_PORT))
			{
				subst=strtok_r(NULL," \n",&strt_p);
				config->udp_control_port=(U16) atoi((char *) subst);		
			}
			else if(0==strcmp((char *) subst,DNS_UDP_LISTEN_PORT))
			{
				subst=strtok_r(NULL," \n",&strt_p);
				config->dns_udp_port=(U16) atoi((char *) subst);		
			}
			else if(0==strcmp((char *) subst,DNS_TCP_LISTEN_PORT))
			{
				subst=strtok_r(NULL," \n",&strt_p);
				config->dns_tcp_port=(U16) atoi((char *) subst);		
			}
			else if(0==strcmp((char *) subst,DNS_LISTEN_IP))
			{
				subst=strtok_r(NULL,".\n",&strt_p);
				if(strlen((char *) subst))
					config->Bind_IP.ipb1=atoi(subst);		

				subst=strtok_r(NULL,".\n",&strt_p);
				if(strlen((char *) subst))
					config->Bind_IP.ipb2=atoi(subst);

				subst=strtok_r(NULL,".\n",&strt_p);
				if(subst)
					config->Bind_IP.ipb3=atoi(subst);

				subst=strtok_r(NULL,".\n",&strt_p);
				if(subst)
					config->Bind_IP.ipb4=atoi(subst);
			}
			else if(0==strcmp(subst,DNS_AUTO_RELOAD))
			{
				subst=strtok_r(NULL," \n",&strt_p);
				config->auto_reload=atoi(subst);
			}
			else if(0==strcmp(subst,DNS_STAT_INTERVAL))
			{
				subst=strtok_r(NULL," \n",&strt_p);
				config->stats_interval=atoi(subst);
			}
			else if(0==strcmp(subst,DNS_STAT_FILE))
			{
		        subst=strtok_r(NULL," \n",&strt_p);
        		strncpy(config->stats_file,subst,MAX_PATH);
		        config->stats_file[MAX_PATH-1]=0;
			}
		}
		ret=1;
		fclose(fp);
	}
	return(ret);
}



