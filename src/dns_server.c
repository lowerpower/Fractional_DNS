/*!								www.yoics.com			
 *---------------------------------------------------------------------------
 *! \file dns_server.c
 *  \brief Weaved DNS Server
 *
 *  This first version of weaved dns server using yhash for local data
 *  and redis for IPC and database.  This listens only for UDP requests,
 *  A TCP service should run and handle TCP requests (this could just be a 
 *  proxy to UDP).
 *
 *  This design should not block at all, process packet and reply if
 *  Possible or queue it to redis.  Read redis queue and send needed
 *  reply.
 *
 *  Goal is 60K requests per second, reach 120K requests per second.
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
 *
 * Notes:
 * 
 * Likely we should update this to use libevent so we can handle api
 * calls and requests.   Otherwise we should create an API handler
 * as a seperate process and communicate via the UDP interface.
 *
 *
 *
*/

/*					*/ 
/* include files 	*/
/*					*/
#include "weaved_dns_server.h"
#include "arch.h"
#include "net.h"
#include "file_config.h"
#include "yselect.h"
#include "daemonize.h"
#include "debug.h"
#include "dns.h"
#include "control.h"
#include "zones.h"
#include "dns_names.h"

#if defined(WIN32)
#include "wingetopt.h"
#endif

int			    go=1;
DNS_CONFIG	    *global_dns_ptr=0;
int             global_flag;


//
// Update the statistics file, should only be called periodically at most every 15 seconds, more likely every 1-5 min for MRTG or similar.
//
int
write_statistics(DNS_CONFIG *dns)
{
	FILE *fp;
	
	if(!dns->stats_file)
		return(-1);
	if(0==strlen((char*)dns->stats_file))
		return(-1);

	DEBUG2(" writing stats at %s\n",dns->stats_file);

	if(NULL == (fp = fopen((char*)dns->stats_file, "w")) )				// fopen_s for windows?
		return -1;

   	fprintf(fp,"dns_records = %ld;\n",dns->records);
	fprintf(fp,"dns_lookup_requests = %ld;\n",dns->requests);
	fprintf(fp,"dns_fractional_lookups = %ld;\n",dns->fractional_hits);
	fprintf(fp,"dns_exact_lookups = %ld;\n",dns->direct_hits);
	fprintf(fp,"dns_nomatch_lookups = %ld;\n",dns->nomatch_hits);
	fprintf(fp,"unknown_pkts = %ld;\n",dns->unknown_packets);
    fprintf(fp,"set_pkts = %ld;\n",dns->set_requests);
    fprintf(fp,"get_pkts = %ld;\n",dns->get_requests);
    fprintf(fp,"get_pkts = %ld;\n",dns->bad_requests);
	fprintf(fp,"tx_pkts = %ld;\n",dns->tx_packets);
	fprintf(fp,"tx_err = %ld;\n",dns->tx_errors);
	fprintf(fp,"rx_pkts = %ld;\n",dns->rx_packets);
	fprintf(fp,"runt_pkts = %ld;\n",dns->runt_packets);	
	// Last message
	fclose(fp);
	return(0);
}






void
initialize_test_hash(DNS_CONFIG *dns)
{
    // Test hash inserts
    {
        // Add test reord
        DNS_RECORD *dnsr,*fdns;
        dnsr=malloc(sizeof(DNS_RECORD));
        fdns=malloc(sizeof(DNS_RECORD));
        memset(dnsr,'\0',sizeof(DNS_RECORD));
        memset(fdns,'\0',sizeof(DNS_RECORD));
        dnsr->name=malloc(strlen("1.dood.com")+1);
        strcpy(dnsr->name,"1.dood.com");
        dnsr->ttl=1200;
        dnsr->type=DNS_TYPE_A;
        fdns->name=malloc(strlen("p007.weaved.co")+1);
        strcpy(fdns->name,"p007.weaved.co");
        fdns->ttl=600;
        fdns->type=DNS_TYPE_A;
        fdns->ip.ip32=0x0200007f;
        dnsr->ip.ip32=0x0100007f;
        yhash_insert_string_key(dns->names,dnsr->name, dnsr);
        yhash_insert_string_key(dns->fractions,fdns->name, fdns);
    }    
}




//
// We receive packets here, this is very simple, we only support responding to two types of packets, map requests and auth requests.  We do not 
// Support encrypted packets, we will wait for a UDP packet here and process it one by one, if no UDP packets comes for the setup timeout (currently
//	1 second) we will return.
//
int
dns_rx_packet(DNS_CONFIG *dns)
{
	int					ret;

    //
    // Wait on select, 200ms, chance YS to ms paramters
    //
    DEBUG3("call select\n");
    ret = Yoics_Select(2000);

	//yprintf("select returned %d\n",ret);
	// If timeout don't RX
	if(SOCKET_ERROR==ret)
	{
		//threadswitch();
		DEBUG3("select error %d\n",get_last_error());       
		return(ret);
	}else
    if(0<ret)
    {
        // Figure out what kind of packet
        if(Yoics_Is_Select(dns->udp_control_soc))
        {
            Handle_UDP_Control(dns);
        }
        if(Yoics_Is_Select(dns->udp_listen_soc))
        {
            Handle_UDP_DNS(dns);
        }
        //if(Yoics_Is_Select(dns->tcp_listen_soc))
        //{
        //   Handle_TCP_DNS(dns);
        // }
    }
    else if(0==ret)
    {
        DEBUG3("slect=0\n");
    }
    

	return(0);
}






#if defined(WIN32)
BOOL WINAPI ConsoleHandler(DWORD CEvent)
{
    switch(CEvent)
    {
    case CTRL_C_EVENT:
		yprintf("CTRL+C received!\n");
        break;
    case CTRL_BREAK_EVENT:
		yprintf("CTRL+BREAK received!\n");
        break;
    case CTRL_CLOSE_EVENT:
		yprintf("program is being closed received!\n");
        break;
    case CTRL_SHUTDOWN_EVENT:
		yprintf("machine is being shutdown!\n");
		break;
    case CTRL_LOGOFF_EVENT:
		return FALSE;
    }
	go=0;

    return TRUE;
}

#else

void
termination_handler (int signum)
{
	if(global_dns_ptr->verbose) printf("term handler for signal %d\n",signum);

	sprintf(global_dns_ptr->last_msg,"term handler for signal %d\n",signum);
	//write_statistics(global_chat_ptr);
	go=0;	

    if((SIGFPE==signum) || (SIGSEGV==signum) || (11==signum))
    {
        yprintf("Weaved DNS Terminated from Signal %d\n",signum);
		if(global_flag&GF_DAEMON) syslog(LOG_ERR,"Weaved DNS Terminated from Signal 11\n");

#if defined(BACKTRACE_SYMBOLS)
              {
                // addr2line?                
                void* callstack[128];
                int i, frames = backtrace(callstack, 128);
                char** strs = backtrace_symbols(callstack, frames);
                yprintf("backtrace:\n");
                for (i = 0; i < frames; ++i) 
                {
                    yprintf("T->%s\n", strs[i]);
                    if(global_flag&GF_DAEMON)  syslog(LOG_ERR,"T->%s\n", strs[i]);
                }
                free(strs);
                fflush(stdout);
              }
#endif
        exit(11);
    }
}
#endif


void
startup_banner()
{
	//------------------------------------------------------------------
	// Print Banner
	//------------------------------------------------------------------
	printf("yoics_dns_server built " __DATE__ " at " __TIME__ "\n");
	printf("   Version " VERSION " - (c)2014 Weaved Inc. All Rights Reserved\n");
	fflush(stdout);	
}


void usage(int argc, char **argv)
{
  startup_banner();

  printf("usage: %s [-h] [-v(erbose)] [-d][pid file] [-f config_file] [-c control_port] [-u dns_udp_port] [-t dns_tcp_port] \n",argv[0]);
  printf("\t -h this output.\n");
  printf("\t -v console debug output.\n");
  printf("\t -d runs the program as a daemon with optional pid file.\n");
  printf("\t -f specify a config file.\n");
  printf("\t -c control port (defaults to 5950)\n");
  printf("\t -u dns udp port (defaults to 53)\n");
  printf("\t -c dns tcp port (defaults to 53)\n");
  exit(2);
}

int main(int argc, char *argv[])
{
char			config_file[MAX_PATH];
DNS_CONFIG		dns;
int				range_len=0;
int				c;
U32				timestamp=second_count();

#if defined(LINUX) || defined(MACOSX)
/* Our process ID and Session ID */
pid_t			pid, sid;

	signal(SIGPIPE, SIG_IGN);
#endif


	go=1;
	// Set default config file
	memset(config_file,'\0',MAX_PATH);
	strcpy(config_file,DEFAULT_CONFIG_FILE);
	//
	// Clean the whole FE structure
	global_dns_ptr=&dns;
	memset(&dns,'\0',sizeof(DNS_CONFIG));
	//
	// Set FE Defaults, can be overwritten later by config file, but will operate on these if it does not exist
	//
	dns.udp_control_port=5950;
	dns.dns_udp_port=53;
	dns.dns_tcp_port=53;
    dns.verbose=0;
    //
    // Set default data files
    //
    strcpy(dns.zone_file,DEFAULT_ZONE_FILE);
    strcpy(dns.name_file,DEFAULT_NAME_FILE);
    strcpy(dns.fraction_file,DEFAULT_FRACTION_FILE);
    //
    // set the default hash sizes
    //
    dns.zone_size=DNS_DEFAULT_ZONE_SIZE;
    dns.fraction_size=DNS_DEFAULT_FRACTION_SIZE;
    dns.name_size=DNS_DEFAULT_NAME_SIZE;
	//
	// Set update server and filter files
	//
	//default stats updated once every 60 seconds
    //
	strcpy(dns.stats_file,"/tmp/dns_stats.txt");
    dns.stats_interval=DEFAULT_STATISTICS_INTERVAL;

	//
	// Banner
	startup_banner();
	
	// Startup Network
	network_init();
    Yoics_Init_Select();



	//------------------------------------------------------------------
	// Initialize error handling and signals
	//------------------------------------------------------------------
#if defined(WIN32) 
if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler,TRUE)==FALSE)
{
    // unable to install handler... 
    // display message to the user
    yprintf("Error - Unable to install control handler!\n");
    exit(0);
}
#else 
#if !defined(WINCE)
	//	SetConsoleCtrlHandle(termination_handler,TRUE);

	if (signal (SIGINT, termination_handler) == SIG_IGN)
		signal (SIGINT, SIG_IGN);
	if (signal (SIGTERM, termination_handler) == SIG_IGN)
		signal (SIGTERM, SIG_IGN);
	if (signal (SIGILL , termination_handler) == SIG_IGN)
		signal (SIGILL , SIG_IGN);
	if (signal (SIGFPE , termination_handler) == SIG_IGN)
		signal (SIGFPE , SIG_IGN);
	//if (signal (SIGSEGV , termination_handler) == SIG_IGN)
	//	signal (SIGSEGV , SIG_IGN);
#if defined(LINUX) || defined(MACOSX) || defined(IOS)
	if (signal (SIGXCPU , termination_handler) == SIG_IGN)
		signal (SIGXCPU , SIG_IGN);
	if (signal (SIGXFSZ , termination_handler) == SIG_IGN)
		signal (SIGXFSZ , SIG_IGN);
#endif
#endif
#endif

	//
	//
	//
	while ((c = getopt(argc, argv, "f:c:u:t:l:dvh")) != EOF)
	{
    		switch (c) 
			{
    		case 0:
    			break;
    		case 'f':
    		    //config file
				strncpy(config_file,optarg,MAX_PATH-1);
    		    break;
    		case 'l':
    		    //log level
    		    dns.log_level = atoi(optarg);
    		    break;
            case 'c':
    		    //udp Port
    		    dns.udp_control_port = atoi(optarg);
    		    break;
            case 'u':
    		    //udp Port
    		    dns.dns_udp_port = atoi(optarg);
    		    break;
    		case 't':
    		    //Front end port1 (for to listen on 2 ports)
    		    dns.dns_tcp_port = atoi(optarg);
    		    break;
    		case 'd':
				// Startup as daemon with pid file
				printf("Starting up as daemon\n");
				strncpy(dns.pidfile,optarg,MAX_PATH-1);
				//global_flag&GF_DAEMON
                //dns.
                //fe.log_level = atoi(optarg);
    			break;
    		case 'v':
    			dns.verbose=1;
    			break;
    		case 'h':
    			usage (argc,argv);
    			break;
    		default:
    			usage (argc,argv);
				break;
    	}
    }
	argc -= optind;
	argv += optind;
	
	//if (argc != 1)
	//	usage (argc,argv);

	// Read File Config
	if(strlen(config_file))
	{
		if(read_file_config(config_file, &dns))
		{
			if(dns.verbose) printf("Config File Loaded\n");
		}
		else
		{
			if(dns.verbose) printf("Config File Failed to Load\n");
		}
	}


    //
	// Config Hashes, this are optimzied fo up the the counts show, you can do more, but queries may start slowing down
    // Adjust these values up for larger systems.  Must have memory to support the values.
	// 
    dns.names=yhash_init(dns.name_size);               
    dns.fractions=yhash_init(dns.fraction_size);      
    dns.zones=yhash_init(dns.zone_size);              
    

    //
    // Initialize test hashes
    initialize_test_hash(&dns);
    
    // Load the data from the files
    dns_reload_zone(&dns);
    dns_reload_names(&dns);
    dns_reload_fractions(&dns);


	//  config.fe_port = port to run fround end on, should bind to 127 only
	//
	// Bind UD Socket istener
	dns.udp_control_soc=udp_listener(dns.udp_control_port,dns.Bind_IP);

	if(dns.udp_control_soc!=SOCKET_ERROR)
	{
		if(dns.verbose) printf("DNS UDP Bound to %d.%d.%d.%d.%d on socket %d\n",dns.Bind_IP.ipb1,dns.Bind_IP.ipb2,dns.Bind_IP.ipb3,dns.Bind_IP.ipb4,
                                                                                dns.udp_control_port,dns.udp_listen_soc);
        // nonblock on sock
	    set_sock_nonblock(dns.udp_control_soc);
        // Add to select
        Yoics_Set_Select_rx(dns.udp_control_soc);
	}
	else
	{
		if(dns.verbose) printf("Failed to bindt %d, error %d cannot Startup\n",dns.udp_control_port,get_last_error());
		perror("bind\n");
		//get_last_error();
		go=0;
        exit(1);
	}

	// Bind UD Socket Listener (+++ we should crank out buffers on this socket to handle long task switches)
	dns.udp_listen_soc=udp_listener(dns.dns_udp_port,dns.Bind_IP);

	if(dns.udp_listen_soc!=SOCKET_ERROR)
	{
        int r,s,t;
		if(dns.verbose) printf("DNS UDP Bound to %d.%d.%d.%d.%d on socket %d\n",dns.Bind_IP.ipb1,dns.Bind_IP.ipb2,dns.Bind_IP.ipb3,dns.Bind_IP.ipb4,
                                                                                dns.dns_udp_port,dns.udp_listen_soc);

		// open up the send buffer in windows to 1 meg, should be bigger	
		s=1024*256;
		t=setsockopt(dns.udp_listen_soc, SOL_SOCKET, SO_SNDBUF, (char*) &s, sizeof(s));
		DEBUG3("snd buffer increase returnd %d\n",t);
        r=1024*1024;
        t=setsockopt(dns.udp_listen_soc, SOL_SOCKET, SO_RCVBUF, (char*) &r, sizeof(r));
        DEBUG3("rx buffer increase returnd %d\n",t);
        // nonblock on sock
	    set_sock_nonblock(dns.udp_listen_soc);
        // Add to select
        Yoics_Set_Select_rx(dns.udp_listen_soc);
	}
	else
	{
		if(dns.verbose) printf("Failed to bindt %d, error %d cannot Startup\n",dns.dns_udp_port,get_last_error());
		perror("bind\n");
		//get_last_error();
		go=0;
        exit(1);
	}

    // Bind TCP

#if !defined(WIN32)
    //
    // Should Daemonize here
    //
	if(global_flag&GF_DAEMON)
	{
            // Daemonize this
            daemonize(0,0,0,0);

            // Setup logging
			openlog("chat_server",LOG_PID|LOG_CONS,LOG_USER);
			syslog(LOG_INFO,"Yoics DNS Server built "__DATE__ " at " __TIME__ "\n");
			syslog(LOG_INFO,"   Version " VERSION " - (c)2014 Yoics Inc. All Rights Reserved\n");
			syslog(LOG_INFO,"Starting up as daemon\n");
	       
/*
			if(pidfile)
			{
				FILE *fd;
				// pidfile creation specified
				fd=fopen(argv[pidfile],"w");
				if(fd)
				{
					fprintf(fd,"%d",getpid());
					fclose(fd);
					syslog(LOG_INFO,"Creating pidfile %s with PID %d\n",argv[pidfile],getpid());
				}
				else
				{
					syslog(LOG_ERR,"Failed creating pidfile %s with PID %d -errno %d\n",argv[pidfile],getpid(),errno);	
					exit(0);
				}
			}
*/
    }
#endif

	//------------------------------------------------------------------
	// Initialize error handling and signals
	//------------------------------------------------------------------
#if defined(WIN32) 
if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler,TRUE)==FALSE)
{
    // unable to install handler... 
    // display message to the user
    yprintf("!!Error - Unable to install control handler!\n");
    return -1;
}
#else 
	if (signal (SIGINT, termination_handler) == SIG_IGN)
		signal (SIGINT, SIG_IGN);
	if (signal (SIGTERM, termination_handler) == SIG_IGN)
		signal (SIGTERM, SIG_IGN);
	if (signal (SIGILL , termination_handler) == SIG_IGN)
		signal (SIGILL , SIG_IGN);
	if (signal (SIGFPE , termination_handler) == SIG_IGN)
		signal (SIGFPE , SIG_IGN);
	if (signal (SIGSEGV , termination_handler) == SIG_IGN)
		signal (SIGSEGV , SIG_IGN);
	if (signal (SIGXCPU , termination_handler) == SIG_IGN)
		signal (SIGXCPU , SIG_IGN);
	if (signal (SIGXFSZ , termination_handler) == SIG_IGN)
		signal (SIGXFSZ , SIG_IGN);
#endif



    //
	// Main Loop Forever, we should exit on program termination, timeout every 1s if no packet to handle housekeeping
    //
	if(dns.verbose) printf("Starting DNS Server\n");	
	
    go=10;
    while(go)
	{
		// Everything fun happens in rx_packet, this is the server
		dns_rx_packet(&dns);
		//
		// Do Checks and write statistics every 60 seconds, we also check for reload
        // Do not do this to fast on a heavy loaded server with lots of records stored in file,
        // reloads can cost.  Best to use control interface for dynamic server.
		//
		if((second_count()-timestamp)> dns.stats_interval)
		{
			//if(dns.verbose) printf("Try Reload\n");
			timestamp=second_count();	
			//
			// check if we need to reload
			//
            dns_reload_zone(&dns);
            dns_reload_names(&dns);
            dns_reload_fractions(&dns);
			//
			// Write out statistics
			//
			write_statistics(&dns);
			fflush(stdout);	
		}
	}

    // We are out of here, cleanup

    yhash_destroy(dns.names, (void (*)(void *))&dns_name_free);
    yhash_destroy(dns.fractions, (void (*)(void *))&dns_name_free);
    yhash_destroy(dns.zones, (void (*)(void *))&dns_zone_free);

	// Should never exit, but if we do cleanup and print statistics
	if(dns.verbose) printf("Exiting On Go = 0\n");	
	fflush(stdout);	
	
	return(0);
}


