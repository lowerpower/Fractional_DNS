/*!																www.yoics.com			
 *---------------------------------------------------------------------------
 *! \file daemonize.c
 *  \brief Function to daemonize a process
 *																			
 *---------------------------------------------------------------------------
 * Version                                                                  -
 *		0.1 Original Version June 3, 2006									-        
 *
 *---------------------------------------------------------------------------    
 * Version                                                                  -
 * 0.1 Original Version August 31, 2006     							    -
 *																			-
 * (c)2006 Yoics Inc. All Rights Reserved									-
 *---------------------------------------------------------------------------
 *
 */
#if !defined(WIN32)             // For unix only

#include <stdio.h>    //printf(3)
#include <stdlib.h>   //exit(3)
#include <unistd.h>   //fork(3), chdir(3), sysconf(3)
#include <signal.h>   //signal(3)
#include <sys/stat.h> //umask(3)
#include <syslog.h>   //syslog(3), openlog(3), closelog(3)
#include "daemonize.h"



/*! \fn int daemonize(name,path,outfile,errorfile,infile)
    \brief Daemonize a process

    \param 

	\return 
*/

int
//daemonize(char* path, char *user, char* outfile, char* errfile, char* infile )
daemonize(char* path, char* outfile, char* errfile, char* infile )
{
    int ret;
    pid_t child;
    int fd;
    struct passwd *pw;

    // Fill in defaults if not specified
    if(!path) { path="/"; }
    if(!infile) { infile="/dev/null"; }
    if(!outfile) { outfile="/dev/null"; }
    if(!errfile) { errfile="/dev/null"; }

/*
    if ((pw = getpwnam(user)) == NULL) {
        fprintf(stderr, "getpwnam(%s) failed: %s\n", user, strerror(errno));
        exit(EXIT_FAILURE);
    }
*/
    //fork, detach from process group leader
    if( (child=fork())<0 ) { //failed fork
        fprintf(stderr,"error: failed fork 1\n");
        exit(EXIT_FAILURE);
    }
    if (child>0) { //parent
        _exit(EXIT_SUCCESS);
    }
    if( setsid()<0 ) { //failed to become session leader
        fprintf(stderr,"error: failed setsid\n");
        exit(EXIT_FAILURE);
    }

    //catch/ignore signals
    signal(SIGCHLD,SIG_IGN);
    signal(SIGHUP,SIG_IGN);

    //fork second time
    if ( (child=fork())<0) { //failed fork
        fprintf(stderr,"error: failed fork 2\n");
        exit(EXIT_FAILURE);
    }
    if( child>0 ) { //parent
        _exit(EXIT_SUCCESS);
    }

    //Close all open file descriptors
    for( fd=sysconf(_SC_OPEN_MAX); fd>0; --fd )
    {
        close(fd);
    }

    //reopen stdin, stdout, stderr
    stdin=fopen(infile,"r");   //fd=0
    stdout=fopen(outfile,"w+");  //fd=1
    stderr=fopen(errfile,"w+");  //fd=2

    //new file permissions
    umask(0);
    //change to path directory
    ret=chdir(path);

/*
     if (chroot(dir) < 0) 
     {
        syslog(LOG_ERR, "chroot(%s) failed: %s\n",
        dir, strerror(errno));
        exit(EXIT_FAILURE);
     }

     if (setgroups(1, &pw->pw_gid) < 0) 
     {
        syslog(LOG_ERR, "setgroups() failed: %s\n",
        strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (setgid(pw->pw_gid)) 
    {
        syslog(LOG_ERR, "setgid %i (user=%s) failed: %s\n",
        pw->pw_gid, user, strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (setuid(pw->pw_uid)) 
    {
        syslog(LOG_ERR, "setuid %i (user=%s) failed: %s\n",
        pw->pw_uid, user, strerror(errno));
        exit(EXIT_FAILURE);
    }
*/

    ret=1;
    return(ret);
}

#endif
