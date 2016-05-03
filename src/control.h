#ifndef __CONTROL_H__
#define __CONTROL_H__
//---------------------------------------------------------------------------
// contro.h - DNS server control interface                          							-
//---------------------------------------------------------------------------
// Version                                                                  -
//		0.1 Original Version Dec 1, 2014     							-
//																			-
// (c)2014 Yoics Inc. All Rights Reserved									-
//---------------------------------------------------------------------------

#define CONTROL_BUFFER_MAX 2048

int Handle_UDP_Control(DNS_CONFIG *dns);

char *control_process_message(DNS_CONFIG *dns, int len, char *in_buffer);
char *control_respond_lookup(DNS_RECORD *drec);
char *control_respond_zone_lookup(SOA *zone);
char *control_lookup(DNS_CONFIG *dns,char *name);
char *control_zone_lookup(DNS_CONFIG *dns,char *name);

char *control_get_name(DNS_CONFIG *dns,char *name);
char *control_get_fraction(DNS_CONFIG *dns,char *name);
char *control_get_zone(DNS_CONFIG *dns,char *name);

char *control_statistics_return(DNS_CONFIG *dns);
char *control_statistics_reset(DNS_CONFIG *dns);
#endif
