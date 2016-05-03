#ifndef __DNS_H__
#define __DNS_H__
//---------------------------------------------------------------------------
// dns.h - DNS Handler                          							-
//---------------------------------------------------------------------------
// Version                                                                  -
//		0.1 Original Version Dec 1, 2014     							-
//																			-
// (c)2014 Yoics Inc. All Rights Reserved									-
//---------------------------------------------------------------------------

#define DNS_MIN_SIZE 18              /* minimum DNS packet size */
#define DNS_BUFFER_SIZE 2048

#define DNS_CLASS_IN    1
#define DNS_CLASS_CS    2
#define DNS_CLASS_CH    3
#define DNS_CLASS_HS    4

#define DNS_TYPE_A      1
#define DNS_TYPE_NS     2
#define DNS_TYPE_MD     3
#define DNS_TYPE_MF     4
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_SOA    6
#define DNS_TYPE_NULL  10
#define DNS_TYPE_PTR   12
#define DNS_TYPE_MX    15
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28

#define DNS_OP_QUERY    0
#define DNS_OP_IQUERY   1
#define DNS_OP_STATUS   2

#define DNS_NO_REPLY_ERROR      -1          /* do not reply, bad packet                                                     */
#define DNS_NO_ERROR            0
#define DNS_FORMAT_ERROR        1
#define DNS_SERVER_FAIL         2
#define DNS_NAME_ERROR          3           /* A name that should exist does not exist                                      */
#define DNS_NOT_IMPLEMENTED     4           /* DNS server does not support the specified Operation code.                    */
#define DNS_REFUSED             5
#define DNS_NOTAUTH             9           /* 	DNS server is not authoritative for the zone named in the Zone section.     */


int Handle_UDP_DNS(DNS_CONFIG *dns);
int create_fraction(char *fname, char *name);

#endif
