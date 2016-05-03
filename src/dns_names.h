#ifndef __DNS_NAMES_H__
#define __DNS_NAMES_H__
//---------------------------------------------------------------------------
// zones.h - zone stuff                         							-
//---------------------------------------------------------------------------
// Version                                                                  -
//		0.1 Original Version Dec 1, 2014     							-
//																			-
// (c)2014 Yoics Inc. All Rights Reserved									-
//---------------------------------------------------------------------------

// For now fraction size is 4, but could be anything in the future.
#define FRACTION_SIZE   4

void dns_name_free(DNS_RECORD *record);
int  dns_load_names(DNS_CONFIG *dns);
int  dns_reload_names(DNS_CONFIG *dns);

int dns_load_fractions(DNS_CONFIG *dns);
int dns_reload_fractions(DNS_CONFIG *dns);

#endif

