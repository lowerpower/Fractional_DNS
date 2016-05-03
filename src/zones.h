#ifndef __ZONES_H__
#define __ZONES_H__
//---------------------------------------------------------------------------
// zones.h - zone stuff                         							-
//---------------------------------------------------------------------------
// Version                                                                  -
//		0.1 Original Version Dec 1, 2014     							-
//																			-
// (c)2014 Yoics Inc. All Rights Reserved									-
//---------------------------------------------------------------------------



void dns_zone_free(SOA *record);
int  dns_load_zones(DNS_CONFIG *dns);
int  dns_reload_zone(DNS_CONFIG *dns);
SOA* dns_lookup_zone(DNS_CONFIG *dns, char *name);


#endif
