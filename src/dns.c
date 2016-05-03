/*!										
 *---------------------------------------------------------------------------
 *! \file dns.c
 *  \brief Core DNS handler
 *
 *  Process DNS requests here.
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


typedef struct dns_paket_
{
	U16 transaction_id;
    U16 flags;
    U16 questions;
    U16 answers;
    U16 autority;
    U16 Additional;
    U8  data[];
}DNS_PKT;

typedef struct dns_request_
{
	char    in_buffer[2048];
    char    out_buffer[2048];
    int     in_buffer_len;
    IPADDR  in_ip;
    // Reply section
    int     out_buffer_len;
    int     rcode;                      /* -1 do not reply, >=0 retoply */ 
    int     answers;
    int     authority;
}DNS_REQ;


int
parse_question(char *name, U16 *type, U16 *dns_class, unsigned char *in_data, int max_len)
{
    int             end=0,count=0,len,i;
    unsigned char   *ptr;
    unsigned int    max=max_len;

    ptr=(unsigned char *)in_data;

    while(*ptr)
    {
        if(max <= *ptr)
        {
            end=-1;
            break;
        }
        // Store then skip the count
        len=*ptr++;
        for(i=0;i<len;i++)
            name[count++]=*ptr++;
        // Store a dot, if not null
        if(*ptr)
            name[count++]='.';
    }

    if(0==end)
    {
        U16 t,t1;
        // Zero Term the last .
        name[count]=*ptr++;
         t = ((*ptr++) << 8) ;
         t1= (*ptr++);
        *type       = t | t1;
         t = ((*ptr++) << 8) ;
         t1= (*ptr++);
        *dns_class  = t | t1;
        end=ptr-in_data;
    }
    return(end);
}



int
create_fraction(char *fname, char *name)
{
    int ret=0;
    int sub_count=2;
    int count=strlen(name);

    // Find 4 past 3rd dot back
    while(count>=0)
    {
        if('.'==name[count--])
        {
            sub_count--;
            if(sub_count <= 0)
                break;
        }
    }

    if(0==sub_count)
    {
        if((count-3)>=0)
        {
            strcpy(fname,&name[count-3]);
            ret=1;
        }
    }
    return(ret);
}



void
push_int32(DNS_REQ *dns_req,U32 int32)
{
    dns_req->out_buffer[dns_req->out_buffer_len++]=((int32>>24)&0xff);
    dns_req->out_buffer[dns_req->out_buffer_len++]=((int32>>16)&0xff);
    dns_req->out_buffer[dns_req->out_buffer_len++]=((int32>>8)&0xff);
    dns_req->out_buffer[dns_req->out_buffer_len++]=(int32&0xff);
}

//
// Need to zero terminate after this if it is the end or not compressed label
//
void
push_lable(DNS_REQ *dns_req,char *lable)
{
    size_t i;

    // 
    for(i=0;i<strlen(lable);i++)
    {
        dns_req->out_buffer[dns_req->out_buffer_len++]=lable[i];
    }
}


//
// Need to zero terminate after this if it is the end
//
void
push_sub_string(DNS_REQ *dns_req,char *string)
{
    char *ptr,*tptr;

    // Push Len First    
    ptr=string;
    while(*ptr)
    {
        tptr=ptr;
        while((*tptr!='.') && (0!=*tptr))
            tptr++;
        dns_req->out_buffer[dns_req->out_buffer_len++]=(tptr-ptr);
        while(tptr!=ptr)
            dns_req->out_buffer[dns_req->out_buffer_len++]=*ptr++;
        while('.'==*ptr)
            ptr++;
    }
    // zero term, do this later
    // dns_req->out_buffer[dns_req->out_buffer_len++]=0;
}


//
// Make a DNS lable out of a string, IE abc.defg.com = 3abc4defg3com0
//
// Must free object when done with it
//
char*
make_lable(char *string)
{
    int len,count=0;
    char *ptr,*tptr;
    char *lable;

    if(0==string)
        return(0);

    len=strlen(string);
    if(0==len)
        return(0);

    lable=malloc((len*2)+1);         //malloc 2x the input string, worse case x.x.x
    if(lable)
    {
        ptr=string;
        while(*ptr)
        {
            tptr=ptr;
            // Find length of next object
            while((*tptr!='.') && (0!=*tptr))
                tptr++;
            // Send Length
            lable[count++]=(tptr-ptr);
            while(tptr!=ptr)
                lable[count++]=*ptr++;
            // Kill dot and multidots
            while('.'==*ptr)
                ptr++;
        }
        lable[count++]=0;
    }
    return(lable);
}

//
// String must be in dns label format, zero terminated, compression happens in the lable
//
int
compress_label(DNS_REQ *dns_req,char *dns_lable)
{
    int len;
    U16 offset=0;
    char *ptr,*tptr;
    int compressed=0;

    if(0==dns_lable)
        return(0);
    len=strlen(dns_lable);

    if(0==len)
        return(0);
    
    ptr=dns_lable;
    while(ptr)
    {
        tptr=memcasemem(dns_req->in_buffer,dns_req->in_buffer_len,ptr,strlen(ptr));
        if(tptr)
        {
            // Match, fixup string return, tptr point to offset
            offset=(U16)(tptr-dns_req->in_buffer);
            // Set offset
            *ptr++=(0xc0 | ((offset>>8)&0xff));
            *ptr++=(offset & 0xff);
            *ptr=0; 
            compressed=1;
            break;
        }
        else
        {
            // skip until next sub, ptr should point to length of following sub, we add 1 to skip self
            ptr=ptr+(*ptr+1);
            // protection
            if((size_t)(ptr-dns_lable)>strlen(dns_lable))
                break;
        }
    }
    return(compressed);
}

//
// Push a string to reply, try to compress with zone.
//
void
push_string(DNS_REQ *dns_req, char *push_string)
{
    char            *label;

    // Make a lable out of the string
    label=make_lable(push_string);
    // Compress it
    if(label)
        {
        if(compress_label(dns_req,label))
        {
            // Store it, we don't terminate compressed labels
            push_lable(dns_req,label);
        }
        else
        {
            // store it uncompressed (must termiate it)
            push_lable(dns_req,label);
            dns_req->out_buffer[dns_req->out_buffer_len++]=0;
        }
    }
    if(label) free(label);
}


//
// For now build answer only supports on reply of an IP address, we would want to itterate throught a list if there is more than
//  one reply.
//
int
build_answer (DNS_REQ *dns_req,DNS_RECORD *drec)
{
    // Offset to the domain name in request, always the same 0xC0, 0X0C

    dns_req->out_buffer[dns_req->out_buffer_len++]=0xC0;
    dns_req->out_buffer[dns_req->out_buffer_len++]=0x0C;
    // Type
    dns_req->out_buffer[dns_req->out_buffer_len++]=((drec->type >> 8)&0xff);
    dns_req->out_buffer[dns_req->out_buffer_len++]=(drec->type & 0xff);
    // Class, fixed we only support internet 0x00, 0x01
    dns_req->out_buffer[dns_req->out_buffer_len++]=0x00;
    dns_req->out_buffer[dns_req->out_buffer_len++]=0x01;
    // TTL    
    push_int32(dns_req,drec->ttl);
    //
    if(DNS_TYPE_A ==drec->type)
    {
        dns_req->out_buffer[dns_req->out_buffer_len++]=0x00;
        dns_req->out_buffer[dns_req->out_buffer_len++]=0x04;
        // Last Put IP address
        dns_req->out_buffer[dns_req->out_buffer_len++]=drec->ip.ipb1;
        dns_req->out_buffer[dns_req->out_buffer_len++]=drec->ip.ipb2;
        dns_req->out_buffer[dns_req->out_buffer_len++]=drec->ip.ipb3;
        dns_req->out_buffer[dns_req->out_buffer_len++]=drec->ip.ipb4;
    }
    else if(DNS_TYPE_CNAME ==drec->type)
    {
        int len,tlen;
        len=tlen=dns_req->out_buffer_len;
        dns_req->out_buffer_len+=2;

        push_string(dns_req,drec->value);

        len=(dns_req->out_buffer_len-tlen)-2;

        dns_req->out_buffer[tlen++]=(len>>8)&0xff;
        dns_req->out_buffer[tlen]=len&0xff;
    }

    dns_req->answers++;
 
    return(0);
}

// Must be called in the right order
int
build_soa(DNS_REQ *dns_req,SOA *soa)
{
    int     data_len,i;

    // soa name
    push_string(dns_req, soa->zone);
    // Type
    dns_req->out_buffer[dns_req->out_buffer_len++]=((DNS_TYPE_SOA >> 8)&0xff);
    dns_req->out_buffer[dns_req->out_buffer_len++]=(DNS_TYPE_SOA & 0xff);
    // Class, fixed we only support internet 0x00, 0x01
    dns_req->out_buffer[dns_req->out_buffer_len++]=0x00;
    dns_req->out_buffer[dns_req->out_buffer_len++]=0x01;
    // TTL
    push_int32(dns_req,soa->ttl);
    
    // Save Data Pointer
    data_len=dns_req->out_buffer_len;
    // Skip it for now
    dns_req->out_buffer_len+=2;
    
    // Push primary NS
    push_string(dns_req,soa->server);
    // Push Email
    push_string(dns_req,soa->email);

    // Serial number
    push_int32(dns_req,soa->serial);
    // Refresh
    push_int32(dns_req,soa->refresh);
    // Retry
    push_int32(dns_req,soa->retry);
    // expire
    push_int32(dns_req,soa->expire);
    // min ttl
    push_int32(dns_req,soa->ttl);

    // fixup len data_len
    i=(dns_req->out_buffer_len-data_len) -2;
    dns_req->out_buffer[data_len++]=((i >> 8)&0xff);
    dns_req->out_buffer[data_len++]=(i&0xff); 

    return(0);
}

// Must be called in the right order
int
build_soa_dns(DNS_REQ *dns_req,DNS_SERVER *dns, char *zone)
{
    int     data_len,i;

    // soa name
    push_string(dns_req, zone);
    // Type
    dns_req->out_buffer[dns_req->out_buffer_len++]=((DNS_TYPE_NS>> 8)&0xff);
    dns_req->out_buffer[dns_req->out_buffer_len++]=(DNS_TYPE_NS & 0xff);
    // Class, fixed we only support internet 0x00, 0x01
    dns_req->out_buffer[dns_req->out_buffer_len++]=0x00;
    dns_req->out_buffer[dns_req->out_buffer_len++]=0x01;
    // TTL
    push_int32(dns_req,dns->ttl);
    
    // Save Data Pointer
    data_len=dns_req->out_buffer_len;
    // Skip it for now
    dns_req->out_buffer_len+=2;
    
    // Push primary NS
    push_string(dns_req,dns->name);

    // fixup len data_len
    i=(dns_req->out_buffer_len-data_len) -2;
    dns_req->out_buffer[data_len++]=((i >> 8)&0xff);
    dns_req->out_buffer[data_len++]=(i&0xff); 

    return(0);
}




int
//process_dns_message(DNS_CONFIG *dns, unsigned char* in_buffer, int in_buffer_len, char *out_buffer)
process_dns_message(DNS_CONFIG *dns, DNS_REQ *dns_req)
{   
    DNS_PKT *dns_pkt,*dns_pkt_out;
    int     query,end;
    int     recursion;
    int     authority_flag=0;
    U16     type,flags,dns_class;
    SOA     *zone=0;
    char    name[2048];
    char    fname[2048];

    dns_pkt=(DNS_PKT *)dns_req->in_buffer;
    dns_pkt_out=(DNS_PKT *)dns_req->out_buffer;
    dns_req->out_buffer_len=dns_req->in_buffer_len;

    query       = (0x0080 & dns_pkt->flags); 
    //query_type  = (0x0078 & dns_pkt->flags)>>3;
    //truncated   = (0x0002 & dns_pkt->flags);
    recursion   = (0x0001 & dns_pkt->flags);

    DEBUG3("Packet into process_dns_message\n");
    //
    //
    //
    if((htons(dns_pkt->questions)!=1) || (query))
    {
        // We ignore questions not of 1 or not a query
        dns->unknown_packets++;
        dns_req->rcode=DNS_NO_REPLY_ERROR; 
        return(-1);
    }
    //
    // Copy over original packet to reply
    // 
    memcpy(dns_req->out_buffer,dns_req->in_buffer,dns_req->in_buffer_len);

    dns->requests++;
        
    // Parse the question, we only handle one here
    if(0<(end=parse_question(name,&type,&dns_class,dns_pkt->data,(dns_req->in_buffer_len-sizeof(DNS_PKT)))) )
    {
        // store end of question
        dns_req->out_buffer_len=end+12;
        // dns is case insensitive, convert to lower case
        strtolower(name);
        // Check the zone
        zone=dns_lookup_zone(dns,name);
        if(zone)
            authority_flag=1;
        // We only handle  Internet Class and Address query types

        if(dns->verbose) printf("Looking up %s of type %d for %d:%d:%d:%d, we are auth %d\n",name,type,dns_req->in_ip.ipb1,
                                dns_req->in_ip.ipb2,dns_req->in_ip.ipb3,dns_req->in_ip.ipb4,authority_flag);

        if(DNS_CLASS_IN==dns_class)
        {
            switch(type)
            {
            case DNS_TYPE_NS:
                if(zone)
                {
                    dns_req->rcode=DNS_NO_ERROR;
                    //build_soa(dns_req,zone);
                    //dns_req->answers=1;
                    if(0==strcmp(zone->zone,name))
                    {
                        DNS_SERVER *dptr;

                        if(dns->verbose) printf("request is zone print out nameservers\n");
                        dptr=zone->dns_servers; // dns_req->answers=1;
                        while(dptr)
                        {
                            // build answer for each dns server
                            build_soa_dns(dns_req,dptr, zone->zone);
                            dns_req->answers++;
                            dptr=dptr->next;
                        }
                    }
                    else
                    {
                        build_soa(dns_req,zone);
                        dns_req->authority=1;
                        //dns_req->answers=1;
                    }
                }
                else
                    dns_req->rcode=DNS_REFUSED;
                break;
            case DNS_TYPE_SOA:
                if(zone)
                {
                    dns_req->rcode=DNS_NO_ERROR;
                    //dns_req->authority=1;
                    //build_answer(dns, dns_req, drec);    
                    build_soa(dns_req,zone);
                    dns_req->answers=1;
                }
                else
                    dns_req->rcode=DNS_REFUSED;
                break;
            case DNS_TYPE_A:
            case DNS_TYPE_CNAME:
            case DNS_TYPE_AAAA:
            //case DNS_TYPE_NS:
                // Lookup Name
                if(strlen(name))
                {
                    DNS_RECORD *drec;
                    // First look for exact match
                    drec=(DNS_RECORD*)yhash_lookup_string(dns->names, name);
                    if(drec)
                    {
                        dns->direct_hits++;                
                        if(DNS_TYPE_A==drec->type)
                        {
                            if(dns->verbose) printf("name %s found IP %d.%d.%d.%d\n",name,drec->ip.ipb1,drec->ip.ipb2,drec->ip.ipb3,drec->ip.ipb4);
                        }else if(DNS_TYPE_CNAME==drec->type) {
                            if(dns->verbose) printf("name %s reqtype %d found CNAME %s\n",name,type,drec->value);
                        }else if(DNS_TYPE_AAAA==type) {
                            if(dns->verbose) printf("name %s found type %d but req was AAAA (no sup for now)\n",name,drec->type);
                        }

                        dns_req->rcode=DNS_NO_ERROR; 

                       // If no AAAA record found, but other records on that name exist, return no error, but no anwer http://www.ietf.org/rfc/rfc4074.txt
                        if(DNS_TYPE_AAAA!=type) 
                        {
                            if(dns->verbose) printf("build response\n");
                            build_answer(dns_req, drec);      
                        }
                    }
                    else
                    {
                        // Try Fractional, first fixup nam
                        if(create_fraction(fname,name))
                        {
                            drec=(DNS_RECORD*)yhash_lookup_string(dns->fractions, fname);
                            if(drec)
                            {
                                dns->fractional_hits++;
                                dns_req->rcode=DNS_NO_ERROR; 
                                
                                // If no AAAA record found, but other records on that name exist, return no error, but no anwer http://www.ietf.org/rfc/rfc4074.txt
                                if(DNS_TYPE_AAAA!=type)
                                {
                                    if(dns->verbose) printf("build fractional response\n");
                                    build_answer(dns_req, drec);  
                                }
                            }
                            else
                            {
                                if(dns->verbose) printf("Fractional name %s not found\n",fname);
                                // Should return 0x03 for zone names, 0x05 for all others (REFUSED)
                                dns->nomatch_hits++;
                                dns_req->rcode=DNS_NAME_ERROR; 
                            }
                        }
                        else
                        {
                            dns->nomatch_hits++;
                            dns_req->rcode=DNS_NAME_ERROR; 
                        }
                    }
                }
                else
                {
                    dns_req->rcode=DNS_FORMAT_ERROR;
                }
                break;
            default:
                if(dns->verbose) printf("Type %d not implemented\n",type);
                dns_req->rcode=DNS_NOT_IMPLEMENTED;
                break;
            }//switch
        }
        else
        {
            //if(DNS_CLASS_IN!=dns_class)
            dns_req->rcode=DNS_NOT_IMPLEMENTED;
        }
    }   
    else
    {
        dns_req->rcode=DNS_FORMAT_ERROR;
    }

    if((zone) && (DNS_NAME_ERROR==dns_req->rcode)) 
    {
        // We are autority
        dns_req->authority=1;
        build_soa(dns_req,zone);
    }

    // Finish Fixup
    // Stuff answers
    dns_pkt_out->answers=htons(dns_req->answers);
    // Stuff Autority
    dns_pkt_out->autority=htons(dns_req->authority);
    dns_pkt_out->Additional=0;//

    // Fixup Flags, we have no recursion     recursion   = (0x0001 & dns_pkt->flags);
    flags=0;
    flags|=0x0080;                      // response
    flags|=(dns_req->rcode&0xf)<<8;     // rcode
    if(recursion)
        flags|=0x0001;                  // Set recursion requested
    if(authority_flag)
        flags|=0x0004;

    dns_pkt_out->flags=flags;

    return(0);
}




//
// All UDP DNS traffic is handled here
//
int
Handle_UDP_DNS(DNS_CONFIG *dns)
{
    int ret,slen;
	struct sockaddr_in	server;				/* Information about the server */
    IPADDR  tip;
    DNS_REQ dns_req;

    //
    // Receive the packet
    //
    memset(&dns_req,'\0',sizeof(DNS_REQ));
    memset(&server,'\0',sizeof(struct sockaddr));
    slen=sizeof(struct sockaddr_in);
    ret=recvfrom(dns->udp_listen_soc, dns_req.in_buffer, DNS_BUFFER_SIZE, 0, (struct sockaddr *)&server, (socklen_t *) &slen);

    if(ret>0)
    {
        DEBUG3("Pkt In len %d \n",ret);
        dns_req.in_buffer_len=ret;
        dns->rx_packets++;

        // DNS requests must be of minimum size
        if(ret< DNS_MIN_SIZE)
        {
            DEBUG3("Dropped because of runt \n");
            dns->runt_packets++;
            return(-1);
        }
        //
        // Check dest IP address, if broadcast.
        tip.ip32=server.sin_addr.s_addr;
        if(255==tip.ipb4)
        {
            DEBUG3("Dropped because of broadcast \n");
            dns->rx_broadcast_packets++;
            return(-1);
        }
        // Store source IP for logging
        dns_req.in_ip.ip32=tip.ip32;

        process_dns_message(dns,&dns_req);

        if(dns_req.rcode>=0)
        {
             dns->udp_requests++;
            // Send Reply
            ret=sendto(dns->udp_listen_soc, dns_req.out_buffer, dns_req.out_buffer_len, 0, (struct sockaddr *)&server, sizeof(struct sockaddr));
            if(ret>0)
            {
                dns->tx_packets++;
            }
            else if(ret<0)
            {
                dns->tx_errors++;
            }
        }
    }
	else if(SOCKET_ERROR==ret)
	{
		ret=get_last_error();
		if(ret!=EWOULDBLOCK)
        {
            dns->rx_errors++;
			DEBUG3("Error %d on main read\n",ret);
        }
        else
        {
            DEBUG3("Would Block\n");
        }
    }
    return(0);
}

