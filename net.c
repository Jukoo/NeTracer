#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>  
#include <netinet/ip.h>
#include <netinet/ip_icmp.h> 
#include <pcap/pcap.h> 
#include <string.h> 
#include <stdarg.h>
#include <net/ethernet.h> 
#include <fmtmsg.h> 
#include <assert.h> 

#include "net.h"

char error_buff[PCAP_ERRBUF_SIZE] = {0} ; 
bint net_is_valid_ipv4_addr(char * restrict ipv4_addr_string)
{
  SADDR_IN sa ;  
  bint status = inet_pton(AF_INET , ipv4_addr_string , &(sa.sin_addr))  ;  
  if (status == 1) return  0 ; 
  return ~0;   

}

struct __active_idev_lists * 
net_found_active_interface(pcap_if_t  * raw_net_interface , struct __active_idev_lists * idev)   
{

  struct  _idev  * c  ;  
  while (raw_net_interface  != nullable){
    
    int  interface_status_check =  raw_net_interface->flags  & PCAP_IF_CONNECTION_STATUS ; 
    
    if (interface_status_check ==  PCAP_IF_CONNECTION_STATUS_CONNECTED) { 
      char *connected_idev = raw_net_interface->name ; 
      ///active_idev = strdup(raw_net_interface->name) ; 
      char *phylayer_protobuff = (char *)  raw_net_interface->addresses->addr ; 
      struct sockaddr_in *in =  (struct sockaddr_in *) phylayer_protobuff  ; 
      bpf_u_int32 netp  , maskp ; 
      int status =  pcap_lookupnet (connected_idev  ,  &netp , &maskp ,  error_buff) ; 
      if  (PCAP_ERROR ==  status) {
        raw_net_interface = raw_net_interface->next ; 
        continue ; 
      }
      
      struct __active_idev_lists * new_active_idevs =  (struct __active_idev_lists *) \
                               malloc(sizeof(*new_active_idevs)); 
      if (! new_active_idevs) 
        return nullable ; 

      memcpy(new_active_idevs->idev ,  connected_idev , strlen(connected_idev)) ;  
      new_active_idevs->next = nullable ; 
    }   

    
    raw_net_interface = raw_net_interface->next ;  
    idev = 
  }


  return idev ; 

}


struct __raw_iproto *  net_translate( struct __raw_iproto  * rip  ,int index ,  ... )
{ 

  struct in_addr *address =  (struct in_addr *) malloc(sizeof(struct in_addr) * index) ; 
  if (!address)  
    return nullable ; 

  bpf_u_int32 ip ; 

  va_list ap ; 
  va_start(ap , index) ; 

  int i = 0 ; 
  while (  i <  index ) { 
    ip= va_arg(ap ,  bpf_u_int32) ;
    address[i].s_addr = ip  ; 
    if (i == 0){
      memcpy(rip->ipv4 , inet_ntoa(address[i]) ,NET_IPV4_LENGTH) ; 
    } 
    if (i == 1) {
      memcpy(rip->subnet_mask  , inet_ntoa(address[i]) , NET_IPV4_LENGTH) ; 
    } 
    explicit_bzero((char*) address ,  sizeof(struct in_addr ) * index) ; 
    i++ ; 
  }
   
  va_end(ap) ; 
  free(address) ; 
  return rip ; 
}



void net_handler(u_char * device , const struct pcap_pkthdr * pkhdr ,  const u_char * raw_packet_bytes)  
{
 
  printf("size of raw packet bytes %i\n" , strlen(raw_packet_bytes)) ; 
 
  struct ether_header  *ethn  = (struct ether_header *) raw_packet_bytes ;
  
  uint16_t  eth_type =  ntohs(ethn->ether_type) ;
  if (eth_type == ETHERTYPE_IP)  {
     struct iphdr * ip = (struct iphdr *) (raw_packet_bytes   + sizeof(struct ether_header)) ; 
     char s[10] ={0} ; 
     sprintf(s ,"::%i\n",   ip->protocol) ;
     
     if  (ip->protocol ==  IPPROTO_ICMP){ 
       struct   icmphdr *icmp  = (struct icmphdr *)  (raw_packet_bytes + sizeof(struct ether_header) + sizeof(struct iphdr)) ; 
       switch(icmp->type){
         case ICMP_ECHO : 
           
           fmtmsg(MM_CONSOLE | MM_PRINT, "icmp::echo_request", MM_INFO , nullable ,  nullable ,nullable) ; 
           break ; 
         case ICMP_ECHOREPLY: 
           fmtmsg(MM_CONSOLE | MM_PRINT, "icmp::echo_reply", MM_INFO , nullable ,  nullable ,nullable) ; 
           break; 
         default: 
           fmtmsg(MM_CONSOLE | MM_PRINT, "icmp::unknow", MM_WARNING , nullable ,  nullable ,nullable) ; 
           break ; 
       }
     }
  }

  
}
