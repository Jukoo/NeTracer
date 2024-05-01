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

struct __active_inet_devices * 
net_found_active_interface(pcap_if_t  * raw_net_interface , struct __active_inet_devices * inetdevs)   
{
  
  while (raw_net_interface  != nullable){
    
    int  interface_status_check =  raw_net_interface->flags  & PCAP_IF_CONNECTION_STATUS ; 
    
    if (interface_status_check ==  PCAP_IF_CONNECTION_STATUS_CONNECTED) { 
      char *connected_inetdev = raw_net_interface->name ;
      bpf_u_int32 netp  , maskp ; 
      //! check  if the device has ipv4 address   
      int status =  pcap_lookupnet (connected_inetdev  ,  &netp , &maskp ,  error_buff) ;
      
      if  (PCAP_ERROR ==  status) {
        raw_net_interface = raw_net_interface->next ; 
        continue ; 
      }

      struct __active_inet_devices * new_active_inetdev =  (struct __active_inet_devices *) \
                               malloc(sizeof(*new_active_inetdev)); 

      if (! new_active_inetdev)
      {
        return nullable ; 
      }

      new_active_inetdev->idev = strdup(connected_inetdev) ;  
      
      inetdevs = append_inetdev(inetdevs ,   new_active_inetdev) ; 
    } 
    
    raw_net_interface = raw_net_interface->next ;  
  }


  return inetdevs ; 

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

struct __active_inet_devices * append_inetdev(struct  __active_inet_devices  * idevs , struct __active_inet_devices *  new_inetdev) 
{ 
  struct __active_inet_devices * hold  = idevs ; //new_inetdev;  
  printf("new inet device  %s \n" , new_inetdev->idev) ; 
  idevs =  new_inetdev ; 
  idevs->next  = hold ; 
  // new_inetdev->next = idevs   ; 

  return idevs  ;   
}

void list_inetdevs (const struct __active_inet_devices  * inetdevs) 
{ 
  struct __active_inet_devices * inetdevs_hold= (struct __active_inet_devices *) inetdevs ;   
  
  while (inetdevs_hold != nullable) 
  {
    printf("-> %s\n" , inetdevs_hold->idev) ; 
    inetdevs_hold =  inetdevs_hold->next ; 
  }
}
