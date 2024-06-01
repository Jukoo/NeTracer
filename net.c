#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>  
#include <netinet/ip.h>
#include <netinet/in.h> 
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
  int interface_status_check = 0 ; 

  while (raw_net_interface  != nullable){
    
    interface_status_check =  raw_net_interface->flags  & PCAP_IF_CONNECTION_STATUS ; 
    
    if (interface_status_check ==  PCAP_IF_CONNECTION_STATUS_CONNECTED) { 

      struct __active_inet_devices * new_active_inetdev =  (struct __active_inet_devices *) \
                               malloc(sizeof(*new_active_inetdev)); 

      if (! new_active_inetdev)
      {
        return nullable ; 
      }

      new_active_inetdev->idev = strdup(raw_net_interface->name) ;   
      
      inetdevs = append_inetdev(inetdevs ,   new_active_inetdev) ; 

    } //!  endif (interface_status_check == PCAP_IF_CONNECTION_STATUS_CONNECTED)  
    
    raw_net_interface = raw_net_interface->next ;  
  }


  return inetdevs ; 

}

struct __idev_info_t  * 
net_get_idev_info(const char  * restrict   idevname) 
{
   idev_info_t *  idev_info = (idev_info_t *) malloc(sizeof(*idev_info)) ; 
   if (!idev_info) 
     return nullable ; 
  
   bpf_u_int32  netip, subnetip ; 
  
   
   int status = pcap_lookupnet(idevname , &netip , &subnetip ,  error_buff) ; 
   if (PCAP_ERROR == status){ 
     free(idev_info) ; 
     fprintf(stderr , "%s\n" , error_buff) ; 
     return nullable; 
   }

   struct  in_addr  address[2] ; 
 

   int subnetclass =    SUBN_MASK & subnetip  ; 

   address[0].s_addr = netip  ; 
   address[1].s_addr = subnetip ;  
   
   
   //!get  net ip address  
   memcpy(idev_info->ipv4netnum , inet_ntoa( *(address+0) ) , NET_IPV4_LENGTH) ; 
   
   //!get subnet mask 
   memcpy(idev_info->subnet_mask , inet_ntoa( *(address+1) ) , NET_IPV4_LENGTH) ; 

   //!get  net class type 
   idev_info->class_type  =  _GSTRCLS(subnetclass) ; 


   if (!idev_info->ipv4netnum || !idev_info->subnet_mask) 
     fprintf(stderr , "Not  able to fecth  all information about this device %s\n", idevname) ; 

  
   return  idev_info ; 
}




void net_handler(u_char * device , const struct pcap_pkthdr * pkhdr ,  const u_char * raw_packet_bytes)  
{


  printf("size of raw packet bytes %i\n" , strlen(raw_packet_bytes)) ; 
  
  //!Extract  Ethernet Trame from  raw_packet_bytes 
  struct ether_header  *ethn  = (struct ether_header *) raw_packet_bytes ;
 
  uint16_t  eth_type =  ntohs(ethn->ether_type) ;
  if ( (sizeof(*ethn) & 0x0f )  !=  ETHER_HEADER_LEN )  
    fprintf(stderr , "corrupted  raw_packet Byte payload\n"); 

  if ( ETHER_IS_VALID_LEN(sizeof(*ethn)) )  
    puts("valid") ; 
  else  
    puts("no valid") ; 

     printf("sizeof  of header eth packet   %i\n" ,  sizeof(*ethn)) ; 
     //!  ETHERTYE_IP ->  ETH_P_IP <linux/if_ether.h> 
  if (eth_type == ETHERTYPE_IP)  {
     //! Extract  IP Datagrame 
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

struct __active_inet_devices * 
append_inetdev(struct  __active_inet_devices  * idevs , struct __active_inet_devices *  new_inetdev) 
{
  //! hold the previews  
  struct __active_inet_devices * hold  = idevs ;  
  printf("new inet device  %s \n" , new_inetdev->idev) ;
  
  //! permutation 
  idevs =  new_inetdev ; 
  idevs->next  = hold ; 

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


char * net_get_device_name(struct __active_inet_devices  *idevs)  
{
   
  return   (idevs->idev && strlen(idevs->idev) > 0 )  ?  idevs->idev   : nullable  ;  
}

void show_idevinfo(const struct __idev_info_t *  idevinfo) 
{
  if (!idevinfo)return ; 
  fprintf(stdout , "net ip:: %s \n" , idevinfo->ipv4netnum ) ;  
  fprintf(stdout , "subnet mask:: %s \n" , idevinfo->subnet_mask ) ;  
  fprintf(stdout , "class Type :: %s \n" , idevinfo->class_type) ;  
  

}
