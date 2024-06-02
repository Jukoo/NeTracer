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

#include "netracer.h"  

int  nidevs  = 0 ; 
char  interface_device_name[0x14] = {0}; 

char error_buff[PCAP_ERRBUF_SIZE] = {0} ; 
bint net_is_valid_ipv4_addr(char * restrict ipv4_addr_string)
{
  struct sockaddr_in sa ;  
  bint status = inet_pton(AF_INET , ipv4_addr_string , &(sa.sin_addr))  ;  
  if (status == 1) return  0 ; 
  return ~0;   

}



void net_handler(u_char * user_data  , const struct pcap_pkthdr * pkhdr ,  const u_char * raw_packet_bytes)  
{
  
  fprintf(stdout , "%s:\n" , user_data) ;  
  
  int  pket_len = pkhdr->len ; 
  printf("packet lenght  -> %i \n" , pket_len) ; 
  //printf("size of raw packet bytes %i\n" , strlen(raw_packet_bytes)) ; 
  
  //!Extract  Ethernet Trame from  raw_packet_bytes 
  struct ether_header  *ethn  = (struct ether_header *) raw_packet_bytes ;
 
  uint16_t  eth_type =  ntohs(ethn->ether_type) ;
  if ( (sizeof(*ethn) & 0x0f )  !=  ETHER_HEADER_LEN )  
    fprintf(stderr , "corrupted  raw_packet Byte payload\n"); 


     //!  ETHERTYE_IP ->  ETH_P_IP <linux/if_ether.h> 
  if (eth_type == ETHERTYPE_IP)  {
     //! Extract  IP Datagrame 
     struct iphdr * ip = (struct iphdr *) (raw_packet_bytes   + sizeof(struct ether_header)) ; 

     size_t tram_len = 0  ; 
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
     
     tram_len =  (sizeof(struct  ether_header) + sizeof(struct iphdr)  + sizeof(struct icmphdr)) ; 
     }

     if (pket_len >  tram_len ) 
     {
       printf("payload") ; 
       char * raw_payload =  (char *) raw_packet_bytes  + tram_len  ; 
                puts((char *) raw_packet_bytes + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)));
     }
  }

}


