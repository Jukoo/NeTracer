/**  @file main.c 
 *   @brief  us
 *
 */ 

#include <stdlib.h> 
#include <stdio.h> 
#include <err.h> 
#include <pcap/pcap.h>
#include <netinet/in.h>  

#include "net.h" 

int main (int ac , char **av ) 
{

  if (ac == 1)   
    errx(~0 , "<ipv4 address>"); 

  char errbuf[PCAP_ERRBUF_SIZE] ={0} ; 
  pcap_if_t  * netdevs ;
  bpf_u_int32 netip , maskip ; 
  pcap_t  *handler ;


  char *ip = av[ac-1] ; 
  
  if (net_is_valid_ipv4_addr(av[ac-1]) != 0 )   
    errx(~0 , "Not a valid ip address") ; 

 
  int status =   pcap_findalldevs(&netdevs ,errbuf) ;
  
  if (~0 == status){
    errx(PCAP_ERROR , "pcap_findalldevs : %s" , errbuf) ; 
  }
  
  active_inetdevs  *idevices = nullable ;  
  idevices = net_found_active_interface(netdevs , idevices); 
  
  if (!idevices)  
    errx(-1, "No Connected adaptater found") ; 

   list_inetdevs(idevices) ; 
  /* 

  if(PCAP_ERROR == pcap_lookupnet(device , &netip , &maskip , errbuf)) {
    free(device) ; 
    pcap_freealldevs(netdevs) ;
    errx(PCAP_ERROR , "pcap_lookupnet: %s" , errbuf) ; 
  }

   * */
   struct __raw_iproto  rip ; 
   (void *)net_translate(&rip , 2,  netip , maskip) ; 

 
  printf("ipv4 : %s\n",  rip.ipv4) ; 
  printf("net mask : %s\n" , rip.subnet_mask) ; 
  
  //handler = net_stream_on(null ,) ; // if null start on first devices  
  handler =  pcap_open_live(idevices  , BUFSIZ,  0 ,10, errbuf)  ; 
  if (!handler){
    free(idevices) ; 
    pcap_freealldevs(netdevs) ; 
    errx(~0 ,  "pcap_open_live:: %s", errbuf) ; 
  }

  pcap_loop(handler, 0, net_handler , nullable) ; 

  free(idevices) ; 
  pcap_freealldevs(netdevs); 

  
  return 0 ; 
}
