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


  char errbuf[PCAP_ERRBUF_SIZE] ={0} ; 
  pcap_if_t  * netdevs ;
  bpf_u_int32 netip , maskip ; 
  pcap_t  *handler ;
 
  int status =   pcap_findalldevs(&netdevs ,errbuf) ;
  
  if (~0 == status){
    errx(PCAP_ERROR , "pcap_findalldevs : %s" , errbuf) ; 
  }
  
  active_inetdevs  *idevices = nullable ; 
  idevices = net_found_active_interface(netdevs , idevices); 
  
  if (!idevices)  
    errx(-1, "No Connected adaptater found") ; 

  list_inetdevs(idevices) ; 
  
  char *idevname = net_get_device_name(idevices); 

  idev_info_t  * idevinfo =   nullable ;  
  idevinfo = net_get_idev_info(idevname);  
                                        
  show_idevinfo(idevinfo) ;  
   
  //! ADD filter  here 
  //handler = net_stream_on(null ,) ; // if null start on first devices  
  
  handler =  pcap_open_live(idevname  , BUFSIZ,  0 ,10, errbuf)  ; 
  if (!handler){
    free(idevices) ; 
    pcap_freealldevs(netdevs) ; 
    errx(~0 ,  "pcap_open_live:: %s", errbuf) ; 
  }

  pcap_loop(handler, 0, net_handler , nullable) ; 

  free(idevices) ; 
  pcap_freealldevs(netdevs);  
  pcap_close(handler) ; 
  
  return 0 ; 
}
