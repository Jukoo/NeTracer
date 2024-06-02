/**  @file main.c 
 *   @brief  us
 *
 */ 

#include <stdlib.h> 
#include <stdio.h> 
#include <err.h> 
#include <pcap/pcap.h>
#include <netinet/in.h>  


#include "netracer.h" 
#include "ifnetdevs_manip.h" 
int main (int ac , char **av ) 
{


  char errbuf[PCAP_ERRBUF_SIZE] ={0} ; 
  pcap_if_t  * netdevs ;
  bpf_u_int32 netip , maskip ; 
  struct  bpf_program  fp ; 
  pcap_t  *handler ;
 
  int status =   pcap_findalldevs(&netdevs ,errbuf) ;
  
  if (~0 == status){
    errx(PCAP_ERROR , "pcap_findalldevs : %s" , errbuf) ; 
  }
  
  active_inet_devices   *idevices = nullable ; 
  idevices =  fetch_active_netdev_interface(netdevs , idevices); 


  if (!idevices)  
    errx(-1, "No Connected adaptater found") ; 

  list_active_interface(idevices ,  (void *) 0 ) ; 
  //list_idevs(idevices) ; 
  
  char *idevname  = get_default_interface(idevices) ;   

  
  inet_device_info   * idevinfo =   nullable ;  
  idevinfo = get_interface_info(idevname); 
                                        
  show_idevinfo(idevinfo) ;  
   

  handler =  pcap_open_live(idevname  , BUFSIZ,  0 ,10, errbuf)  ; 
  if (!handler){
    free(idevices) ; 
    pcap_freealldevs(netdevs) ; 
    errx(~0 ,  "pcap_open_live:: %s", errbuf) ; 
  }
 //! ADD filter  here 
  char filter_exp[]= "icmp" ;  

  int  rc=   pcap_compile(handler , &fp ,  filter_exp, 0 ,    netip) ;   
  if (PCAP_ERROR == rc ) { 
     
    errx(~0 , "pcap_compile issue  %s \n" ,  pcap_geterr(handler)) ; 
  } 

  if (PCAP_ERROR == pcap_setfilter(handler , &fp))  
    errx(~0 , "pcap_setfilter error") ; 


 pcap_loop(handler, 0, net_handler ,   filter_exp) ; 

  free(idevices) ; 
  pcap_freealldevs(netdevs);  
  pcap_close(handler) ; 
  
  return 0 ; 
}
