#include <stdlib.h> 
#include <stdio.h> 
#include <string.h> 
#include <pcap/pcap.h> 
#include <arpa/inet.h> 

#include "ifnetdevs_manip.h" 

bpf_u_int32  netip, subnetip ; 
char error_buffer[PCAP_ERRBUF_SIZE] ={0} ; 

struct __active_inet_devices * 
fetch_active_netdev_interface(pcap_if_t * raw_netdevs , active_inet_devices  * indevs) 
{
  int incoming_if_status_check = 0;  
  while (raw_netdevs !=  NULL){
    incoming_if_status_check = raw_netdevs->flags & PCAP_IF_CONNECTION_STATUS ; 
    if ( incoming_if_status_check == PCAP_IF_CONNECTION_STATUS_CONNECTED) {
      struct __active_inet_devices * new_indev  = (struct __active_inet_devices *)\
                                                   malloc(sizeof(*new_indev)) ; 
      if (!new_indev)  
        return NULL  ; 
    
      memcpy(new_indev->idevname , raw_netdevs->name , strlen(raw_netdevs->name));
      char *ipv4addr = get_interface_ipv4(raw_netdevs->addresses) ;
      if (ipv4addr!= nullable) 
        memcpy(new_indev->ipv4_address , ipv4addr , strlen(ipv4addr)) ; 

      printf("ip address %s\n" , new_indev->ipv4_address) ; 
      indevs = register_inetdev(indevs , new_indev) ; 
    } 

    raw_netdevs = raw_netdevs->next ; 

  }

  return indevs ; 
}

static char *  get_interface_ipv4 ( struct pcap_addr * addr_resolution ) 
{
  while (addr_resolution  != nullable) {
    struct sockaddr  *sa = addr_resolution->addr ; 
    if (sa->sa_family == PF_INET)  {
      return inet_ntoa(  ((struct sockaddr_in *)sa)->sin_addr); 
    }
    addr_resolution = addr_resolution->next ; 
  }
  return nullable; 
}

static struct __active_inet_devices * 
register_inetdev(active_inet_devices  * idevs_nodelist ,   active_inet_devices  * new_idev_node) 
{
  /*   *[idevs]-> NULL 
   *  [new_idev_node] 
   *      |
   *      v
   *  [new_idev_node] -> [*idevs] -> NULL 
   *        |                 |
   *        ----------v       | 
   *       -----------)--------
   *       |          ------|
   *       v                v
   * *[new_idev_node] -> [idevs] -> NULL 
   *      
   */ 
  struct __active_inet_devices * hold_head  = idevs_nodelist ; 
  
  idevs_nodelist = new_idev_node ;
  idevs_nodelist->next = hold_head ; 
  return idevs_nodelist  ; 
  
}


int list_active_interface(const active_inet_devices  *idevs_nodelist , show_info_t show)  
{
  struct __active_inet_devices  * node = (struct __active_inet_devices*) idevs_nodelist ; 
  int  if_items = 0 ; 

  while(node !=  NULL ) {
     if (show)
       show(node) ; 
     node = node->next ; 
     if_items++ ; 
  }
  return if_items ; 
}

char * get_interface(const active_inet_devices * idevs_nodelist , int  index) 
{
    int  n_interfaces  = list_active_interface(idevs_nodelist  , (void * ) 0)  ;  
    

    int  i = abs(n_interfaces  - index) ; 
    int  j = 1  ; 
    
    struct __active_inet_devices * node  =  (struct __active_inet_devices *) idevs_nodelist ; 
    
    while (node != NULL) {
      if (j == i ) break ; 
      node= node->next ; 
      j++ ; 
    }
    
    return  strdup(node->idevname)  ; 

} 

 
struct __idev_info_t * 
get_interface_info(const char  * interface_name)  
{
  inet_device_info * devinfo  = (inet_device_info *) malloc(sizeof(*devinfo)) ; 
  if (!devinfo) return NULL ; 
   
  if (PCAP_ERROR == pcap_lookupnet(interface_name ,   &netip , &subnetip ,  error_buffer)){
    free(devinfo) ; 
    return NULL;   
  }

  int subnetclass = SUBN_MASK & subnetip ; 

  struct  in_addr  address[2] ; 
  address[0].s_addr = netip; 
  address[1].s_addr = subnetip ; 

  memcpy(devinfo->idevname  , interface_name  , strlen(interface_name )); 
  memcpy(devinfo->ipv4netnum , inet_ntoa(*(address+0)) ,  NET_IPV4_LENGHT)  ; 
  memcpy(devinfo->subnet_mask  , inet_ntoa(* (address +1)) , SUBNETMASK_BUFFER) ; 
  
  devinfo->class_type =  _GSTRCLS(subnetclass) ;  

  return devinfo ; 
}
