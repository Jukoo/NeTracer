/* *
 *
 *
 **/

#ifndef  interface_network_devices_manipulations
#define  interface_network_devices_manipulations 

#if __GNUC_PREREQ(3,4)
  #pragma once 
#else 
  #warning  "Need at least a recent GNU C Compiler"
#endif 

#include "attr.h"  

#define  NET_IPV4_LENGHT   20 
#define  DFLBUFFER         20 
#define  SUBNETMASK_BUFFER 20  


#define SUBN_MASK  0xffffffff 
#define SBN_CLASS_C   0x8  
#define SBN_CLASS_B   0x10 
#define SBN_CLASS_A   0x18

enum  { 
    IS_CLSC =   (SUBN_MASK >> SBN_CLASS_C ) , 
#define  IS_CLSC IS_CLSC 
#define m_IS_CLSC  "C"
     
      IS_CLSB =   (SUBN_MASK >> SBN_CLASS_B) , 
#define IS_CLSB IS_CLSB 
#define m_IS_CLSB  "B"

        IS_CLSA =   (SUBN_MASK >> SBN_CLASS_A) 
#define IS_CLSA IS_CLSA
#define m_IS_CLSA  "A"
          
}; 
//! get string   class 
#define _GSTRCLS(_class_mask) \
  _class_mask == IS_CLSC ? m_##IS_CLSC : \
  _class_mask == IS_CLSB ? m_##IS_CLSB : \
  _class_mask == IS_CLSA ? m_##IS_CLSA : "" 



__BEGIN_DECLS  


typedef struct __active_inet_devices  active_inet_devices ;  
typedef struct __idev_info_t inet_device_info ; 
typedef void (*show_info_t)(active_inet_devices * ) ; 
 
extern char error_buff[PCAP_ERRBUF_SIZE] ; 
extern bpf_u_int32  netip , subnetip ; 


typedef struct    __idev_t idev_t  ;   
struct    __idev_t  {   
  char  idevname[DFLBUFFER] ;         /*! interface device name  */ 
  char  idevipv4addr[DFLBUFFER]  ;    /*! interface ip address version 4*/
}; 
/*!  
 * \brief  hold only active  networking device interface  
 * \TODO: Add more informations ... 
 */
struct __active_inet_devices {
  /*interface  device name*/
  char idevname[DFLBUFFER] ;
  char ipv4_address[NET_IPV4_LENGHT]; 
  struct __active_inet_devices  * next ; 
}; 

/*! \brief hold  some information related to active_devices */
struct __idev_info_t {
   char idevname[DFLBUFFER]  ;  
   union {
    char ipv4netnum[NET_IPV4_LENGHT];
    char *ipv6netnum ;  //! not enable yet 
   }; 
   char subnet_mask[SUBNETMASK_BUFFER] ; 
   char *class_type ;  
} ;


/*! 
 * \brief 
 **/
struct  __active_inet_devices * 
fetch_active_netdev_interface(pcap_if_t * __raw_netdevs ,  active_inet_devices * indevs) ; 

static struct __active_inet_devices * 
register_inetdev(active_inet_devices * idevs_nodelist , active_inet_devices *  new_idev_node);  

int  list_active_interface(const  active_inet_devices * idevs_nodelist , show_info_t  verbose) ; 
#define  list_idevs(__active_inet_devices) \
  list_active_interface(__active_inet_devices , show_info); 

char * get_interface(const active_inet_devices * idevs_nodelist , int   index ) ;
#define  get_default_interface(__active_inet_devices)\
  get_interface(__active_inet_devices , 0) ; 

//char *get_interface_by_name(const active_inet_devices *  idevs_nodelist , const char * name) ; 

struct __idev_info_t * 
get_interface_info(const char  *  interface_devices_name) ; 

static char * get_interface_ipv4(struct  pcap_addr *) ; 

static void __inline__ show_idevinfo (const  inet_device_info  * idevinfo) 
{
  if(!idevinfo) return  ; 
  
  fprintf(stdout , "Caputring on interface::<%s>\n" , idevinfo->idevname) ; 
  fprintf(stdout , "Net ip:: %s \n" , idevinfo->ipv4netnum ) ;  
  fprintf(stdout , "Subnet mask:: %s \n" , idevinfo->subnet_mask ) ;  
  fprintf(stdout , "Class Type :: %s \n" , idevinfo->class_type) ;  

}



__END_DECLS

#endif  
