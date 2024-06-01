/** 
 * @file  net.h
 * @brief network stuff  
 * @copyright(c) 2024, Umar Ba <oumar.ba@pasteur.sn> 
 *
 */ 

#ifndef  __net_H
#define  __net_H

#ifdef  __cplusplus 
  #define  NETH  extern "C" 
#else 
  #define  NETH 
#endif 

#include <stdint.h> 
#include <sys/socket.h>
typedef uint8_t  bint ; 

#define  SADDR_IN  struct  sockaddr_in 

#ifndef  lib_pcap_pcap_h 
  #error "require libpcap"
#endif

#ifdef __ptr_t 
  #define nullable (__ptr_t) 0  
#else 
  #define nullable (void *) 0 
#endif 

#define NET_IPV4_LENGTH  0x14
typedef struct __raw_iproto  raw_iproto ; 
struct __raw_iproto {
  union { 
    char ipv4[NET_IPV4_LENGTH] ; 
    char * ipv6 ; //! not supported yet !!  
  } ; 
  char subnet_mask[NET_IPV4_LENGTH] ; 
}; 

typedef struct __active_inet_devices active_inetdevs ; 
struct  __active_inet_devices   
{
   char  *idev ;   
   struct __active_inet_devices *  next ;  
} ; 


extern int nidevs ; 
extern char interface_device_name[0x14] ;  

extern   char error_buff[PCAP_ERRBUF_SIZE] ; 
/**
 * @fn bint is_valid_ipv4_address
 * @brief check if string address is a valid ip address 
 * @param  char  * 
 * @return bint 0 ok : -1 error
 */ 
NETH bint  
net_is_valid_ipv4_addr(char * __restrict__ __ipv4_addr); 

/** 
 * @fn net_found_active_interface 
 * @brief  find  active  device  interface  
 * @param pcap_if_t *  interfaces 
 * @param struct __active_inet_devices * 
 * @return  char *   null for failure 
 * !TODO : struct  __device_t {  
 *    char * device ; 
 *    char * description  ; 
 *    int inet ; 
 * }
 */ 
NETH struct __active_inet_devices *
net_found_active_interface(pcap_if_t * __raw_interface ,  struct __active_inet_devices * ); 

/**
 *  @fn net_translate 
 *  @brief variadic function translate byteordered address 
 *         to human redable address stored on struct __raw_iproto  
 *         ipv4 and subnet_mask
 *        
 *  @param struct __raw_iproto * 
 *  @param int index 
 *  @param ...
 *  @return  struct __raw_iproto 
 */ 
NETH struct __raw_iproto * 
net_translate(struct __raw_iproto *  , int index ,  ...) ;

/*
 * @fn net_handler
 * @brief custom routine 
 */ 
NETH void
net_handler(u_char * __device_adpter  , const struct pcap_pkthdr * __packet_headr  , const u_char* __raw_byte_packet) ;  



NETH struct  __active_inet_devices * 
append_inetdev(struct __active_inet_devices  *  , struct __active_inet_devices  * new_idev)  ; 
 

NETH  void 
list_inetdevs (const struct __active_inet_devices * __inet_devices) ;

NETH char * 
shiftback_idevname(const struct  __active_inet_devices *  , int index ) ; 
#endif 
