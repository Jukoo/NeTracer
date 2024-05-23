/** 
 * @file  net.h
 * @brief network stuff  
 * @copyright(c) 2024, Umar Ba <oumar.ba@pasteur.sn> 
 *
 */ 

#ifndef  __net_H
#define  __net_H

#if defined ( __GNUC__) && ( (__GNUC__  == 3 && __GNU_MINOR__ >= 4) ) || (__GNUC__ >4)   
  #pragma once
#else 
  #warning "To Old GNU C compiler version"
#endif 


#ifdef  __cplusplus 
  #define  NETH  extern "C" 
#else 
  #define  NETH 
#endif 

#include <stdint.h> 
#include <sys/socket.h>

#ifndef  lib_pcap_pcap_h 
  #error "require libpcap"
#endif

typedef uint8_t  bint ; 

#define  SADDR_IN  struct  sockaddr_in 



#ifdef __ptr_t 
  #define nullable (__ptr_t) 0  
#else 
  #define nullable (void *) 0 
#endif 

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


#define NET_IPV4_LENGTH  0x14  

typedef struct __active_inet_devices active_inetdevs ; 
typedef struct __idev_info_t   idev_info_t ; 

/**  

 * @brief hold information about interface device  
 * such as iterface device name  ip address  and subnet  
 */
struct __idev_info_t { 
  char * idevname ; 
  union { 
    char ipv4netnum[NET_IPV4_LENGTH] ; 
    char * ipv6 ; //! not supported yet !!  
  } ;

  char subnet_mask[NET_IPV4_LENGTH] ;
  char *class_type ; 
}; 

/**
 * @brief  a linked list structure that hold only 
 *         active iterface devices 
 */
struct  __active_inet_devices   
{
   char  *idev ;   
   struct __active_inet_devices *  next ;  
} ; 


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
 * @brief look which adapter is connected 
 * @param pcap_if_t *  interfaces 
 * @param char *      
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
 * @brief  retrive  information  from  interface device 
 *
 * @param  char *   interface device name 
 * @return struct __idev_info_t  * The related information is stored in 
 */

NETH  struct __idev_info_t * 
net_get_idev_info (const  char  * __restrict__  __interface_device) ;  


/**
 * @brief get the active  interface device name on top of  the list 
 */

NETH char *  
net_get_device_name(struct __active_inet_devices   * __list_of_active_devices_interface) __nonnull((1))  ; 


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
#endif 
