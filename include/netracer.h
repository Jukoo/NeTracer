/** 
 * @file  net.h
 * @brief network stuff  
 * @copyright(c) 2024, Umar Ba <oumar.ba@pasteur.sn> 
 *
 */ 

#ifndef  netracer
#define  netracer 

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

#include "attr.h" 

#ifndef  lib_pcap_pcap_h 
  #error "require libpcap"
#endif

#define  ETHER_HEADER_LEN  0x0E 

typedef uint8_t  bint ; 

/*! \brief The Ethernet header is always 14 bytes  */

bint net_is_valid_ipv4_addr(char * __restrict__ ipv4_addr_string) ; 

 /*
 * @fn net_handler
 * @brief custom routine 
 */ 
NETH void
net_handler(u_char * __user    , const struct pcap_pkthdr * __packet_hdr  , const u_char* __raw_byte_packet) ;  



#endif 
