#ifndef SENDER_H
#define	SENDER_H

//#include "in_cksum.c" //Calculo do checksum

#include <stdio.h>
//#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netdb.h> 
#include <netinet/in.h>
#include <bits/ioctls.h> 
#include <linux/if_ether.h> 

//TCP
#include <netinet/tcp.h>

void monta_e_envia_pacote();
void monta_data_tcp();
void monta_header_tcp();
void monta_pacote_icmpv6();
void monta_pacote_ipv6();
void monta_pacote_ethernet();
void monta_to();

int setup(int tempIsGet, char *tempURL, char *tempPath, u_int16_t tempFin, u_int16_t tempSyn, u_int16_t tempRst, u_int16_t tempAck, u_int32_t tempSeq, u_int32_t tempAck_seq, u_int16_t tempWindow,
        int tempIsEchoRequest,u_int32_t tempIcmpv6Seq,
        char *tempSourceIP, char *tempDestinationIP,
        u_int8_t  tempDestinationMacAddress[ETH_ALEN], char *tempInterface);


unsigned short in_cksum(unsigned short *addr,int len);

uint16_t icmp6_checksum(struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen);


#endif	/* SENDER_H */

