/*
 * Authors: Guilherme Krzisch e Pedro Webber
 */

#include "socketRawAPI.h"

//GLOBAL
uint8_t *pacote;
int i; //para loops
int socketDescriptor;

//TCP
unsigned int tcpHeaderLength;
unsigned int tcpDataLength;

//ICMPv6
struct icmp6_hdr *icmpv6Header;
char *icmpv6Data;
unsigned int icmpv6HeaderLength;


//IPv6
struct ip6_hdr *ipv6Header; // a struct ip esta descrita no /usr/include/netinet/ip.h    
unsigned int ipv6HeaderLength;

//Ethernet
unsigned int ethernetHeaderLength;
struct ifreq ifr;
char *interface;
uint8_t *sourceMacAddress;

//To
struct sockaddr_ll to;

//Informations
#define GET 1
#define HTML_DATA 2
#define ZERO_DATA 3

int operation;
char *url, *path;
u_int16_t fin, syn, rst, ack, window;
u_int32_t seq, ack_seq;
int isEchoRequest;
u_int32_t icmpv6Seq;

char *sourceIP, *destinationIP;

u_int8_t destinationMacAddress[ETH_ALEN];

int setup(int tempOperation, char *tempURL, char *tempPath, u_int16_t tempFin, u_int16_t tempSyn, u_int16_t tempRst, u_int16_t tempAck, u_int32_t tempSeq, u_int32_t tempAck_seq, u_int16_t tempWindow,
        int tempIsEchoRequest, u_int32_t tempIcmpv6Seq,
        char *tempSourceIP, char *tempDestinationIP,
        u_int8_t tempDestinationMacAddress[ETH_ALEN], char *tempInterface) {
    operation = tempOperation;

    if (operation != ZERO_DATA) {
        url = (char *) malloc((strlen(tempURL) + 1) * sizeof (char));
        strcpy(url, tempURL);
        if (operation == GET) {
            path = (char *) malloc((strlen(tempPath) + 1) * sizeof (char));
            strcpy(path, tempPath);
        }
    }


    fin = tempFin;
    syn = tempSyn;
    rst = tempRst;
    ack = tempAck;
    seq = tempSeq;
    ack_seq = tempAck_seq;
    window = tempWindow;

    isEchoRequest = tempIsEchoRequest;
    icmpv6Seq = tempIcmpv6Seq;

    sourceIP = tempSourceIP;
    destinationIP = tempDestinationIP;

    for (i = 0; i < ETH_ALEN; i++) {
        destinationMacAddress[i] = tempDestinationMacAddress[i];
    }

    interface = strdup(tempInterface);

    monta_e_envia_pacote();
}

int setupZeroData(u_int16_t tempSyn, u_int16_t tempAck, u_int32_t tempSeq, u_int32_t tempAck_seq, int tempIsEchoRequest, u_int32_t tempIcmpv6Seq, char *tempSourceIP, char *tempDestinationIP, 
        u_int8_t tempDestinationMacAddress[ETH_ALEN], char *tempInterface){
    
    setup(ZERO_DATA, NULL, NULL, 0, tempSyn, 0, tempAck, tempSeq, tempAck_seq, IP_MAXPACKET, tempIsEchoRequest, tempIcmpv6Seq, tempSourceIP, tempDestinationIP, tempDestinationMacAddress, tempInterface);
}

void monta_e_envia_pacote() {
    //Pacote
    pacote = (uint8_t *) malloc(IP_MAXPACKET * sizeof (uint8_t));
    memset(pacote, 0, IP_MAXPACKET * sizeof (uint8_t));

    //Lengths
    ethernetHeaderLength = 14;
    ipv6HeaderLength = 40;
    icmpv6HeaderLength = 8;
    tcpHeaderLength = sizeof (struct tcphdr);

    //TCP
    monta_data_tcp();

    monta_header_tcp();

    //IPv6
    monta_pacote_ipv6();

    //ICMPv6 - dependecia no IPv6, pq utiliza para calcular o checksum
    monta_pacote_icmpv6();

    if ((socketDescriptor = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("\tErro na criacao do socket.\n");
        exit(1);
    }

    //Ethernet
    memset(&ifr, 0, sizeof (ifr));
    sourceMacAddress = (uint8_t *) malloc(6 * sizeof (uint8_t)); //source mac
    monta_pacote_ethernet();

    //To
    monta_to(); //dependencia no Ethernet, pq utiliza o source mac address


    //Envia pacote
    int retValue = 0;
    if ((retValue = sendto(socketDescriptor, (char *) pacote, ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength + tcpDataLength, 0, (struct sockaddr*) &to, sizeof (to)) < 0)) {
        printf("\tERROR! sendto() Ret value: %d\n",retValue);
        printf("Socket descriptor: %d, length: %d, sizeof(to): %lu\n",socketDescriptor,ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength + tcpDataLength,sizeof (to));
        printf("\n\n%s\n\n",(char *)pacote);
        exit(1);
    }
    //printf("Socket descriptor: %d, length: %d, sizeof(to): %lu\n",socketDescriptor,ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength + tcpDataLength,sizeof (to));
    //printf("\n\n%s\n\n",(char *)pacote);
    fflush(stdout);

}

void monta_data_tcp() {
    char *tcpData;
    tcpData = (char *) malloc(IP_MAXPACKET * sizeof (char));
    memset(tcpData, 0, IP_MAXPACKET * sizeof (char));

    if (operation != ZERO_DATA) {
        if(operation == GET){
            sprintf(tcpData, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, url);
        }
        else if(operation == HTML_DATA){
            sprintf(tcpData, "%s", url);
        }
        
        tcpDataLength = strlen(tcpData);
        memcpy((pacote + ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength), tcpData, tcpDataLength * sizeof (uint8_t));
            
    } else if(operation == ZERO_DATA) {
        tcpDataLength = 0;
    }
}

void monta_header_tcp() {
    struct tcphdr *tcpHeader; // a struct tcp esta descrita em /usr/include/netinet/tcp.h
    tcpHeader = (struct tcphdr *) &pacote[ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength];

    tcpHeader->source = htons((uint16_t) 60000);
    tcpHeader->dest = htons((uint16_t) 60000);
    tcpHeader->seq = htonl(seq);
    tcpHeader->ack_seq = htonl(ack_seq);

    tcpHeader->res1 = 0;
    tcpHeader->doff = 5;
    tcpHeader->fin = fin;
    tcpHeader->syn = syn;
    tcpHeader->rst = rst;
    tcpHeader->psh = 1; //PUSH = 1
    tcpHeader->ack = ack;
    tcpHeader->urg = 0;
    tcpHeader->res2 = 0;

    tcpHeader->window = htons(window);
    tcpHeader->check = htons(in_cksum((uint16_t *)tcpHeader,tcpHeaderLength+tcpDataLength));//htons((uint16_t) 0);
    tcpHeader->urg_ptr = htons((uint16_t) 0);

}

void monta_pacote_icmpv6() {
    icmpv6Header = (struct icmp6_hdr *) &pacote[ethernetHeaderLength + ipv6HeaderLength];

    if (isEchoRequest) {
        icmpv6Header->icmp6_type = (ICMP6_ECHO_REQUEST);
    } else {
        icmpv6Header->icmp6_type = (ICMP6_ECHO_REPLY);
    }

    icmpv6Header->icmp6_code = 0;
    icmpv6Header->icmp6_id = htons(666); //Identificador
    icmpv6Header->icmp6_seq = htons(icmpv6Seq);
    icmpv6Header->icmp6_cksum = (icmp6_checksum(*ipv6Header, *icmpv6Header, &pacote[ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength], tcpHeaderLength + tcpDataLength));
}

void monta_pacote_ipv6() {
    ipv6Header = (struct ip6_hdr *) &pacote[ethernetHeaderLength];

    ipv6Header->ip6_flow = htonl((6 << 28) | (0 << 20) | 0); // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
    ipv6Header->ip6_plen = htons(icmpv6HeaderLength + tcpHeaderLength + tcpDataLength); // Payload length - 2 bytes
    ipv6Header->ip6_nxt = IPPROTO_ICMPV6;
    ipv6Header->ip6_hops = 255;

    int status;
    if ((status = inet_pton(AF_INET6, sourceIP, &(ipv6Header->ip6_src))) != 1) {
        fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
    if ((status = inet_pton(AF_INET6, destinationIP, &(ipv6Header->ip6_dst))) != 1) {
        fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
        exit(EXIT_FAILURE);
    }
}

void monta_pacote_ethernet() {
    struct ether_header *ethernetHeader;
    ethernetHeader = (struct ether_header *) &pacote[0];

    // Use ioctl() to look up interface name and get its MAC address.
    memset(&ifr, 0, sizeof (ifr));
    snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl(socketDescriptor, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed to get source MAC address ");
        exit(EXIT_FAILURE);
    }

    // Copy source MAC address.
    memcpy(sourceMacAddress, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    for (i = 0; i < 6; i++) {
        ethernetHeader->ether_shost[i] = sourceMacAddress[i];
    }

    ethernetHeader->ether_type = htons(ETH_P_IPV6);
    for (i = 0; i < ETH_ALEN; i++) {
        ethernetHeader->ether_dhost[i] = destinationMacAddress[i];
    }
}

void monta_to() {
    /* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
    to.sll_family = htons(PF_PACKET);
    to.sll_protocol = htons(ETH_P_ALL);

    // Find interface index from interface name and store index in struct sockaddr_ll device, which will be used as an argument of sendto().
    if ((to.sll_ifindex = if_nametoindex(interface)) == 0) { /* indice da interface pela qual os pacotes serao enviados */
        perror("if_nametoindex() failed to obtain interface index ");
        exit(EXIT_FAILURE);
    }

    // Fill out sockaddr_ll.
    to.sll_family = AF_PACKET;
    memcpy(to.sll_addr, sourceMacAddress, 6 * sizeof (uint8_t));
    to.sll_halen = htons(6);
}

/*  Copyright (C) 2011-2013  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
// Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t icmp6_checksum(struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen) {
    char buf[ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength + tcpDataLength];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0]; // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
    ptr += sizeof (iphdr.ip6_src);
    chksumlen += sizeof (iphdr.ip6_src);

    // Copy destination IP address into buf (128 bits)
    memcpy(ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
    ptr += sizeof (iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

    // Copy Upper Layer Packet length into buf (32 bits).
    // Should not be greater than 65535 (i.e., 2 bytes).
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = (icmpv6HeaderLength + payloadlen) / 256;
    ptr++;
    *ptr = (icmpv6HeaderLength + payloadlen) % 256;
    ptr++;
    chksumlen += 4;

    // Copy zero field to buf (24 bits)
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy(ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
    ptr += sizeof (iphdr.ip6_nxt);
    chksumlen += sizeof (iphdr.ip6_nxt);

    // Copy ICMPv6 type to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_type, sizeof (icmp6hdr.icmp6_type));
    ptr += sizeof (icmp6hdr.icmp6_type);
    chksumlen += sizeof (icmp6hdr.icmp6_type);

    // Copy ICMPv6 code to buf (8 bits)
    memcpy(ptr, &icmp6hdr.icmp6_code, sizeof (icmp6hdr.icmp6_code));
    ptr += sizeof (icmp6hdr.icmp6_code);
    chksumlen += sizeof (icmp6hdr.icmp6_code);

    // Copy ICMPv6 ID to buf (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_id, sizeof (icmp6hdr.icmp6_id));
    ptr += sizeof (icmp6hdr.icmp6_id);
    chksumlen += sizeof (icmp6hdr.icmp6_id);

    // Copy ICMPv6 sequence number to buff (16 bits)
    memcpy(ptr, &icmp6hdr.icmp6_seq, sizeof (icmp6hdr.icmp6_seq));
    ptr += sizeof (icmp6hdr.icmp6_seq);
    chksumlen += sizeof (icmp6hdr.icmp6_seq);

    // Copy ICMPv6 checksum to buf (16 bits)
    // Zero, since we don't know it yet.
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy ICMPv6 payload to buf
    memcpy(ptr, payload, payloadlen * sizeof (uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i = 0; i < payloadlen % 2; i++, ptr++) {
        *ptr = 0;
        ptr += 1;
        chksumlen += 1;
    }

    return in_cksum((uint16_t *) buf, chksumlen);
}
//End of copyright

/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
unsigned short in_cksum(unsigned short *addr, int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return (answer);
}
//END of Copyright
