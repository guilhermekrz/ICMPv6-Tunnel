/*
 * Authors: Guilherme Krzisch e Pedro Webber
 */

//#include <cstdlib>

#include "../socketRawAPI.c"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

//IPv6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <ifaddrs.h> //para int getifaddrs(struct ifaddrs **ifap);

#define ESPERANDO_CONEXAO 1
#define ESPERANDO_ACK_CONEXAO 2
#define CONEXAO_ESTABELECIDA_ESPERANDO_DADOS 3
#define ESPERANDO_ACK_DADOS 4
#define ESPERANDO_ACK_FIN 5

int main(int argc, char** argv) {
    char *interface;
    //Code from http://man7.org/linux/man-pages/man3/getifaddrs.3.html
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            char* token = strtok(host, "%");
            while (token) {
                interface = strdup(token);
                token = strtok(NULL, "%");
            }
        }
    }

    freeifaddrs(ifaddr);
    //End Code from http://man7.org/linux/man-pages/man3/getifaddrs.3.html

    int estado;
    estado = ESPERANDO_CONEXAO;

    unsigned char pacoteRecebido[IP_MAXPACKET]; // buffer de recepcao

    int socketDescriptor;
    struct ifreq ifr;

    //Ethernet
    unsigned int ethernetHeaderLength;
    struct ether_header *ethernetHeader;

    //IPv6
    struct ip6_hdr *ipv6Header;
    unsigned int ipv6HeaderLength;

    //ICMPv6
    struct icmp6_hdr *icmpv6Header;
    unsigned int icmpv6HeaderLength;

    //TCP
    unsigned int tcpHeaderLength;
    struct tcphdr *tcpHeader; // a struct tcp esta descrita em /usr/include/netinet/tcp.h    


    ethernetHeaderLength = 14;
    ipv6HeaderLength = 40;
    icmpv6HeaderLength = 8;
    tcpHeaderLength = sizeof (struct tcphdr);

    //Cliente
    char *clienteIP;
    clienteIP = (char *) malloc(INET6_ADDRSTRLEN * sizeof (char));
    memset(clienteIP, 0, (INET6_ADDRSTRLEN * sizeof (char)));
    struct in6_addr clienteIPstruct;

    u_int8_t clientMacAddress[ETH_ALEN];

    u_int16_t clientPort;

    //Server
    char *serverIP;
    serverIP = (char *) malloc(INET6_ADDRSTRLEN * sizeof (char));
    strcpy(serverIP, host);

    char *foodata;
    foodata = (char *) malloc(100 * sizeof (char));
    strcpy(foodata, "foobarBlahblahblahEND");

    u_int16_t serverPort;
    serverPort = 60000;

    u_int32_t tempSeq = 0;
    u_int32_t tempAck_seq = 0;
    u_int32_t esperadoSeq = 0;
    u_int32_t esperadoAck_seq = 0;

    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if ((socketDescriptor = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("Nao foi possivel criar o socket.\n");
        exit(1);
    }

    // O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
    strcpy(ifr.ifr_name, interface);
    if (ioctl(socketDescriptor, SIOCGIFINDEX, &ifr) < 0) {
        printf("Nao foi possivel utilizar a funcao ioctl.\n");
        exit(1);
    }
    ioctl(socketDescriptor, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(socketDescriptor, SIOCSIFFLAGS, &ifr);

    printf("============================================\n");
    printf("Dados do servidor:\n");
    printf("\tServer interface:  %s\n", interface);
    printf("\tServer IP address:  %s\n", serverIP);
    printf("\tServer TCP port:  %u\n", serverPort);
    printf("============================================\n");

    //Controle
    int printaAgain = 1;

    // loop de recepcao de pacotes
    while (1) {
        if (printaAgain) {
            if (estado == ESPERANDO_ACK_FIN) {
                printf("Aguardando ACK FIN do cliente...");
            } else if (estado == ESPERANDO_CONEXAO) {
                printf("Aguardando nova conexao...");
            } else if (estado == ESPERANDO_ACK_CONEXAO) {
                printf("Aguardando ACK de resposta (para o pacote SYN ACK enviado ao cliente)...");
            } else if (estado == CONEXAO_ESTABELECIDA_ESPERANDO_DADOS) {
                printf("Aguardando dados de requisicao do cliente...");
            } else if (estado == ESPERANDO_ACK_DADOS){
                printf("Aguardando ACK dos dados enviados...");
            }
            printaAgain = 0;
            fflush(stdout);
        } else {
            printf(".");
            fflush(stdout);
        }

        memset(pacoteRecebido, 0, IP_MAXPACKET * sizeof (unsigned char));
        recv(socketDescriptor, (char *) &pacoteRecebido, sizeof (pacoteRecebido), 0x0);

        ethernetHeader = (struct ether_header *) &pacoteRecebido[0];
        ipv6Header = (struct ip6_hdr *) &pacoteRecebido[ethernetHeaderLength];
        icmpv6Header = (struct icmp6_hdr *) &pacoteRecebido[ethernetHeaderLength + ipv6HeaderLength];
        tcpHeader = (struct tcphdr *) &pacoteRecebido[ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength];

        //Testa se eh IPv6, ICMPv6 e echo request
        if (ethernetHeader->ether_type == ntohs(ETH_P_IPV6) && ipv6Header->ip6_nxt == IPPROTO_ICMPV6 && icmpv6Header->icmp6_type == ICMP6_ECHO_REQUEST && icmpv6Header->icmp6_code == 0
                && ntohs(tcpHeader->dest) == serverPort) {
            if (estado == ESPERANDO_CONEXAO) {
                //aceita tudo
            } else {
                //Checa se foi enviado um pacote do cliente com o mesmo IP, MAC, e na mesma porta do que o cliente conectado antes.
                //Checa IP
                if (memcmp(&clienteIPstruct, &(ipv6Header->ip6_src), sizeof (struct in6_addr)) == 0) {
                    //OK
                    //Checa MAC
                    int erro = 0;
                    for (i = 0; i < ETH_ALEN; i++) {
                        if (clientMacAddress[i] != ethernetHeader->ether_shost[i]) {
                            erro = 1;
                            break;
                        }
                    }
                    if (erro) {
                        continue;
                    }
                    //OK
                    if (clientPort != tcpHeader->source) {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            
            //Checa se sequence number e ack number estao certos
            if (estado == ESPERANDO_ACK_FIN && tcpHeader->ack == 1 && tcpHeader->fin == 1) {
                
                if(esperadoAck_seq != ntohl(tcpHeader->ack_seq) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            } else if (estado == ESPERANDO_CONEXAO && tcpHeader->syn == 1) {
                //tanto faz o esperadoSeq e o esperadoSeq
            } else if (estado == ESPERANDO_ACK_CONEXAO && tcpHeader->ack == 1) {
                if((esperadoAck_seq != ntohl(tcpHeader->ack_seq)) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            } else if (estado == CONEXAO_ESTABELECIDA_ESPERANDO_DADOS) {
                if((esperadoAck_seq != ntohl(tcpHeader->ack_seq)) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            } else if (estado == ESPERANDO_ACK_DADOS && tcpHeader->ack == 1) {
                if((esperadoAck_seq != ntohl(tcpHeader->ack_seq)) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            }
            else{
                continue;
            }

            //Pacote valido!

            printaAgain = 1;
            printf("\n");
            printf("----------------------------------------------------\n");
            if (estado == ESPERANDO_ACK_FIN && tcpHeader->ack == 1 && tcpHeader->fin == 1) {
                //Fim da conexao. Limpa tudo e se prepara para receber uma nova conexao.
                printf("Cliente -------------TCP ACK FIN------------->>>> Servidor (Recebido ACK para o pedido de finalizacao da conexao, e recebido tambem o pedido de finalizacao da conexao pela parte do cliente)\n");
            } else if (estado == ESPERANDO_CONEXAO && tcpHeader->syn == 1) {
                printf("\n####################################### Estabelecimento da conexao #######################################\n\n");
                //Cliente tentando se conectar                
                printf("Cliente -------------TCP SYN------------->>>> Servidor (Pedido de conexao)\n");

                //Guardar porta do cliente 
                clientPort = tcpHeader->source;

                //Guardar IP do cliente
                inet_ntop(AF_INET6, &(ipv6Header->ip6_src), clienteIP, INET6_ADDRSTRLEN);
                clienteIPstruct = (ipv6Header->ip6_src);

                //Guardar MAC address do cliente
                for (i = 0; i < ETH_ALEN; i++) {
                    clientMacAddress[i] = ethernetHeader->ether_shost[i];
                }

                //Guardar initial sequence number
                tempAck_seq = ntohl(tcpHeader->seq);

                printf("Dados do cliente:\n");
                printf("\tCliente MAC address:  %x:%x:%x:%x:%x:%x \n", clientMacAddress[0], clientMacAddress[1], clientMacAddress[2], clientMacAddress[3], clientMacAddress[4], clientMacAddress[5]);
                printf("\tCliente IP address:  %s\n", clienteIP);
                printf("\tCliente TCP port:  %u\n", clientPort);
                printf("\tCliente Initial Sequence Number:  %u\n", tempAck_seq);
                printf("----------------------------------------------------\n");
            } else if (estado == ESPERANDO_ACK_CONEXAO && tcpHeader->ack == 1) {
                //Cliente enviou ack de conexao
                printf("Cliente -------------TCP ACK------------->>>> Servidor (Conexao estabelecida - Three-way handshake)\n");
            } else if (estado == CONEXAO_ESTABELECIDA_ESPERANDO_DADOS) {
                printf("\n####################################### Recebimento de dados #######################################\n\n");
                printf("Cliente -------------TCP DATA------------->>>> Servidor (Dados GET)\n");
            } else if (estado == ESPERANDO_ACK_DADOS && tcpHeader->ack == 1) {
                printf("Cliente -------------TCP ACK------------->>>> Servidor (Cliente acknowledgeou todos os dados recebidos)\n");
            }

            //Printa informacoes gerais do pacote
            printf("TCP sequence number: %u, ", ntohl(tcpHeader->seq));
            if (tcpHeader->ack) {
                printf("ack number: %u, ", ntohl(tcpHeader->ack_seq));
            } else {
                printf("not an ack packet, ");
            }
            printf("reset: %u, ", tcpHeader->rst);
            printf("syn: %u, ", tcpHeader->syn);
            printf("fin: %u, ", tcpHeader->fin);
            printf("window size: %u.\n", tcpHeader->window);
            if (ntohs(ipv6Header->ip6_plen) > (icmpv6HeaderLength + tcpHeaderLength)) {
                printf("TCP data:\n******************************\n%s\n", &pacoteRecebido [ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength]);
                printf("******************************\n");
            }

            if (estado == ESPERANDO_ACK_FIN && tcpHeader->ack == 1 && tcpHeader->fin == 1) {
                printf("Cliente <<<<----------TCP ACK---------------- Servidor (ACK de finalizacao - conexao encerrada - limpa tudo e se prepara para aceitar uma nova conexao)\n");
                tempSeq = tempSeq + 1;
                tempAck_seq = tempAck_seq + 1;
                setup(ZERO_DATA, NULL, NULL, 0, 0, 0, 1, tempSeq, tempAck_seq, IP_MAXPACKET, 0, 0, serverIP, clienteIP, clientMacAddress, interface);

                //Clean up
                estado = ESPERANDO_CONEXAO;
                memset(clienteIP, 0, (INET6_ADDRSTRLEN * sizeof (char)));
                esperadoSeq = 0;
                esperadoAck_seq = 0;
            } else if (estado == ESPERANDO_CONEXAO && tcpHeader->syn == 1) {
                //Mando um syn-ack
                printf("Cliente <<<<----------TCP SYN ACK---------------- Servidor\n");
                tempAck_seq = tempAck_seq + 1;                
                esperadoSeq = tempAck_seq;
                setupZeroData(1, 1, tempSeq, tempAck_seq, 0, 0, serverIP, clienteIP, clientMacAddress, interface);
                tempSeq = tempSeq + 1;
                esperadoAck_seq = tempSeq;
                estado = ESPERANDO_ACK_CONEXAO;

            } else if (estado == ESPERANDO_ACK_CONEXAO && tcpHeader->ack == 1) {
                estado = CONEXAO_ESTABELECIDA_ESPERANDO_DADOS;
            } else if (estado == CONEXAO_ESTABELECIDA_ESPERANDO_DADOS) {
                printf("Cliente <<<<----------TCP ACK---------------- Servidor (ACK de dados - servidor recebeu os dados)\n");
                unsigned int dataSize = (ntohs(ipv6Header->ip6_plen) - (icmpv6HeaderLength + tcpHeaderLength));
                if(dataSize > 0){
                    tempAck_seq = tempAck_seq + dataSize;
                }        
                esperadoSeq = tempAck_seq;
                setupZeroData(0, 1, tempSeq, tempAck_seq, 0, 0, serverIP, clienteIP, clientMacAddress, interface);
                printf("\n####################################### Envio de dados #######################################\n\n");
                printf("Tratando os dados recebidos. Envio de requisicao ao servidor remoto, via comando GET. Apos resposta, retornaremos ao cliente estes dados.\n");
                unsigned char *get = &pacoteRecebido[ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength];


                char s[IP_MAXPACKET];
                char *ptr2 = (char *) &pacoteRecebido[ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength];
                strcpy(s, ptr2);
                char* token = strtok(s, " \r\n");
                int lineNumber;
                lineNumber = 0;
                while (token) {
                    if (lineNumber == 4) {
                        break;
                    }
                    token = strtok(NULL, " \r\n");
                    lineNumber++;
                }


                struct sockaddr_in *socketTo;
                socketTo = (struct sockaddr_in *) malloc(sizeof (struct sockaddr_in *));
                int socketDescriptor;
                if ((socketDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
                    perror("Erro! Nao foi possivel criar o socket TCP.\n");
                    exit(1);
                }

                struct addrinfo hints, *result;
                char addrstr[100];
                void *ptr;
                memset(&hints, 0, sizeof (hints));
                //hints.ai_family = PF_INET6;
                //hints.ai_family = PF_UNSPEC;
                hints.ai_family = PF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags |= AI_CANONNAME;
                //getaddrinfo("ipv6.google.com", "http", &hints, &result);
                //getaddrinfo("google.com", "http", &hints, &result);                

                if(token[0] == 'w' && token[1] == 'w' && token[2] == 'w' && token[3] == '.'){
                    getaddrinfo(&token[4], "http", &hints, &result);
                }
                else{
                    getaddrinfo(&token[0], "http", &hints, &result);
                }
                

                while (result) {
                    inet_ntop(result->ai_family, result->ai_addr->sa_data, addrstr, 100);

                    switch (result->ai_family) {
                        case AF_INET:
                            ptr = &((struct sockaddr_in *) result->ai_addr)->sin_addr;

                            break;
                            //case AF_INET6:
                            //ptr = &((struct sockaddr_in6 *) result->ai_addr)->sin6_addr;
                            //break;
                    }
                    inet_ntop(result->ai_family, ptr, addrstr, 100);
                    //printf("IPv%d address: %s (%s)\n", result->ai_family == PF_INET6 ? 6 : 4, addrstr, result->ai_canonname);
                    result = result->ai_next;
                    //break;
                }

                socketTo->sin_family = AF_INET;
                socketTo->sin_port = htons(80);
                inet_pton(AF_INET, addrstr, (void *) (&(socketTo->sin_addr.s_addr)));
                if (connect(socketDescriptor, (struct sockaddr *) socketTo, sizeof (struct sockaddr)) < 0) {
                    perror("Erro! Nao foi possivel abrir conexao com o servidor remoto.\n");
                    exit(1);
                }

                //Manda a requisicao get para o server
                int sent = 0;
                int tmpres;
                while (sent < strlen((const char *) (get))) {
                    tmpres = send(socketDescriptor, ((const char *) get) + sent, strlen((const char *) (get)) - sent, 0);
                    if (tmpres == -1) {
                        perror("Erro! Nao foi possivel enviar o comando GET para o servidor remoto.\n");
                        exit(1);
                    }
                    sent += tmpres;
                }
                //recebe a resposta
                int index;
                index = 0;

                char buffer[65000];
                memset(buffer, 0, sizeof (buffer));
                int htmlstart = 0;
                char * htmlcontent;
                while ((tmpres = recv(socketDescriptor, buffer, 65000, 0)) > 0) {
                    printf("Dados recebidos do servidor remoto.\n");
                    if (htmlstart == 0) {
                        htmlcontent = strstr(buffer, "\r\n\r\n");
                        if (htmlcontent != NULL) {
                            htmlstart = 1;
                            htmlcontent += 4;
                        }
                    } else {
                        htmlcontent = buffer;
                    }
                    if (htmlstart) {
                        //fprintf(stdout, "%s", htmlcontent);
                        //Enviar dados para o cliente
                        printf("Cliente <<<<----------TCP DATA---------------- Servidor (Enviando dados recebidos para o cliente)\n");
                        setup(HTML_DATA, htmlcontent, NULL, 0, 0, 0, 1, tempSeq, tempAck_seq, IP_MAXPACKET, 0, 0, serverIP, clienteIP, clientMacAddress, interface);
                        tempSeq = tempSeq + tcpDataLength;
                        esperadoAck_seq = tempSeq;
                    }

                    memset(buffer, 0, tmpres);
                }
                if (tmpres < 0) {
                    perror("Erro no recebimento dos dados!\n");
                    exit(1);
                }
                close(socketDescriptor);
                printf("Todos os dados recebidos do servidor remoto foram enviados para o cliente.\n");
                printf("Esperando ACK do cliente, acknowledgeando todos os dados recebidos.\n");
                printf("----------------------------------------------------\n");
                estado = ESPERANDO_ACK_DADOS;
            } else if (estado == ESPERANDO_ACK_DADOS && tcpHeader->ack == 1) {
                printf("\n####################################### Finalizacao da conexao #######################################\n\n");
                printf("Cliente <<<<----------TCP FIN---------------- Servidor (Enviando requisicao de finalizacao da conexao)\n");
                setup(ZERO_DATA, NULL, NULL, 1, 0, 0, 1, tempSeq, tempAck_seq, IP_MAXPACKET, 0, 0, serverIP, clienteIP, clientMacAddress, interface);
                esperadoAck_seq = tempSeq + 1;
                estado = ESPERANDO_ACK_FIN;
            } 
        }
    }
}
