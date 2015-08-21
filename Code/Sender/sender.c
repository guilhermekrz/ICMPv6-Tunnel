/*
 * Authors: Guilherme Krzisch e Pedro Webber
 */

#include "../socketRawAPI.c"

#include <ifaddrs.h> //para int getifaddrs(struct ifaddrs **ifap);
#include <limits.h>       //For PATH_MAX

#define ESPERANDO_SYN_ACK 1
#define ESPERA_ACK_DADOS 2
#define ESPERA_DADOS_SERVIDOR 3
#define ESPERA_ACK_FINALIZACAO 4

#define URL 3
#define PATH 4

u_int8_t convertStringToHex(const char * s);
void usage();

int main(int argc, char** argv) {
    if (argc != 5) {
        usage();
        exit(1);
    }

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

    char *clienteIP, *serverIP;
    clienteIP = (char *) malloc(INET6_ADDRSTRLEN * sizeof (char));
    serverIP = (char *) malloc(INET6_ADDRSTRLEN * sizeof (char));
    strcpy(clienteIP, host);

    u_int32_t tempSeq = 0;
    u_int32_t tempAck_seq = 0;
    u_int32_t esperadoSeq = 0;
    u_int32_t esperadoAck_seq = 0;

    strcpy(serverIP, argv[1]);

    struct in6_addr serverIPstruct;
    inet_pton(AF_INET6, serverIP, (void *) (&(serverIPstruct)));

    u_int8_t serverMacAddress[ETH_ALEN];
    char s2[256];
    strcpy(s2, argv[2]);
    char* token = strtok(s2, ":");
    int tokenIndex = 0;
    while (token) {
        serverMacAddress[tokenIndex] = convertStringToHex(token);
        token = strtok(NULL, ":");
        tokenIndex++;
    }

    u_int16_t clientPort;
    clientPort = 60000;
    u_int16_t serverPort;
    serverPort = 60000;

    //Aguarda o recebimento TCP SYN ACK
    int estado;
    estado = ESPERANDO_SYN_ACK;

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
    //unsigned int tcpDataLength;
    struct tcphdr *tcpHeader; // a struct tcp esta descrita em /usr/include/netinet/tcp.h    


    ethernetHeaderLength = 14;
    ipv6HeaderLength = 40;
    icmpv6HeaderLength = 8;
    tcpHeaderLength = sizeof (struct tcphdr);

    //Dados
    char *foodata;
    foodata = (char *) malloc(100 * sizeof (char));
    strcpy(foodata, "foobarBlahblahblahEND");


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


    //Printa dados do cliente
    printf("============================================\n");
    printf("Dados do cliente:\n");
    printf("\tCliente interface:  %s\n", interface);
    printf("\tCliente IP address:  %s\n", clienteIP);
    printf("\tCliente TCP port:  %u\n", clientPort);
    printf("============================================\n");
    //Comeca o envio
    //Send TCP SYN
    printf("============================================\n");
    printf("Dados do servidor:\n");
    printf("\tServer MAC address:  %x:%x:%x:%x:%x:%x \n", serverMacAddress[0], serverMacAddress[1], serverMacAddress[2], serverMacAddress[3], serverMacAddress[4], serverMacAddress[5]);
    printf("\tServer IP address:  %s\n", serverIP);
    printf("\tServer TCP port:  %u\n", serverPort);
    
    printf("\n####################################### Estabelecimento da conexao #######################################\n\n");
    
    printf("Cliente -------------TCP SYN------------->>>> Servidor\n");
    setupZeroData(1, 0, tempSeq, tempAck_seq, 1, 0, clienteIP, serverIP, serverMacAddress, interface);
    esperadoAck_seq = tempSeq + 1;
            
    //Controle
    int printaAgain = 1;
    int primeirosDados = 0;
    FILE *f;
    char *filename;
    int urlLength = strlen(argv[URL]);
    filename = (char *) malloc(urlLength * (sizeof (char) + 1 + 5));
    strcpy(filename, argv[URL]);
    strcpy(&(filename[urlLength]), ".html");

    // loop de recepcao de pacotes
    while (1) {
        if (printaAgain) {
            if (estado == ESPERANDO_SYN_ACK) {
                printf("Aguardando SYN ACK do servidor...");
            } else if (estado == ESPERA_ACK_DADOS) {
                printf("Aguardando ACK de dados do servidor...");
            } else if (estado == ESPERA_DADOS_SERVIDOR) {
                printf("Aguardando dados de resposta do servidor...");
            } else if (estado == ESPERA_ACK_FINALIZACAO) {
                printf("Aguardando ACK do servidor (para o pedido de finalizacao de conexao)...");
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


        //Testa se eh IPv6, ICMPv6 e echo reply
        if (ethernetHeader->ether_type == ntohs(ETH_P_IPV6) && ipv6Header->ip6_nxt == IPPROTO_ICMPV6 && icmpv6Header->icmp6_type == ICMP6_ECHO_REPLY && icmpv6Header->icmp6_code == 0
                && ntohs(tcpHeader->dest) == clientPort) {
            //Pacote recebido
            //Checa se foi enviado um pacote do servidor com o mesmo IP, MAC, e na mesma porta do que o real servidor.
            //Checa IP
            if (memcmp(&serverIPstruct, &(ipv6Header->ip6_src), sizeof (struct in6_addr)) == 0) {
                //OK
                //Checa MAC
                int erro = 0;
                for (i = 0; i < ETH_ALEN; i++) {
                    if (serverMacAddress[i] != ethernetHeader->ether_shost[i]) {
                        erro = 1;
                        break;
                    }
                }
                if (erro) {
                    continue;
                }
                //OK
                if (serverPort != ntohs(tcpHeader->source)) {
                    continue;
                }
            } else {
                continue;
            }
            
            //Checa se sequence number e ack number estao certos
            if (estado == ESPERANDO_SYN_ACK && tcpHeader->syn == 1 && tcpHeader->ack == 1) {
                //tanto faz o esperadoSeq
                if(esperadoAck_seq != ntohl(tcpHeader->ack_seq)){
                    continue;
                }
            } else if (estado == ESPERA_ACK_DADOS && tcpHeader->ack == 1) {
                if((esperadoAck_seq != ntohl(tcpHeader->ack_seq)) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            } else if (estado == ESPERA_ACK_FINALIZACAO && tcpHeader->ack == 1) {
                if((esperadoAck_seq != ntohl(tcpHeader->ack_seq)) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            } else if (estado == ESPERA_DADOS_SERVIDOR && tcpHeader->fin == 1) {
                if((esperadoAck_seq != ntohl(tcpHeader->ack_seq)) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            } else if (estado == ESPERA_DADOS_SERVIDOR) {
                if((esperadoAck_seq != ntohl(tcpHeader->ack_seq)) || esperadoSeq != ntohl(tcpHeader->seq)){
                    continue;
                }
            }
            else{
                continue;
            }
            

            //Pacote valido
            printaAgain = 1;
            printf("\n");
            printf("----------------------------------------------------\n");

            if (estado == ESPERANDO_SYN_ACK && tcpHeader->syn == 1 && tcpHeader->ack == 1) {
                //SYN ACK recebido    
                printf("Cliente <<<<----------TCP SYN ACK---------------- Servidor\n");
            } else if (estado == ESPERA_ACK_DADOS && tcpHeader->ack == 1) {
                printf("Cliente <<<<----------TCP ACK---------------- Servidor (ACK de dados - servidor recebeu os dados)\n");
            } else if (estado == ESPERA_ACK_FINALIZACAO && tcpHeader->ack == 1) {
                printf("Cliente <<<<----------TCP ACK---------------- Servidor (ACK de finalizacao - conexao encerrada)\n");
            } else if (estado == ESPERA_DADOS_SERVIDOR && tcpHeader->fin == 1) {
                printf("\n####################################### Finalizacao da conexao #######################################\n\n");
                printf("Cliente <<<<----------TCP FIN---------------- Servidor\n");
            } else if (estado == ESPERA_DADOS_SERVIDOR) {
                printf("Cliente <<<<----------TCP DATA---------------- Servidor\n");
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

            if (estado == ESPERANDO_SYN_ACK && tcpHeader->syn == 1 && tcpHeader->ack == 1) {
                //Guardar initial sequence number
                tempAck_seq = ntohl(tcpHeader->seq);

                //Envia um ACK em resposta
                printf("Cliente -------------TCP ACK------------->>>> Servidor (Conexao estabelecida - Three-way handshake)\n");
                tempSeq = tempSeq + 1;                
                tempAck_seq = tempAck_seq + 1;     
                esperadoSeq = tempAck_seq;
                setupZeroData(0, 1, tempSeq, tempAck_seq, 1, 0, clienteIP, serverIP, serverMacAddress, interface);
                
                printf("\n####################################### Envio de dados #######################################\n\n");

                //Envio de dados
                printf("Cliente -------------TCP DATA------------->>>> Servidor (Dados GET)\n");

                setup(GET, argv[URL], argv[PATH], 0, 0, 0, 1, tempSeq, tempAck_seq, IP_MAXPACKET, 1, 0, clienteIP, serverIP, serverMacAddress, interface);

                tempSeq = tempSeq + tcpDataLength;
                esperadoAck_seq = tempSeq;
                //Espera o recebimento da resposta do servidor

                estado = ESPERA_ACK_DADOS;               
                
            } else if (estado == ESPERA_ACK_DADOS && tcpHeader->ack == 1) {
                printf("\n####################################### Recebimento de dados #######################################\n\n");
                estado = ESPERA_DADOS_SERVIDOR;
            } else if (estado == ESPERA_ACK_FINALIZACAO && tcpHeader->ack == 1) {
                break;
            } else if (estado == ESPERA_DADOS_SERVIDOR && tcpHeader->fin == 1) {
                printf("Cliente -------------TCP ACK FIN------------->>>> Servidor (Enviando ACK para o pedido de finalizacao do servidor, e pedindo tambem a finalizacao da conexao)\n");
                tempAck_seq = tempAck_seq + 1;
                esperadoSeq = tempAck_seq;
                esperadoAck_seq = tempSeq + 1;
                setup(ZERO_DATA, NULL, NULL, 1, 0, 0, 1, tempSeq, tempAck_seq, IP_MAXPACKET, 1, 0, clienteIP, serverIP, serverMacAddress, interface);
                estado = ESPERA_ACK_FINALIZACAO;
            } else if (estado == ESPERA_DADOS_SERVIDOR) {
                //printf("Dados recebidos do servidor.\n");
                if (primeirosDados == 0) {
                    f = fopen(filename, "w");
                    if (f == NULL) {
                        printf("Error opening file!\n");
                        exit(1);
                    }
                    fprintf(f, "%s", &pacoteRecebido [ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength]);
                    fclose(f);
                    primeirosDados = 1;
                } else {
                    f = fopen(filename, "a");
                    if (f == NULL) {
                        printf("Error opening file!\n");
                        exit(1);
                    }
                    fprintf(f, "%s", &pacoteRecebido [ethernetHeaderLength + ipv6HeaderLength + icmpv6HeaderLength + tcpHeaderLength]);
                    fclose(f);
                }
                
                printf("Cliente -------------TCP ACK------------->>>> Servidor (Cliente acknowledgeando os dados recebidos)\n");
                unsigned int dataSize = (ntohs(ipv6Header->ip6_plen) - (icmpv6HeaderLength + tcpHeaderLength));
                if(dataSize > 0){
                    tempAck_seq = tempAck_seq + dataSize;
                }         
                esperadoSeq = tempAck_seq;
                setupZeroData(0, 1, tempSeq, tempAck_seq, 1, 0, clienteIP, serverIP, serverMacAddress, interface);
                
                /*char command[26 + PATH_MAX + 1];
                char buf[PATH_MAX + 1];
                realpath("output.html", buf);
                strcpy(command, "gksu x-www-browser file://"); //26
                strcpy(&command[26], buf);
                strcpy(&command[26+strlen(buf)]," &");
                printf("%s\n", command);
                system(command);*/
            }
        }
    }

    printf("============================================\n");

    //Clean up
    free(interface);

    return 0;
}

void usage() {
    printf("Usage: ./sender [IPv6 do servidor] [MAC do servidor] [URL] [path]\n");
    printf("Example: ./sender XXXX::XXXX:XXXX:XXXX:XXXX XX:XX:XX:XX:XX:XX www.google.com /\n");
}

/*
 * Code from http://stackoverflow.com/questions/10746450/how-to-convert-string-to-hexadecimal, user http://stackoverflow.com/users/1276280/pizza
 */
u_int8_t convertStringToHex(const char * s) {
    u_int8_t result = 0;
    int c;
    while (*s) {
        result = result << 4;
        if (c = (*s - '0'), (c >= 0 && c <= 9)) result |= c;
        else if (c = (*s - 'A'), (c >= 0 && c <= 5)) result |= (c + 10);
        else if (c = (*s - 'a'), (c >= 0 && c <= 5)) result |= (c + 10);
        else break;
        ++s;
    }
    return result;
}
/*
 * End Code from http://stackoverflow.com/questions/10746450/how-to-convert-string-to-hexadecimal, user http://stackoverflow.com/users/1276280/pizza
 */
