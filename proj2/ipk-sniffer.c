#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pcap/pcap.h>
#include <time.h>
#include <getopt.h>
#include<netinet/udp.h>    //Provides declarations for udp header
#include<netinet/tcp.h>    //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<net/ethernet.h>
#include <sys/time.h>


void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_hex_ascii(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);

//STRUCTURE FOR GETOPT_LONG
static struct option long_options[] =
{
    {"interaface", required_argument, NULL, 'i'},//S ARGUMENTOM = required_argument
    {"port", required_argument, NULL, 'p'},//S ARGUMENTOM = required_argument
    {"tcp", no_argument, NULL, 't'}, //BEZ ARGUMENTU = no_argument
    {"udp", no_argument, NULL, 'u'}, //BEZ ARGUMENTU = no_argument
    {"num", required_argument, NULL, 'n'},//S ARGUMENTOM = required_argument
    {NULL, 0, NULL, 0}
};
//STORING VARS FOR GETOPT_LONG
char *store_p;
char *store_t;
char *store_u;
int store_n= 1; //KED N NEZADAME OSTAVA 1
char *store_i;

struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

//FUNKCIA HEX
void print_hex_ascii(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    //OFFSET
    printf("0x%04X   ", offset);
    
    //HEXA HODNOTY A SPRAVNY FORMAT
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch); //FORMAT
        ch++;
    }
    //PRE UHLADNOST
    if (len < 8)
        printf(" ");
    
    
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");
    
    //ASCII CAST
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

return;
}

// FUNKCIA PAYLOAD
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        //AKTUALNA DLZKA
        line_len = line_width % len_rem;
        //PRIN LINE
        print_hex_ascii(ch, line_len, offset);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        //PRIDANY OFFSET
        offset = offset + line_width;
        //KONTROLA
        if (len_rem <= line_width) {
            //PRINT LAST LINE
            print_hex_ascii(ch, len_rem, offset);
            break;
        }
    }

return;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    //SOURCE IP AND DESTINATION IP
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    
    
    // CAS V MILISEKUNDACH
    struct timeval tval_before, tval_after, tval_result;
    gettimeofday(&tval_before, NULL);
    sleep(1);
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &tval_result);

    //CAS H:M:
    char buff[100];
    time_t now = time (0);
    strftime (buff, 100, "%H:%M:", localtime (&now));
    printf ("%s", buff);
    printf("%ld.%06ld", (long int)tval_result.tv_sec, (long int)tval_result.tv_usec);
    
    int size_ip = 0;
    int size_tcp = 0;
    int size_payload;
    const u_char *payload;
    const struct sniff_ethernet *ethernet;
    ethernet = (struct sniff_ethernet*)(buffer);
    unsigned short iphdrlen = iph->ihl*4;
    payload = (u_char *)(buffer + iphdrlen + size_ip + size_tcp);
    
    switch (iph->protocol)
    
    {
        // V PRIPADE KED DOSTANEME UDP
        case 17:
        {
            struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
            int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
            printf(" %s" , inet_ntoa(source.sin_addr) );
            printf(" : %d" , ntohs(udph->uh_sport));
            printf(" > %s" , inet_ntoa(dest.sin_addr) );
            printf(" : %d\n" , ntohs(udph->uh_dport));
            size_payload = ntohs(iph->ihl) - (size_ip + size_tcp);

            if (size_payload > 0)
            {
                printf("   Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
            }

            break;
        }
        // V PRIPADE KED DOSTANEME TCP
        case 6:
        {
            struct tcphdr *tcphdr=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
            int header_size =  sizeof(struct ethhdr) + iphdrlen + tcphdr->doff*4;
            printf(" %s" , inet_ntoa(source.sin_addr) );
            printf(" : %d" ,ntohs(tcphdr->th_sport));
            printf(" > %s" , inet_ntoa(dest.sin_addr) );
            printf(" : %d\n",ntohs(tcphdr->th_dport));
            size_payload = ntohs(iph->ihl) - (size_ip + size_tcp);

            if (size_payload > 0)
            {
                printf("   Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
            }

            break;
        }
    }
}
int main(int argc, char *argv[])
{
    bool interface=false;
    bool store_tcp=false;
    bool store_udp=false;
    char option;
    while ((option = getopt_long(argc, argv, "i:p:tun:", long_options, NULL)) != -1)
    {
        // KONTROLA
        switch (option)
        {
             // SHORT option 'p'
             case 'p':
                store_p = optarg;
                break;
             // SHORT option 't'
             case 't':
                store_tcp = true;
                break;
            // SHORT option 'u'
            case 'u':
                store_udp = true;
                break;
            // SHORT option 'n'
            case 'n':
                store_n = atoi(optarg);
                break;
            // SHORT option 'i'
            case 'i':
                store_i = optarg;
                interface=true;
                break;
        }
    }
    if (interface == false)
    {
        pcap_if_t *alldevsp, *device;
        int count = 1 ;
        char errbuf[100] , devs[100][100];
        //Print the available devices
        printf("\nAvailable Devices are :\n");
        if( pcap_findalldevs( &alldevsp , errbuf) )
        {
            printf("Error finding devices : %s" , errbuf);
            exit(1);
        }
        for(device = alldevsp ; device != NULL ; device = device->next)
        {
            printf("%d. %s - %s\n" , count , device->name , device->description);
            if(device->name != NULL)
            {
                strcpy(devs[count] , device->name);
            }
            count++;
        }
    }
    
    pcap_t *handle; //HANDLE ROZHRANIA NA SNIFFOVANIE
    char errbuf[100] , devname[100] ;
    struct bpf_program fp;        // COMPILE EXPRESSION
    bpf_u_int32 net = 0;        // IP
    
    //OTVORENIE ROZHRANIA
    handle = pcap_open_live(store_i , BUFSIZ, 1, 1000 , errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        exit(1);
    }
    
    // KONKATENACIA A VYTVARANIE FILTRA
    char str[100]="";
    if (store_p != NULL) //KED MAME PORT
    {
        strcat((char*)&str, "port "); //FILTER :port
        strcat((char*)&str, store_p); //FILTER :port []
        if ((store_tcp==true) && (store_udp == false)) //KED MAME TCP
        {
            strcat((char*)&str, " and "); //FILTER :port [] and
            strcat((char*)&str, "tcp\n"); //FILTER :port [] and tcp
        }
        else if ((store_udp==true) && (store_tcp == false)) // KED MAME UDP
        {
            strcat((char*)&str, " and "); //FILTER :port [] and
            strcat((char*)&str, "udp\n"); //FILTER :port [] and udp
        }
        else if ((store_tcp ==true) && (store_udp ==true)) //KED MAME AJ TCP AJ UDP
        {
            strcat((char*)&str, " and "); //FILTER :port [] and
            strcat((char*)&str, "tcp or udp\n"); //FILTER :port [] and tcp or udp
        }
    }
    else // KED NEMAME PORT ALE MAME TCP ALEBO UDP
    {
        if ((store_tcp==true) && (store_udp == false)) //KED MAME TCP
        {
            strcat((char*)&str, "tcp\n"); //FILTER : tcp
        }
        else if ((store_udp==true) && (store_tcp == false)) //KED MAME UDP
        {
            strcat((char*)&str, "udp\n"); //FILTER : udp
        }
        else if ((store_tcp ==true) && (store_udp ==true)) // KED MAME TCP AJ UDP
        {
            strcat((char*)&str, "tcp or udp\n"); //FILTER : tcp or udp
        }
    }
    
    
    //FUNKCIA PCAP COMPILE PRE KOMPILACIU FILTRA
    if (pcap_compile(handle, &fp, str, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", str, pcap_geterr(handle));
        return(2);
    }
    
    //FUNKCIA PCAP SETFILTER PRE NASTAVENIE FILTROV
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", str, pcap_geterr(handle));
        return(2);
    }
    
    //SNIFFOVANIE ROZHRANIA
    pcap_loop(handle , store_n , process_packet , NULL);
    
}


