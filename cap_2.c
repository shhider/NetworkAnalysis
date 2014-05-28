#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    static int count = 1;
    fprintf(stdout,"%d, ",count);
    if(count == 4)
        fprintf(stdout,"Come on baby sayyy you love me!!! ");
    if(count == 7)
        fprintf(stdout,"Tiiimmmeesss!! ");
    fflush(stdout);
    count++;
}

int main(int argc, char **argv)
{
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;      /*you can man it*/
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    u_char *ptr; /* printing out hardware header info */

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }

    printf("DEV: %s\n",dev);

    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    packet = pcap_next(descr,&hdr);

    if(packet == NULL)
    {/* dinna work *sob* */
        printf("Didn't grab packet\n");
        exit(1);
    }

    /*  struct pcap_pkthdr {
        struct timeval ts;   time stamp 
        bpf_u_int32 caplen;  length of portion present 
        bpf_u_int32;         lebgth this packet (off wire) 
        }
     */

    printf("Grabbed packet of length %d\n",hdr.len);
    printf("Recieved at ..... %s\n",(char*)ctime((const time_t*)&hdr.ts.tv_sec)); 
    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;

    /* Do a couple of checks to see what packet type we have..*/
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
    }else {
        printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
        exit(1);
    }

    /* THANK YOU RICHARD STEVENS!!! RIP*/
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf(" Destination Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf(" Source Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    return 0;
}

