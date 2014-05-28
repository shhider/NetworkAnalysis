 /*pcap_4.c*/
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <linux/ip.h>
#include <linux/tcp.h>

/* just print a count every time we have a packet...                        */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    struct in_addr addr;
    struct iphdr *ipptr;
    struct tcphdr *tcpptr;//太次片，，ip，tcp数据结构
    char *data;
        
    pcap_t *descr = (pcap_t*)useless;//捕获网络数据包的数据包捕获描述字
    //const u_char *packet;
    struct pcap_pkthdr hdr = *pkthdr;//(libpcap 自定义数据包头部)，
    struct ether_header *eptr;//以太网字头
    u_char *ptr;
    int i;
 
    if (packet == NULL)//packet里面有内容，可以证明上面的猜想，
    {
        printf ("Didn't grab packet!\n");
        exit (1);
    }
    printf ("\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");
    printf ("Grabbed packet of length %d\n", hdr.len);
    printf ("Received at : %s\n", (char*)ctime((const time_t*)&hdr.ts.tv_sec));
    printf ("Ethernet address length is %d\n", ETHER_HDR_LEN);
    
    eptr = (struct ether_header*)packet;//得到以太网字头
    
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
    {
        printf ("Ethernet type hex:%x dec:%d is an IP packet\n",
                    ntohs(eptr->ether_type), ntohs(eptr->ether_type));
    }
    else 
    {
        if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
        {
            printf ("Ethernet type hex:%x dec:%d is an ARP packet\n",
                        ntohs(eptr->ether_type), ntohs(eptr->ether_type));
        }
        else
        {
            printf ("Ethernet type %x not IP\n", ntohs(eptr->ether_type));
            exit (1);
        }
    }
        
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf ("i=%d\n", i);
    printf ("Destination Address: ");
    do
    {
        printf ("%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    }while(--i>0);
    printf ("\n");
    //printf ("%x\n",ptr);
    
    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf ("Source Address: ");
    do
    {
        printf ("%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    }while(--i>0);
    printf ("\n");
    printf ("Now decoding the IP packet.\n");
    ipptr = (struct iphdr*)    (packet+sizeof(struct ether_header));//得到ip包头
    
    printf ("the IP packets total_length is :%d\n", ipptr->tot_len);
    printf ("the IP protocol is %d\n", ipptr->protocol);
    addr.s_addr = ipptr->daddr;
    printf ("Destination IP: %s\n", inet_ntoa(addr));    
    addr.s_addr = ipptr->saddr;
    printf ("Source IP: %s\n", inet_ntoa(addr));
    
    printf ("Now decoding the TCP packet.\n");
    tcpptr = (struct iphdr*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr));//得到tcp包头
    printf ("Destination port : %d\n", tcpptr->dest);
    printf ("Source port : %d\n", tcpptr->source);
    printf ("the seq of packet is %d\n", tcpptr->seq);
    //以上关于ip、tcp的结构信息请查询/usr/include/linux/ip.h | tcp.h
    
    data = (char*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct tcphdr));//得到数据包里内容，不过一般为乱码。
    
    printf ("the content of packets is \n%s\n",data);
}

int main()
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h                    */
    struct ether_header *eptr;  /* net/ethernet.h            */
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    char filt[20] = "host www.baidu.com";

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { fprintf(stderr,"%s\n",errbuf); exit(1); }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading this time lets set it in promiscuous
     * mode so we can monitor traffic to another machine             */
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    /* Lets try and compile the program.. non-optimized */
/*    if(pcap_compile(descr,&fp,filt,0,netp) == -1)
    { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

     set the compiled program as the filter 
    if(pcap_setfilter(descr,&fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }*/

    /* ... and loop */ 
    pcap_loop(descr,10,my_callback,NULL);

    printf("\nDone!\n");

    return 0;
}
