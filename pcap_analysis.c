// pcap_analysis.c
#include <stdio.h>
#include <malloc.h>
#include <pcap.h>
#include "protocol.h"

#define IPTOSBUFFERS    12
static char *iptos(bpf_u_int32 in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/*
在以太网中，规定最小的数据包为64个字节，如果数据包不足64字节，则会由网卡填充。
*/

int main(int argc, char const *argv[])
{

    char *filename = "traffic.data";
    FILE *fp = fopen(filename, "r");
    long fileLen = 0;

    struct pcap_pkthdr *pkthdr  = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    ether_header    *segEther   = (ether_header*)malloc(sizeof(ether_header));
    ip_header       *segIP      = (ip_header*)malloc(sizeof(ip_header));
    tcp_header      *segTCP     = (tcp_header*)malloc(sizeof(tcp_header));
    udp_header      *segUDP     = (udp_header*)malloc(sizeof(udp_header));
    u_short pktLen      = 0;
    u_short ipLen_real  = 0;
    u_short tcpLen_real = 0;
    u_short dataLen     = 0;

    // get length of file
    fseek(fp, 0, SEEK_END);
    fileLen = ftell(fp);
    fseek(fp, PCAP_HEADER_LEN, SEEK_SET);
    // 移动文件位置指针。
    // If successful, the function returns zero.
    // Otherwise, it returns non-zero value.
    // SEEK_SET:文件开头;SEEK_CUR:当前位置;SEEK_END:文件结尾

    int i = 0;
    while( ftell(fp) > 0 &&  ftell(fp) < fileLen )
    {
        //printf("\n%d\t", ++i);
        fread(pkthdr, PACKET_HEADER_LEN, 1, fp);
        //printf("%d\t", pkthdr->caplen);
        fread(segEther, ETHER_LEN, 1, fp);
        //printf("%ld\t", ftell(fp));

        fread(segIP, IP_LEN_MIN, 1, fp);
        ipLen_real = (segIP->ver_ihl & 0x0f)*4;
        //printf("iplen:%u\t", ipLen_real);
        pktLen = (u_short)((segIP->tlen) >> 8 | (segIP->tlen) << 8);
        fseek(fp, ipLen_real - IP_LEN_MIN, SEEK_CUR);

        printf("src:%s\t", iptos(segIP->saddr));
        printf("des:%s\t", iptos(segIP->daddr));


        if(segIP->proto == IP_TCP)
        {
            fread(segTCP, TCP_LEN_MIN, 1, fp);
            tcpLen_real = (((segTCP->th_len)>>4) & 0x0f) * 4;
            dataLen = pktLen - ipLen_real - tcpLen_real;
            fseek(fp, dataLen + (tcpLen_real - TCP_LEN_MIN), SEEK_CUR);

            printf("sport:%u\t", (u_short)((segTCP->th_sport) >> 8 | (segTCP->th_sport) << 8));
            printf("dport:%u\t", (u_short)((segTCP->th_dport) >> 8 | (segTCP->th_dport) << 8));
        }
        else if(segIP->proto == IP_UDP)
        {
            fread(segUDP, UDP_LEN, 1, fp);
            dataLen = pktLen - ipLen_real - UDP_LEN;
            fseek(fp, dataLen, SEEK_CUR);

            printf("sport:%u\t", (u_short)((segUDP->uh_sport) >> 8 | (segUDP->uh_sport) << 8));
            printf("dport:%u\t", (u_short)((segUDP->uh_dport) >> 8 | (segUDP->uh_dport) << 8));
        }
    }
    printf("Done!\n");
    return 0;
}
