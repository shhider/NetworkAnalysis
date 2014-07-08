// pcap_analysis.c
#include <stdio.h>
#include <malloc.h>
#include <time.h>
#include <string.h>
#include <pcap.h>
#include "protocol.h"


//timeval结构
typedef struct _shh_timeval{
    int tv_sec;        /* seconds 1900之后的秒数 */
    int tv_usec;      /* and microseconds */
}shh_timeval;

// pcap_next()方法执行后，pcap_pkthdr类型的指针指向抓包的信息
typedef struct _shh_pkthdr {
    shh_timeval ts;  /* time stamp 时间 */
    bpf_u_int32 caplen; /* length of portion present 包的数据长度？？ */
    bpf_u_int32 len;    /* length this packet (off wire) 包的实际长度  */
}shh_pkthdr;

typedef struct _net5set
{
    u_int       sip;
    u_short     sport;
    u_int       dip;
    u_short     dport;
    u_char      protocol;
}net5set;

typedef struct _net_link_node
{
    net5set nln_5set;
    int     nln_upl_size;
    int     nln_downl_size;
    int     nln_upl_pkt;
    int     nln_downl_pkt;
    u_char  nln_status;
    #define CLOSED      0x00
    #define SYN_SENT    0x01    // client sent SYN
    #define SYN_RECVD   0x02    // recieve SYN, and send SYN ACK
    #define ESTABLISHED 0x03    // client get SYN & ACK, server get ACK

    #define FIN_WAIT_1  0x04    // client send FIN
    #define CLOSE_WAIT  0x05    // server recv FIN, and send ACK
    #define FIN_WAIT_2  0x06    // client recv ACK
    #define LAST_ACK    0x07    // server send FIN
    #define TIME_WAIT   0x08    // client recv FIN
    // CLOSED: client send ACK, server recv ACK
    #define UNDEFINED   0xff
    struct  _net_link_node *next;
}net_link_node, *p_net_link;

typedef struct _net_link_header
{
    int count_conn;
    int count_upl_pkt;
    int count_downl_pkt;
    int count_upl;
    int count_downl;
    p_net_link link;
}net_link_header;


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

char *long2time(long ltime)
{
    time_t t;
    struct tm *p;
    static char s[100];

    t = ltime;
    p = gmtime(&t);

    strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", p);
    return s;
}

// 需要三个链表，一个哈希链表，保存处于连接状态的包
// 另两个链表分别保存tcp和udp的流量
net_link_header *FLowLink_TCP;
net_link_header *FLowLink_UDP;

/* ========== hash table ============= */
#define HASH_TABLE_SIZE 0xffff
p_net_link HashTable[HASH_TABLE_SIZE];

void init_flowLink(net_link_header *head)
{
    head->count_conn        = 0;
    head->count_upl_pkt     = 0;
    head->count_downl_pkt   = 0;
    head->count_upl         = 0;
    head->count_downl       = 0;
    head->link              = NULL;
}

void add_to_flowLink(net_link_header *head, const net_link_node *theNode)
{
    net_link_node *newNode = (net_link_node *)malloc(sizeof(net_link_node));
    memcpy(newNode, theNode, sizeof(net_link_node));

    head->count_conn ++;
    head->count_upl_pkt     += newNode->nln_upl_pkt;
    head->count_downl_pkt   += newNode->nln_downl_pkt;
    head->count_upl         += newNode->nln_upl_size;
    head->count_downl       += newNode->nln_downl_size;

    newNode->next = head->link;
    head->link = newNode;
}

void clear_flowLink(net_link_header *head)
{
    if( head->link == NULL ){ return;}

    net_link_node *pTemp1 = NULL;
    net_link_node *pTemp2 = NULL;

    pTemp1 = head->link;
    pTemp2 = pTemp1->next;
    while( pTemp2 != NULL )
    {
        free(pTemp1);
        pTemp1 = pTemp2;
        pTemp2 = pTemp1->next;
    }
    free(pTemp1);

    head->link = NULL;
}

void parse_flowLink_TCP(FILE *fOutput)
{
    fprintf(fOutput, "TCP连接个数：\t%d\n", FLowLink_TCP->count_conn);
    fprintf(fOutput, "TCP数据包个数：\t%d\n", FLowLink_TCP->count_upl_pkt + FLowLink_TCP->count_upl_pkt);
    fprintf(fOutput, "TCP数据总流量：\t%d bytes\n", FLowLink_TCP->count_upl + FLowLink_TCP->count_downl);
    fprintf(fOutput, "TCP数据上传量：\t%d bytes\n", FLowLink_TCP->count_upl);
    fprintf(fOutput, "TCP数据下载量：\t%d bytes\n", FLowLink_TCP->count_downl);
    fprintf(fOutput, "-----------------------\n");

    net_link_node *pTemp = NULL;
    pTemp = FLowLink_TCP->link;
    while( pTemp != NULL )
    {
        fprintf(fOutput, "%s\t%u\t", iptos(pTemp->nln_5set.sip), pTemp->nln_5set.sport);
        fprintf(fOutput, "==>\t%s\t%u\t", iptos(pTemp->nln_5set.dip), pTemp->nln_5set.dport);
        fprintf(fOutput, "上传包数量：%d\t", pTemp->nln_upl_pkt);
        fprintf(fOutput, "下载包数量：%d\t", pTemp->nln_downl_pkt);
        fprintf(fOutput, "upload：%d bytes\t", pTemp->nln_upl_size);
        fprintf(fOutput, "download：%d bytes\t", pTemp->nln_downl_size);
        fprintf(fOutput, "\n");
        pTemp = pTemp->next;
    }

    clear_flowLink(FLowLink_TCP);

}

void parse_flowLink_UDP(FILE *fOutput)
{
    fprintf(fOutput, "UDP数据包个数：\t%d\n", FLowLink_UDP->count_upl_pkt + FLowLink_UDP->count_upl_pkt);
    fprintf(fOutput, "UDP数据流量：\t%d bytes\n", FLowLink_UDP->count_upl + FLowLink_UDP->count_downl);
    clear_flowLink(FLowLink_UDP);
}



u_short get_ushort_net(u_short virtu)
{
    return (u_short)(virtu >> 8 | virtu << 8);
}



u_short get_hash(const net5set *theSet)
{
    u_int srcIP = theSet->sip;
    u_int desIP = theSet->dip;
    u_int port  = (u_int)(theSet->sport * theSet->dport);
    u_int res   = (srcIP^desIP)^port;
    u_short hash= (u_short)((res & 0x00ff)^(res >> 16));
    return hash;
}

void add_to_hashTable(u_short hash, const net_link_node *theNode, u_char flags)
{
    net_link_node *HashNode = (net_link_node *)malloc(sizeof(net_link_node));
    memcpy(HashNode, theNode, sizeof(net_link_node));

    if(HashTable[hash] == NULL)
    {
        HashTable[hash] = HashNode;
        return;
    }
    net_link_node *pTemp = HashTable[hash];
    net_link_node *pBack = NULL;
    int isSame_up = 0;
    int isSame_down = 0;
    while(pTemp != NULL)
    {
        isSame_up = (pTemp->nln_5set.sip == HashNode->nln_5set.sip)
                && (pTemp->nln_5set.dip == HashNode->nln_5set.dip)
                && (pTemp->nln_5set.sport == HashNode->nln_5set.sport)
                && (pTemp->nln_5set.dport == HashNode->nln_5set.dport);

        isSame_down = (pTemp->nln_5set.dip == HashNode->nln_5set.sip)
                && (pTemp->nln_5set.sip == HashNode->nln_5set.dip)
                && (pTemp->nln_5set.dport == HashNode->nln_5set.sport)
                && (pTemp->nln_5set.sport == HashNode->nln_5set.dport);
        if( isSame_up )
        {
            pTemp->nln_upl_size += HashNode->nln_upl_size;
            pTemp->nln_upl_pkt ++;
            if(pTemp->nln_status == ESTABLISHED && (flags & TH_FIN) )
            {
                pTemp->nln_status = FIN_WAIT_1;
            }
            else if (pTemp->nln_status == TIME_WAIT && (flags & TH_ACK))
            {
                pTemp->nln_status = CLOSED;
                if(pBack == NULL)
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_flowLink(FLowLink_TCP, pTemp);
                free(pTemp);
            }
            else if(pTemp->nln_status == CLOSE_WAIT && (flags & TH_FIN))
            {
                pTemp->nln_status = LAST_ACK;
            }
            free(HashNode);
            break;
        }
        else if( isSame_down )
        {
            pTemp->nln_downl_size += HashNode->nln_upl_size;
            pTemp->nln_downl_pkt ++;
            if(pTemp->nln_status == ESTABLISHED && (flags & TH_FIN))
            {
                pTemp->nln_status = CLOSE_WAIT;
            }
            else if(pTemp->nln_status == LAST_ACK && (flags & TH_ACK))
            {
                pTemp->nln_status = CLOSED;
                if(pBack == NULL)
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_flowLink(FLowLink_TCP, pTemp);
                free(pTemp);
            }
            else if(pTemp->nln_status == FIN_WAIT_1 && (flags & TH_ACK))
            {
                pTemp->nln_status = FIN_WAIT_2;
            }
            else if(pTemp->nln_status == FIN_WAIT_2 && (flags & TH_FIN))
            {
                pTemp->nln_status = TIME_WAIT;
            }

            free(HashNode);
            break;
        }
        pBack = pTemp;
        pTemp = pTemp->next;
    }
    if(pTemp == NULL)
    {
        pBack->next = HashNode;
    }
}

void clear_hashTable()
{
    int i = 0;
    net_link_node *pTemp1 = NULL;
    net_link_node *pTemp2 = NULL;
    for(i = 0; i < HASH_TABLE_SIZE; i++)
    {
        if(HashTable[i] == NULL){ continue;}

        pTemp1 = HashTable[i];
        while(pTemp1 != NULL)
        {
            pTemp2 = pTemp1->next;
            add_to_flowLink(FLowLink_TCP, pTemp1);
            free(pTemp1);
            pTemp1 = pTemp2;
        }
        HashTable[i] = NULL;
    }
}



/*
在以太网中，规定最小的数据包为64个字节，如果数据包不足64字节，则会由网卡填充。
*/

int main(int argc, char const *argv[])
{
    char *file_output = "result.data";
    FILE *fOutput = fopen(file_output, "w");
    fclose(fOutput);        // clear file
    fOutput = fopen(file_output, "a+");

    char *filename = "traffic.data";
    fprintf(fOutput, "数据文件：%s\n", filename);

    printf("载入文件...\n");
    FILE *fp = fopen(filename, "r");

    shh_pkthdr      *pkthdr     = (shh_pkthdr *)malloc(sizeof(shh_pkthdr));
    ether_header    *segEther   = (ether_header*)malloc(sizeof(ether_header));
    ip_header       *segIP      = (ip_header*)malloc(sizeof(ip_header));
    tcp_header      *segTCP     = (tcp_header*)malloc(sizeof(tcp_header));
    udp_header      *segUDP     = (udp_header*)malloc(sizeof(udp_header));
    net5set         *Cur5Set    = (net5set *)malloc(sizeof(net5set));
    net_link_node   *LinkNode   = (net_link_node *)malloc(sizeof(net_link_node));

    FLowLink_TCP = (net_link_header *)malloc(sizeof(net_link_header));
    init_flowLink(FLowLink_TCP);
    FLowLink_UDP = (net_link_header *)malloc(sizeof(net_link_header));
    init_flowLink(FLowLink_UDP);

    long    fileLen     = 0;
    int     pktLen      = 0;    // pktLen = Ether + IP
    int     trailerLen  = 0;
    u_short ipLen_real  = 0;
    u_short ipLen_total = 0;
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

    fread(pkthdr, PACKET_HEADER_LEN, 1, fp);
    fseek(fp, - PACKET_HEADER_LEN, SEEK_CUR);
    int tstamp_start    = pkthdr->ts.tv_sec;
    int tstamp_offset   = tstamp_start;
    int tstamp_now      = tstamp_start;
    int cycle           = atoi(argv[1]);
    cycle = (cycle > 0) ? cycle : 10;
    fprintf(fOutput, "分析周期：%d s\n", cycle);

    int i = 0;
    while( ftell(fp) > 0 &&  ftell(fp) < fileLen )
    {
        fread(pkthdr, PACKET_HEADER_LEN, 1, fp);
        pktLen = pkthdr->caplen;
        tstamp_now = pkthdr->ts.tv_sec;
        if(tstamp_now - tstamp_offset >= cycle)
        {
            fprintf(fOutput, "\n\n>>>>> 时间段：%s", long2time(tstamp_offset));
            fprintf(fOutput, " --> %s\n", long2time(tstamp_offset + cycle));

            fprintf(fOutput, "----------------------\n");
            clear_hashTable();
            parse_flowLink_UDP(fOutput);
            init_flowLink(FLowLink_UDP);

            fprintf(fOutput, "----------------------\n");
            parse_flowLink_TCP(fOutput);
            init_flowLink(FLowLink_TCP);
            tstamp_offset = tstamp_now;

        }
        //printf("%d\t", pktLen);
        //printf("\n%d\t", ++i);

        fread(segEther, ETHER_LEN, 1, fp);
        if( get_ushort_net(segEther->type) != ETHER_TYPE_IP )
        {
            //printf("------\t");
            fseek(fp, pktLen - ETHER_LEN, SEEK_CUR);
            continue;
        }

        fread(segIP, IP_LEN_MIN, 1, fp);
        ipLen_real = (segIP->ver_ihl & 0x0f)*4;
        ipLen_total = get_ushort_net(segIP->tlen);
        trailerLen = pktLen - ETHER_LEN - ipLen_total;
        fseek(fp, ipLen_real - IP_LEN_MIN, SEEK_CUR);

        if( segIP->proto != IP_TCP && segIP->proto != IP_UDP )
        {
            //printf("------\t");
            fseek(fp, ipLen_total - ipLen_real + trailerLen, SEEK_CUR);
            continue;
        }

        Cur5Set->sip = segIP->saddr;
        Cur5Set->dip = segIP->daddr;
        Cur5Set->protocol = segIP->proto;
        //printf("src:%s\t", iptos(Cur5Set->sip));
        //printf("des:%s\t", iptos(Cur5Set->dip));

        if(segIP->proto == IP_TCP)
        {
            //printf("TCP\t");
            fread(segTCP, TCP_LEN_MIN, 1, fp);
            tcpLen_real = (((segTCP->th_len)>>4) & 0x0f) * 4;
            dataLen = ipLen_total - ipLen_real - tcpLen_real;

            Cur5Set->sport = get_ushort_net(segTCP->th_sport);
            Cur5Set->dport = get_ushort_net(segTCP->th_dport);

            fseek(fp, (tcpLen_real - TCP_LEN_MIN) + dataLen + trailerLen, SEEK_CUR);
        }
        else if(segIP->proto == IP_UDP)
        {
            //printf("UDP\t");
            fread(segUDP, UDP_LEN, 1, fp);
            dataLen = ipLen_total - ipLen_real - UDP_LEN;

            Cur5Set->sport = get_ushort_net(segUDP->uh_sport);
            Cur5Set->dport = get_ushort_net(segUDP->uh_dport);

            fseek(fp, dataLen + trailerLen, SEEK_CUR);
        }
        LinkNode->nln_5set      = *Cur5Set;
        LinkNode->nln_upl_size  = dataLen;
        LinkNode->nln_downl_size= 0;
        LinkNode->nln_upl_pkt   = 1;
        LinkNode->nln_downl_pkt = 0;
        LinkNode->nln_status    = ESTABLISHED;
        LinkNode->next          = NULL;

        if(segIP->proto == IP_TCP)
        {
            add_to_hashTable(get_hash(Cur5Set), LinkNode, segTCP->th_flags);
        }
        else
        {
            add_to_flowLink(FLowLink_UDP, LinkNode);
        }
    }
    fprintf(fOutput, "\nover\n");

    free(pkthdr);
    free(segEther);
    free(segIP);
    free(segTCP);
    free(segUDP);
    free(Cur5Set);
    free(LinkNode);
    free(FLowLink_TCP);
    free(FLowLink_UDP);
    fclose(fOutput);

    printf("Done!\n");
    return 0;
}
