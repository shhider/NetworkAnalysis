#include <stdio.h>
#include <pcap.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "protocol.h"
#include "analysis.h"
//#include "parse.h"

char *FileName = NULL;
void clear_file()
{
    FILE *fp = fopen(FileName, "w");
    fclose(fp);
}

anaysis_link_node *AnalysisLink_Head_1;
anaysis_link_node *AnalysisLink_Head_2;
p_analysis_link pCurrentLink;

void add_to_analysis_link(const hash_link_node *ClosedNode)
{
    if(ClosedNode == NULL) { return;}

    anaysis_link_node *AnalysisNode = NULL;
    AnalysisNode = (anaysis_link_node *)malloc(sizeof(anaysis_link_node));

    AnalysisNode->aln_5set      = ClosedNode->hln_5set;
    AnalysisNode->aln_ctime     = ClosedNode->hln_ctime;
    AnalysisNode->aln_dtime     = ClosedNode->hln_dtime;
    AnalysisNode->aln_upl_size  = ClosedNode->hln_upl_size;
    AnalysisNode->aln_downl_size= ClosedNode->hln_downl_size;

    AnalysisNode->next = pCurrentLink->next;
    pCurrentLink->next = AnalysisNode;
}
void save_analysis_link()
{
    printf("Write to file\t");
    p_analysis_link pTemp = pCurrentLink->next;
    pCurrentLink->next = NULL;
    pCurrentLink = (pCurrentLink == AnalysisLink_Head_1) ? AnalysisLink_Head_2 : AnalysisLink_Head_1;

    FILE *fp = fopen(FileName, "a+");   // write only & append

    p_analysis_link temp0 = NULL;
    while( pTemp != NULL )
    {
        fprintf(fp, "%s:", iptos(pTemp->aln_5set.sip));
        fprintf(fp, "%u", pTemp->aln_5set.sport);
        fprintf(fp, " -> %s:", iptos(pTemp->aln_5set.dip));
        fprintf(fp, "%u\t", pTemp->aln_5set.dport);

        if( pTemp->aln_5set.protocol == IP_TCP )
            fprintf(fp, "TCP\t");
        else
            fprintf(fp, "UDP\t");

        fprintf(fp, "start: %s\t", long2time(pTemp->aln_ctime));
        fprintf(fp, "over: %s\t", long2time(pTemp->aln_ctime));
        fprintf(fp, "Upload:%d\t", pTemp->aln_upl_size);
        fprintf(fp, "Download:%d\n", pTemp->aln_downl_size);

        temp0 = pTemp;
        pTemp = pTemp->next;
        free(temp0);
        printf(".");
    }
    fprintf(fp, "\n");
    fclose(fp);
    printf("[\033[32m ok \033[0m]\n");
}

/*=== hash表 ===*/
#define HASH_TABLE_SIZE 0xffff
p_hash_link HashTable[HASH_TABLE_SIZE];

void init_hashtable()
{
    int i;
    for(i = 0; i < HASH_TABLE_SIZE; i++)
    {
        HashTable[i] = NULL;
    }
    printf("HashTable init.........");
    printf("[\033[32m ok \033[0m]\n");
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
void add_to_hashTable(u_short hash, hash_link_node *newNode, u_char flags)
{
    hash_link_node *HashNode = (hash_link_node *)malloc(sizeof(hash_link_node));
    memcpy(HashNode, newNode, sizeof(hash_link_node));

    if(HashTable[hash] == NULL && (flags & TH_FIN) == 0)
    {
        HashTable[hash] = HashNode;
        return;
    }
    hash_link_node *pTemp = HashTable[hash];
    hash_link_node *pBack = pTemp;
    int isSame_up = 0;
    int isSame_down = 0;
    while(pTemp != NULL)
    {
        isSame_up = (pTemp->hln_5set.sip == HashNode->hln_5set.sip)
                && (pTemp->hln_5set.dip == HashNode->hln_5set.dip)
                && (pTemp->hln_5set.sport == HashNode->hln_5set.sport)
                && (pTemp->hln_5set.dport == pTemp->hln_5set.dport);

        isSame_down = (pTemp->hln_5set.dip == HashNode->hln_5set.sip)
                && (pTemp->hln_5set.sip == HashNode->hln_5set.dip)
                && (pTemp->hln_5set.dport == HashNode->hln_5set.sport)
                && (pTemp->hln_5set.sport == pTemp->hln_5set.dport);
        if( isSame_up )
        {
            pTemp->hln_upl_size += HashNode->hln_upl_size;
            /*if(pTemp->hln_status == ESTABLISHED && (flags && TH_FIN))
            {
                pTemp->hln_status = FIN_WAIT_1;
            }
            else if (pTemp->hln_status == TIME_WAIT && flags == TH_ACK)
            {
                pTemp->hln_status = CLOSED;
                if(pBack == HashTable[hash])
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_analysis_link(pTemp);
                free(pTemp);
            }
            else if(pTemp->hln_status == CLOSE_WAIT && flags == TH_FIN)
            {
                pTemp->hln_status = LAST_ACK;
            }*/
            if ((flags & TH_FIN) == 0)
            {
                pTemp->hln_status = CLOSED;
                pTemp->hln_dtime = HashNode->hln_ctime;
                if(pBack == HashTable[hash])
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_analysis_link(pTemp);
                free(pTemp);
            }
            free(HashNode);
            break;
        }
        else if( isSame_down )
        {
            pTemp->hln_downl_size += HashNode->hln_upl_size;
            /*if(pTemp->hln_status == ESTABLISHED && flags == TH_FIN)
            {
                pTemp->hln_status = CLOSE_WAIT;
            }
            else if(pTemp->hln_status == FIN_WAIT_1 && flags == TH_ACK)
            {
                pTemp->hln_status = FIN_WAIT_2;
            }
            else if(pTemp->hln_status == FIN_WAIT_2 && flags == TH_FIN)
            {
                pTemp->hln_status = TIME_WAIT;
            }
            else if(pTemp->hln_status == LAST_ACK && flags == TH_ACK)
            {
                pTemp->hln_status = CLOSED;
                if(pBack == HashTable[hash])
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_analysis_link(pTemp);
                free(pTemp);
            }*/
            if ((flags & TH_FIN) == 0)
            {
                pTemp->hln_status = CLOSED;
                pTemp->hln_dtime = HashNode->hln_ctime;
                if(pBack == HashTable[hash])
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_analysis_link(pTemp);
                free(pTemp);
            }
            free(HashNode);
            break;
        }
        pBack = pTemp;
        pTemp = pTemp->next;
    }
    if(pTemp == NULL && (flags & TH_FIN) == 0)
    {
        pBack->next = HashNode;
    }

}

void *thread_clock(void *argv)
{
    pcap_t *handle = argv;
    int allTime = 30;
    int cycle = 10;

    int i = 0;
    for (i = 0; i < allTime; i += cycle)
    {
        sleep(cycle);
        save_analysis_link();
    }
    pcap_breakloop(handle);
}

void cb_parse(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char* package)
{
    // save packets to binary file
    pcap_dump(dumpfile, pkthdr, package);

	ip_header *seg_ip = (ip_header*)(package + ETHER_LEN);
	// we need tcp or udp data
    u_char proto = seg_ip->proto;
    if(seg_ip->proto != IP_TCP && seg_ip->proto != IP_UDP)
    {
        return;
    }

    net5set one_set;
    one_set.sip = seg_ip->saddr;
    one_set.dip = seg_ip->daddr;
    one_set.protocol = proto;

    int ip_len = ((seg_ip->ver_ihl) & 0x0f) * 4;
    tcp_header *seg_tcp = NULL;
    udp_header *seg_udp = NULL;
    u_short src_port, des_port;
    if(proto == IP_TCP)
    {
        //printf("tcp\t");
        seg_tcp = (tcp_header*)(package + ETHER_LEN + ip_len);
        src_port = (u_short)((seg_tcp->th_sport) >> 8 | (seg_tcp->th_sport) << 8);
        des_port = (u_short)((seg_tcp->th_dport) >> 8 | (seg_tcp->th_dport) << 8);
    }
    else
    {
        //printf("udp\t");
        seg_udp = (udp_header*)(package + ETHER_LEN + ip_len);
        src_port = (u_short)((seg_udp->uh_sport) >> 8 | (seg_udp->uh_sport) << 8);
        des_port = (u_short)((seg_udp->uh_dport) >> 8 | (seg_udp->uh_dport) << 8);
    }
    one_set.sport = src_port;
    one_set.dport = des_port;

    u_short hash = get_hash(&one_set);
    //printf("%u\n", hash);

    hash_link_node *hnode = NULL;
    hnode = (hash_link_node*)malloc(sizeof(hash_link_node));

    hnode->hln_5set      = one_set;
    hnode->hln_ctime     = pkthdr->ts.tv_sec;
    hnode->hln_dtime     = pkthdr->ts.tv_sec;
    hnode->hln_upl_size  = 0;
    hnode->hln_downl_size= 0;
    hnode->hln_status    = UNDEFINED;
    hnode->next          = NULL;
    if(proto == IP_UDP)
    {// 直接放到统计列表里
        hnode->hln_upl_size = seg_udp->uh_len - UDP_LEN;
        add_to_analysis_link(hnode);
    }
    else
    {// 放到hash表里
        printf("this is tcp\n");
        int tcp_len = ((seg_tcp->th_len) & 0x0f) * 4;
        hnode->hln_upl_size = (int)(seg_ip->tlen) - ip_len - tcp_len;
        add_to_hashTable(hash, hnode, seg_tcp->th_flags);
    }
    free(hnode);
}

int main(int argc, char const *argv[])
{
	char                *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t              *dev_handle;
	bpf_u_int32         net, mask;
	char                packet_filter[] = "tcp";
    struct bpf_program  fcode;

    FileName = "store.data";
    clear_file();

    init_hashtable();
    AnalysisLink_Head_1 = (anaysis_link_node *)malloc(sizeof(anaysis_link_node));
    AnalysisLink_Head_1->next = NULL;
    AnalysisLink_Head_2 = (anaysis_link_node *)malloc(sizeof(anaysis_link_node));
    AnalysisLink_Head_2->next = NULL;
    pCurrentLink = AnalysisLink_Head_1;


	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		printf("No Device:%s\n", errbuf);
		return 0;
	} // */
    /*char *wlan_dev = "wlan0";
    dev = wlan_dev; // */
	printf("开始抓取数据，设备:%s\n", dev);

	dev_handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
	if(dev_handle == NULL){
		printf("pcap_open_live:%s\n", errbuf);
		return 0;
	}

	pcap_lookupnet(dev, &net, &mask, errbuf);

	//compile the filter
    if (pcap_compile(dev_handle, &fcode, packet_filter, 1, mask) <0 )
	{
        printf("\nUnable to compile the packet filter. Check the syntax.\n");
        return 0;
    }

    //set the filter
    if (pcap_setfilter(dev_handle, &fcode) < 0)
    {
        printf("\nError setting the filter.\n");
        return 0;
    }

    // open file to save pcap
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(dev_handle, "traffic.data");
    if(dumpfile == NULL){
        printf("\nError opening output file\n");
        return 0;
    }

    pthread_t ptClock;
    if(pthread_create(&ptClock, NULL, thread_clock, dev_handle))
    {
        printf("pthread_create(): Error!\n");
        return -1;
    }
	pcap_loop(dev_handle, -1, cb_parse, (u_char*)dumpfile);

	// close all handle
    pcap_close(dev_handle);
	printf("\nDone!\n");

    //save_analysis_link();

	return 0;
}

