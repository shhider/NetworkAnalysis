#include <stdio.h>
#include <pcap.h>
#include "header.h"
#define HASH_TABLE_SIZE 0xffff

/**
一个网络连接的“五”元组，同时是用链表保存时的节点。
因为我们需要的是某个连接的信息，如果以“源”和“目的”来进行hash，则会造成同一个连接，
在hash中存放的位置不同。所以我们以“client”和“server”来进行hash。
通过判断包中本机ip是属于源地址还是目的地址，上传还是下载
*/
typedef struct net_set
{
    u_short  cip_l;     // client IP前16位
    u_short  cip_r;     // client IP后16位
    u_short  cport;     // client 端口
    u_short  sip_l;     // server IP前16位
    u_short  sip_r;     // server IP后16位
    u_short  sport;     // server 端口
    u_char   protocol;  // 连接协议
    // 以上属于连接信息
    u_int    up_size;   // 上传量
    u_int    down_size; // 下载量
    // 上传量、下载量
    net_set  *next;
}NetNode, *pNetSet;

/** hash表 */
pNetSet HashTable[HASH_TABLE_SIZE];


void get5set(const u_char *p_pack)
{
    struct ip_header *seg_ip = (struct ip_header*)(p_pack + ETHER_LEN);
    net5set one_set;
    one_set.set5_saddr = seg_ip->saddr;
    one_set.set5_daddr = seg_ip->daddr;
    one_set.set5_proto = seg_ip->proto;

    int ip_len = ((seg_ip->ver_ihl) & 0x0f) * 4;
    struct tcp_header *seg_tcp = (struct tcp_header*)(p_pack + ETHER_LEN + ip_len);

    u_short src_port = (u_short)((seg_tcp->th_sport) >> 8 | (seg_tcp->th_sport) << 8);
    u_short des_port = (u_short)((seg_tcp->th_dport) >> 8 | (seg_tcp->th_dport) << 8);
    one_set.set5_sport = src_port;
    one_set.set5_dport = des_port;

    disp_net5set(&one_set);
}

void cb_parse(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char* package){
	static id = 0;
	printf("\n\n--------------- 序号: %d --------\n", ++id);
	get5set(package);
}

////////////////////////////////主函数部分
typedef struct run_argv
{
    int runTime;       // 运行总时间
    int runCycle;      // 分析周期
};
run_argv* getArgv(int argv_len, const char* argv)
{
    int i;
    run_argv* RunArgv = (run_argv *)malloc(sizeof(run_argv));
    for(i = 0; i < argv_len; i++)
    {
        switch(argv[i])
        {
            case '-t':
            case '-T':
                RunArgv->runTime = atoi(argv[++i]);
                break;
            case '-c':
            case '-C':
                RunArgv->runCycle = atoi(argv[++i]);
                break;
            default:
                break;
        }
    }

    return RunArgv;
}



int main(){
	char                *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t              *dev_handle;
	bpf_u_int32         net, mask;
	char                packet_filter[] = "tcp";
    struct bpf_program  fcode;
	// struct ether_header *eptr;
	// u_char *ptr;

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

	pcap_loop(dev_handle, 50, cb_parse, NULL);

	// close all handle
    pcap_close(dev_handle);
	printf("\nDone!\n");
	return 0;
}

