#include<stdio.h>
#include<pcap.h>
int main(){
	char *device, *ptr; /* 用来捕获数据包的网络接口的名称 */
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p; /* 捕获数据包句柄，最重要的数据结构 */
	struct bpf_program fcode; /* BPF 过滤代码结构 */

	/* 第一步：查找可以捕获数据包的设备 */
	device = pcap_lookupdev(errbuf);

	/* 第二步：创建捕获句柄，准备进行捕获 */
	p = pcap_open_live(device, 8000, 1, 500, errbuf);

	/* 第三步：如果用户设置了过滤条件，则编译和安装过滤代码 */
	//pcap_compile(p, &fcode, filter_string, 0, netmask)；
	//pcap_setfilter(p, &fcode)；

	/* 第四步：进入（死）循环，反复捕获数据包 */
	for( ; ; ){
		while((ptr = (char *)(pcap_next(p, &hdr))) == NULL);

		/* 第五步：对捕获的数据进行类型转换，转化成以太数据包类型 */
		eth = (struct libnet_ethernet_hdr *)ptr;

		/* 第六步：对以太头部进行分析，判断所包含的数据包类型，做进一步的处理 */
		if(eth->ether_type == ntohs(ETHERTYPE_IP))
			printf("this is IP\n");
		if(eth->ether_type == ntohs(ETHERTYPE_ARP))
			printf("this is ARP\n"); 

	}
		
	/* 最后一步：关闭捕获句柄,一个简单技巧是在程序初始化时增加信号处理函数，
	以便在程序退出前执行本条代码 */
	pcap_close(p);
	return 0;
}
