#include <pcap.h>
#include <stdio.h>
int main()
{
	pcap_t *handle; /* 会话句柄 */
	char *dev; /* 执行嗅探的设备 */
	char errbuf[PCAP_ERRBUF_SIZE]; /* 存储错误信息的字符串 */
	struct bpf_program filter; /* 已经编译好的过滤器 */
	char filter_app[] = "port 53"; /* 过滤表达式 */
	bpf_u_int32 mask; /* 所在网络的掩码 */
	bpf_u_int32 net; /* 主机的IP地址 */
	struct pcap_pkthdr header; /* 由pcap.h定义 */
	const u_char *packet; /* 实际的包 */
	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	/* 探查设备属性 */
	pcap_lookupnet(dev, &net, &mask, errbuf);
	/* 以混杂模式打开会话，准备嗅探 */
	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
	/* 编译并应用过滤器 */
	pcap_compile(handle, &filter, filter_app, 0, net);
	pcap_setfilter(handle, &filter);
	/* 截获一个包 */
	packet = pcap_next(handle, &header);
	/* 打印它的长度 */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* 关闭会话 */
	pcap_close(handle);
	return 0;
}
