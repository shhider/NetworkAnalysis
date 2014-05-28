#include <pcap.h>
#include <stdio.h>
int main()
{
	// 存放错误信息，PCAP_ERRBUF_SIZE就是需要的长度
	char errbuf[PCAP_ERRBUF_SIZE];
	// ==========================================================
	char *dev;
	// 取得设备名
	// 貌似会自动取第一个……
	dev = pcap_lookupdev(errbuf);
	// ==========================================================
	// bpf_u_int32 其实就是u_int，unsigned int
	bpf_u_int32 mask;
	bpf_u_int32 net;
	// 主要是取得ip和子网掩码，分别在net和mask里
	pcap_lookupnet(dev, &net, &mask, errbuf);
	//==========================================================
	// 一个包捕捉句柄，类似文件操作函数使用的文件句柄
	pcap_t *handle;
	// 打开会话，准备嗅探
	handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
	// =========================================================
	// 过滤器的结构体
	struct bpf_program filter; /* 已经编译好的过滤器 */
	char filter_app[] = "port 53"; /* 过滤表达式 */
	// 编译并应用过滤器，都用到上面生成的句柄
	pcap_compile(handle, &filter, filter_app, 0, net);
	pcap_setfilter(handle, &filter);
	// =========================================================
	// pcap_pkthdr结构体存放包的信息
	struct pcap_pkthdr header;
	const u_char *packet;
	// 开始抓包，下面的方法每次抓一个包，返回值就是包的内容所在缓冲区的位置指针
	// 可以用循环使运行直到抓到包
	while( (packet = pcap_next(handle, &header)) == NULL );
	// 接着可以对包进行处理
	// =========================================================
	/* 关闭会话 */
	pcap_close(handle);
	return 0;
}
