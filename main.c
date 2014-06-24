#include <stdio.h>
#include <pcap.h>
#include "header.h"
#include "parse.h"

void cb_parse(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char* package){
	static id = 0;
	printf("\n\n--------------- 序号: %d --------\n", ++id);
	start_parse(package);
}
int main(){
	char                *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t              *dev_handle;
	bpf_u_int32         net, mask;
	char                packet_filter[] = "ip";
    struct bpf_program  fcode;
	// struct ether_header *eptr;
	// u_char *ptr;

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		printf("No Device:%s\n", errbuf);
		return 0;
	}
    /*char *wlan_dev = "wlan0";
    dev = wlan_dev;*/
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
    pcap_dump_close(dumpfile);
    pcap_close(dev_hdl);

	printf("\nDone!\n");
	return 0;
}

