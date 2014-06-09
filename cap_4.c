#include <stdio.h>
#include <pcap.h>
#include "header.h"

void cb_interpret(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char* packet){
	struct ip_header *ip = (struct ip_header *)(packet + ETHER_LEN);
	printf("shit\n");
	printf("%d\n", atoi(ip->proto));
	switch( atoi(ip->proto) ){
		case IP_TCP:
			printf("--------------- TCP -----------------\n");
			break;
		case IP_UDP:
			printf("--------------- UDP -----------------\n");
			break;
		case IP_ICMP:
			printf("--------------- ICMP -----------------\n");
			break;
		case IP_OSPF:
			printf("--------------- OSPF -----------------\n");
			break;
		default:
			printf("--------------- other -----------------\n");
			break;
	}
}
int main(){
	char 				*dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t 				*dev_handle;
	bpf_u_int32 		net, mask;
	char 				packet_filter[] = "ip";
    struct bpf_program 	fcode;
	// struct ether_header *eptr;
	// u_char *ptr;

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		printf("No Device:%s\n", errbuf);
		return 0;
	}
	printf("device:%s\n", dev);

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

	pcap_loop(dev_handle, 10, cb_interpret, NULL);

	printf("done!\n");
	return 0;
}

