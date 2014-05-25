#include<stdio.h>
#include<pcap.h>

void myCallback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char* packet){
	static int count = 1;
	printf("%d", count);
	if(count == 4){
		printf("catch 4!\n");
	}
	if(count == 7){
		printf("catch 7!\n");
	}
	count++;
}
int main(){
	int i;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;
	u_char *ptr;
	
	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		printf("No Device:%s\n", errbuf);
		return 0;
	}
	printf("device:%s\n", dev);
	
	descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
	if(descr == NULL){
		printf("pcap_open_live:%s\n", errbuf);
		return 0;
	}

	pcap_loop(descr, 10, myCallback, NULL);

	printf("done!\n");
	return 0;
}

