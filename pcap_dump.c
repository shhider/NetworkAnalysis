#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "header.h"
#include "parse.h"

// callback function of pcap_loop
void getPacket(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    // save packets to binary file
    pcap_dump(dumpfile, pkthdr, packet);
    start_parse(packet);

    /*printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    int i;
    for(i=0; i<pkthdr->len; ++i){
        printf(" %02x", packet[i] );    // X, 以十六进制形式输出;02, 不足两位前面补0输出
        if( (i + 1) % 16 == 0 ){
            printf("\n");
        }
    }
    */
    printf("\n\n");
}

int main(){
    char errBuf[PCAP_ERRBUF_SIZE];
    char *dev;
    bpf_u_int32 net;            // IP address
    bpf_u_int32 mask;           // subnet mask
    pcap_t *dev_hdl;            // device handle
    struct bpf_program filter;
    char filter_app[] = "ip";

    // get a dev_hdl
    dev = pcap_lookupdev(errBuf);
    if(dev){
        printf("success: device: %s\n", dev);
    }else{
        printf("Error at pcap_lookupdev(): %s\n", errBuf);
        exit(1);
    }

    // get net info
    pcap_lookupnet(dev, &net, &mask, errBuf);

    // open a dev_hdl, prepare to catch packet
    dev_hdl = pcap_open_live(dev, BUFSIZ, 1, 0, errBuf);
    if(!dev_hdl){
        printf("Error at pcap_open_live(): %s\n", errBuf);
        exit(1);
    }

    // compile filter
    pcap_compile(dev_hdl, &filter, filter_app, 0, net);
    pcap_setfilter(dev_hdl, &filter);

    // open file to save pcap
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(dev_hdl, "traffic.data");
    if(dumpfile == NULL){
        printf("\nError opening output file\n");
        exit(1);
    }
    // */

    // begin to catch packet
    // the second param is num of packets
    pcap_loop(dev_hdl, 10, getPacket, (u_char*)dumpfile);

    // close all handle
    pcap_dump_close(dumpfile);
    pcap_close(dev_hdl);
    return 0;
}
