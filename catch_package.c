#include <stdio.h>
#include <pcap.h>
#include <pthread.h>
//#include "protocol.h"

typedef struct _argument
{
    pcap_t *handle;
    int timeLen;
}argument;

/*#define IPTOSBUFFERS    12
static char *iptos(bpf_u_int32 in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}*/

void *thread_clock(void *argv)
{
    pcap_t *handle = ((argument*)argv)->handle;
    int timeLen = ((argument*)argv)->timeLen;  // set time
    sleep(timeLen);
    pcap_breakloop(handle);
}

void cb_getPacket(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // ip_header *seg_ip = (ip_header*)(package + ETHER_LEN);
    pcap_dump(dumpfile, pkthdr, packet);

    static int id = 0;
    printf(".  ");
    if(++id % 30 == 0)
    {
        printf("\n");
    }
}


int main(int argc, char const *argv[])
{
    char                *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t              *dev_handle;
    bpf_u_int32         net, mask;
    char                packet_filter[] = "ip";
    struct bpf_program  fcode;

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
    //args->handle = dev_handle;

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

    // build a new thread
    pthread_t ptClock;
    argument args;
    args.handle = dev_handle;
    int argv_time = atoi(argv[1]);
    args.timeLen = (argv_time > 0) ? argv_time : 60;
    printf("抓取时长：%d s\n", argv_time);
    if(pthread_create(&ptClock, NULL, thread_clock, &args))
    {
        printf("pthread_create(): Error!\n");
        return -1;
    }
    pcap_loop(dev_handle, -1, cb_getPacket, (u_char*)dumpfile);

    // close all handle
    pcap_dump_close(dumpfile);
    pcap_close(dev_handle);
    printf("\nDone!\n");
    return 0;
}
