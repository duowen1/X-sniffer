#include <intercept.h>
#define HAVE_REMOTE
#include "pcap.h"
#include "gloable.h"
Intercept :: Intercept(QObject *parent):QThread(parent){

}

void Intercept::run(){
    pcap_if_t* alldevs;//链表头
    pcap_if_t* d;//头指针
    pcap_t* adhandle;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int i = 0;
    int inum = 4;
    int res;
    u_int netmask;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_dumper_t* dumpfile;

    /* Retrieve the device list */
    if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING,nullptr,&alldevs, errbuf) == -1)//返回网卡列表，alldevs指向表头
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);//找到需要过滤的网卡

    if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf)) == nullptr) {//打开网卡
        printf("wrong.\n");
        pcap_freealldevs(alldevs);
        return;
    }
    dumpfile = pcap_dump_open(adhandle, "file.txt");
    if (dumpfile == nullptr) {
        fprintf(stderr, "\nError opening output file\n");
        return;
    }

    if (pcap_datalink(adhandle) != DLT_EN10MB)//仅过滤以太网
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    if (d->addresses != nullptr) {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else {
        netmask = 0xffffff;
    }

    /*
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
        pcap_freealldevs(alldevs);
        return;
    }

    if (pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    pcap_freealldevs(alldevs);
    */

    flag=true;
    int p=1;
    while (flag&&(res = pcap_next_ex(adhandle, &header, &pkt_data))>=0) {
        pcap_dump((u_char *)dumpfile, header, pkt_data);
        qDebug("写入文件%d",p++);
    }
    return;
}

void Intercept::terminatethread(){
    flag=false;
}
