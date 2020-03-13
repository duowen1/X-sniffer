#include <intercept.h>
#define HAVE_REMOTE
#include "pcap.h"
#include <QFile>

Intercept :: Intercept(QObject *parent,int ada,QString str):QThread(parent){
    adapter=ada;
    filter_str=str;
}

void Intercept::run(){
    QFile::remove("file.txt");
    pcap_if_t* alldevs;//链表头
    pcap_if_t* d;//头指针
    pcap_t* adhandle;
    struct pcap_pkthdr* header;
    struct bpf_program fcode;
    const u_char* pkt_data;
    int i = 0;
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

    for (d = alldevs, i = 0; i < adapter - 1; d = d->next, i++);//找到需要过滤的网卡
    qDebug("%s,%s",d->name,d->description);

    if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf)) == nullptr) {//打开网卡
        printf("wrong.\n");
        pcap_freealldevs(alldevs);
        return;
    }
    dumpfile = pcap_dump_open(adhandle, "file.txt");
    if (dumpfile == nullptr) {
        qDebug("拦截线程打开文件错误");
        return;
    }

    if (pcap_datalink(adhandle) != DLT_EN10MB)//仅过滤以太网
    {
        qDebug("\nThis program works only on Ethernet networks.\n");
        pcap_freealldevs(alldevs);
        return;
    }

    if (d->addresses != nullptr) {
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else {
        netmask = 0xffffff;
    }
    char*  ch;
    QByteArray ba = filter_str.toLatin1();
    ch=ba.data();
    if (pcap_compile(adhandle, &fcode, ch, 1, netmask) < 0) {
        qDebug("filter wrong1");
        pcap_freealldevs(alldevs);
    }
    if (pcap_setfilter(adhandle, &fcode) < 0) {
        qDebug("filter wrong2");
        pcap_freealldevs(alldevs);
    }
    flag=true;
    int p=1;
    qDebug("拦截线程运行成功");
    while (flag&&(res = pcap_next_ex(adhandle, &header, &pkt_data))>=0) {
        pcap_dump((u_char *)dumpfile, header, pkt_data);
    }
    return;
}

void Intercept::terminatethread(){
    flag=false;
}
