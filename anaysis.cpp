#include <analysis.h>
#include <QVariant>
#include <gloable.h>

Analysis :: Analysis(QObject *parent):QThread(parent){

}

void Analysis :: run(){
    sleep(5);
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    if(pcap_createsrcstr(source,PCAP_SRC_FILE,nullptr,nullptr,"file.txt",errbuf)!=0){
        qDebug("Error creating a source string\n");
    }

    if((fp=pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,nullptr,errbuf))==nullptr){
        qDebug("Unabe to open the file\n");
    }
    flag=true;
    int packet_number=1;
    int res;
    while(flag){//应当通过信号和槽将信息传递到主线程
        mutex_in.lock();
        while((res=pcap_next_ex(fp,&header,&pkt_data))<0);
        struct pcap_pkthdr head_info=*header;
        QVariant DataVar;
        DataVar.setValue(head_info);
        emit HeadInformation(packet_number++,DataVar,(char *)pkt_data);
        qDebug("从文件读出%d",packet_number-1);
        mutex_out.unlock();
    }
}

void Analysis :: terminatethread(){
    flag=false;
}
