#include <openfile.h>
#include <QTableWidgetItem>
#include <QDateTime>

Openfile :: Openfile(QObject *parent, QString str):QThread(parent){
    filepath=str;
}

void Openfile :: run(){
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    char*  ch;
    QByteArray ba = filepath.toLatin1(); // must
    ch=ba.data();

    if(pcap_createsrcstr(source,PCAP_SRC_FILE,nullptr,nullptr,ch,errbuf)!=0){
        qDebug("Error creating a source string\n");
    }

    if((fp=pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,nullptr,errbuf))==NULL){
        qDebug("Unabe to open the file\n");
    }
    qDebug("open线程运行成功");

    int packet_number=1;
    while(pcap_next_ex(fp,&header,&pkt_data)>=0){//应当通过信号和槽将信息传递到主线程
        QString Protool;
        QString sourceipstr,desipstr;
        QDateTime time_1= QDateTime::fromTime_t(header->ts.tv_sec);//时间戳转换成QDateTime对象
        Ethernet_header *eh=(Ethernet_header *)pkt_data;
        if(eh->type==0x0008){
            ip_header *ih=(ip_header*)(pkt_data+14);
            switch(ih->proto){
            case TCP: {
                Protool=QString("TCP");
                break;
            }
            case UDP: {
                Protool=QString("UDP");
                break;
            }
            case IGMP: {
                Protool=QString("IGMP");
                break;
            }
            case ICMP: {
                Protool=QString("ICMP");
                break;
            }
            default:
                Protool=QString("Other protool");
            }
            sourceipstr=QString("%1.%2.%3.%4").arg(ih->saddr.byte1).arg(ih->saddr.byte2).arg(ih->saddr.byte3).arg(ih->saddr.byte4);
            desipstr=QString("%1.%2.%3.%4").arg(ih->daddr.byte1).arg(ih->daddr.byte2).arg(ih->daddr.byte3).arg(ih->daddr.byte4);
        }else if(eh->type==0x0608){
            Protool=QString("ARP");
            arp_header * ah=(arp_header *)(pkt_data+14);
            sourceipstr=QString("%1.%2.%3.%4").arg(ah->send_ip.byte1).arg(ah->send_ip.byte2).arg(ah->send_ip.byte3).arg(ah->send_ip.byte4);
            desipstr=QString("%1.%2.%3.%4").arg(ah->target_ip.byte1).arg(ah->target_ip.byte2).arg(ah->target_ip.byte3).arg(ah->target_ip.byte4);
        }else{
            Protool="Unrecognize";
        }
        emit PacketRead(QString("%1").arg(packet_number++),time_1.toString("yyyy-MM-dd hh:mm:ss"),QString::number(header->len),sourceipstr,desipstr, Protool);
    }
}
