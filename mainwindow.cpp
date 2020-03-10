#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QDateTime>
#define HAVE_REMOTE
#include "pcap.h"
#include "dialog.h"
#include "dialog_2.h"
#define LINE_LEN 16

#include <gloable.h>
#include <QFile>
#include <QFileDialog>



typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;


typedef struct arp_header
{
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_size;
    u_char protocol_size;
    u_short opcode;
    u_char  send_mac[6];
    ip_address send_ip;
    u_char  target_mac[6];
    ip_address  target_ip;
}arp_header;


typedef struct Ethernet_header {
    u_char DesMAC[6];
    u_char SourMAC[6];
    u_short type;
}Ethernet_header;

typedef struct ip_header {
    u_char ver_ihl;//1个字节，4bit版本、4bit头部长度
    u_char tos;//1个字节服务类型type of service
    u_short tlen;//2个字节，包长度的字节数
    u_short identification;//2个字节，表示符
    u_short flags_fo;//2个字节，3bit标记位、13bit片偏移
    u_char ttl;//1个字节，生存期
    u_char proto;//1个字节，协议
    u_short crc;//2个字节，crc校验
    ip_address saddr;//4个字节，源地址
    ip_address daddr;//4个字节，目的地址
    u_int op_pad;//4个字节，可选项和填充共计4字节
}ip_header;

typedef struct tcp_header
{
 u_short m_sSourPort;// 源端口号16bit
 u_short m_sDestPort;// 目的端口号16bit
 u_int m_uiSequNum;// 序列号32bit
 u_int m_uiAcknowledgeNum;// 确认号32bit
 u_short m_sHeaderLenAndFlag;// 前4位：TCP头长度；中6位：保留；后6位：标志位
 u_short m_sWindowSize;// 窗口大小16bit
 u_short m_sCheckSum;// 检验和16bit
 u_short m_surgentPointer;// 紧急数据偏移量16bit
}tcp_header;

typedef struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    //初始化统计变量
    row=0;
    tcps=0;
    udps=0;
    arps=0;
    ips=0;
    icmps=0;
    igmps=0;
    //QFile::remove("file.txt");
    //窗口设为不可变
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setMinimumSize(QSize(1100,550));  // QSize parameters come from accurate comput
    setMaximumSize(QSize(1100,550));

    //UI界面初始化
    ui->setupUi(this);
    ui->tableWidget->setColumnCount(6);
    ui->tableWidget->setHorizontalHeaderLabels(QStringList()<<"Num"<<"Time"<<"Len"<<"Source_IP"<<"Destination_IP"<<"Protool");

    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->tableWidget->horizontalHeader()->setDefaultAlignment(Qt::AlignHCenter);
    ui->pushButton_3->setEnabled(false);
    ui->action_4->setEnabled(false);
    ui->action_start->setEnabled(false);

    //启动拦截线程
    inter=new Intercept(this);
    inter->start();

    anal=new Analysis(this);//创建分析线程
    connect(anal,SIGNAL(HeadInformation(int,QVariant,char *)),this,SLOT(UpdateHead(int,QVariant,char *)));//分析线程、主线程同步
    QObject::connect(ui->tableWidget,SIGNAL(cellClicked(int,int)),this,SLOT(RecordCell(int,int)));//点击查看详情

    //终止线程：连接信号和槽
    connect(this,SIGNAL(stopanalysis()),anal,SLOT(terminatethread()));
    connect(this,SIGNAL(stopintercept()),inter,SLOT(terminatethread()));

    //启动分析线程
    anal->start();
}

MainWindow::~MainWindow()
{
    on_pushButton_clicked();
    delete ui;
}

void MainWindow::on_actionexit_triggered()//退出
{
    on_pushButton_clicked();
    exit(0);
}

void MainWindow::RecordCell(int rowi,int colunm){//查看详细
    qDebug("详细查看第%d个数据\n",rowi);
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char source[PCAP_BUF_SIZE];
    const u_char *pkt_data;
    pcap_createsrcstr(source,PCAP_SRC_FILE,nullptr,nullptr,"file.txt",errbuf);
    fp=pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,nullptr,errbuf);
    struct pcap_pkthdr *header;

    pcap_next_ex(fp,&header,&pkt_data);
    for(int i=0;i<rowi;i++){
        pcap_next_ex(fp,&header,&pkt_data);
    }
    QString str;
    Ethernet_header *eh=(Ethernet_header *)pkt_data;
    if(eh->type==0x0008){//是IP协议
        ip_header *ih=(ip_header*)(pkt_data+14);//剥去以太头
        QString version=QString("版本 %1\n").arg((ih->ver_ihl)>>4);
        QString header_length=QString("头部长  %1\n").arg(((ih->ver_ihl)&0xF)*4);
        QString total_length=QString("总长度   %1\n").arg(ih->tlen);
        QString identification=QString("标识符 0x")+QString::number(zijiexu(ih->identification),16)+"\n";
        QString flags=QString("保留字 [%1]   不分片 [%2]  更多片 [%3]\n").arg(zijiexu(ih->flags_fo)&0x80>>7).arg(zijiexu(ih->flags_fo)&0x40>>6).arg(zijiexu(ih->flags_fo)&0x20>>5);
        QString TTL=QString("生存期 %1\n").arg(ih->ttl);
        QString fragment_offset;
        QString Protool=QString("协议 ")+ToString(ih->proto);
        QString sour_ip=QString("\n源IP %1.%2.%3.%4\n").arg(ih->saddr.byte1).arg(ih->saddr.byte2).arg(ih->saddr.byte3).arg(ih->saddr.byte4);
        QString des_ip=QString("目的IP    %1.%2.%3.%4\n").arg(ih->daddr.byte1).arg(ih->daddr.byte2).arg(ih->daddr.byte3).arg(ih->daddr.byte4);
        str+=version+header_length+total_length+identification+flags+TTL+Protool+sour_ip+des_ip;
        if(ih->proto==TCP){//如果是TCP协议
            tcp_header * th=(tcp_header *)((char *)ih+((ih->ver_ihl)&0xF)*4);
            str+=QString("源端口   %1\n").arg(zijiexu(th->m_sSourPort));
            str+=QString("目的端口  %1\n").arg(zijiexu(th->m_sDestPort));
            str+=QString("序列号   %1\n").arg(tozijiexu(th->m_uiSequNum));
            str+=QString("确认号   %1\n").arg(tozijiexu(th->m_uiAcknowledgeNum));
            th->m_sHeaderLenAndFlag=zijiexu(th->m_sHeaderLenAndFlag);
            str+=QString("长度 %1\n").arg(th->m_sHeaderLenAndFlag>>10);
            str+=QString("FALGS:\nURG[%1]").arg((th->m_sHeaderLenAndFlag&0x20)>>5);
            str+=QString("  ACK[%1]").arg((th->m_sHeaderLenAndFlag&0x10)>>4);
            str+=QString("  PSH[%1]").arg((th->m_sHeaderLenAndFlag&0x8)>>3);
            str+=QString("  RST[%1]").arg((th->m_sHeaderLenAndFlag&0x4)>>2);
            str+=QString("  SYN[%1]").arg((th->m_sHeaderLenAndFlag&0x2)>>1);
            str+=QString("  FIN[%1]\n").arg(th->m_sHeaderLenAndFlag&0x1);
        }else if(ih->proto==UDP){
            str+=QString("UDP协议\n");
            udp_header *uh=(udp_header *)((char *)ih+((ih->ver_ihl)&0xF)*4);
            str+=QString("源端口 %1\n").arg(zijiexu(uh->sport));
            str+=QString("目的端口 %2\n").arg(zijiexu(uh->dport));
        }else if(ih->proto==ICMP){
            str+=QString("ICMP协议\n");

        }else if(ih->proto==IGMP){
            str+=QString("IGMP协议\n");
        }
    }else if(eh->type==0x0608){
        str+=QString("ARP协议\n");
        arp_header* ah = (arp_header*)(pkt_data + 14);
        str+=QString("源IP   %1.%2.%3.%4\n").arg(ah->send_ip.byte1).arg(ah->send_ip.byte2).arg(ah->send_ip.byte3).arg(ah->send_ip.byte4);
        str+=QString("目的IP   %1.%2.%3.%4\n").arg(ah->target_ip.byte1).arg(ah->target_ip.byte2).arg(ah->target_ip.byte3).arg(ah->target_ip.byte4);
    }
    ui->textBrowser->setText(str);
}

QString MainWindow::ToString(const int protool){
    switch(protool){
    case TCP: return QString("TCP");
    case UDP: return QString("UDP");
    case IGMP: return QString("IGMP");
    case ICMP: return QString("ICMP");
    }
    return QString("Other protool");
}

void MainWindow::on_pushButton_clicked()//终止两个线程
{
    emit stopintercept();
    emit stopanalysis();//发信号
    QString str("已停止拦截");
    ui->textBrowser->setText(str);
    ui->pushButton_3->setEnabled(true);
    ui->action_4->setEnabled(true);
    ui->pushButton->setEnabled(true);
    ui->action_stop->setEnabled(true);
    ui->filter_button->setEnabled(true);
}

void MainWindow::UpdateHead(int packet_number,QVariant Vhead_info,char * pkt_data){
    mutex_out.lock();
    struct pcap_pkthdr head_info=Vhead_info.value<struct pcap_pkthdr>();
    ui->tableWidget->setRowCount(row+1);
    QTableWidgetItem *number=new QTableWidgetItem(QString("%1").arg(packet_number));
    ui->tableWidget->setItem(row,0,number);
    QDateTime time_1= QDateTime::fromTime_t(head_info.ts.tv_sec);//时间戳转换成QDateTime对象
    QTableWidgetItem *time=new QTableWidgetItem(time_1.toString("yyyy-MM-dd hh:mm:ss"));
    QTableWidgetItem *len=new QTableWidgetItem(QString::number(head_info.len));
    ui->tableWidget->setItem(row,1,time);
    ui->tableWidget->setItem(row,2,len);
    Ethernet_header *eh=(Ethernet_header *)pkt_data;
    if(eh->type==0x0008){
        ips++;
        ip_header *ih=(ip_header*)(pkt_data+14);
        u_char protool=ih->proto;
        QString Protool=ToString(ih->proto);
        QTableWidgetItem *pro=new QTableWidgetItem(Protool);
        pro->setBackground(QBrush(QColor(Qt::darkGreen)));
        ui->tableWidget->setItem(row,5,pro);
        QString sourceip=QString("%1.%2.%3.%4").arg(ih->saddr.byte1).arg(ih->saddr.byte2).arg(ih->saddr.byte3).arg(ih->saddr.byte4);
        QTableWidgetItem *SourceIp=new QTableWidgetItem(sourceip);
        ui->tableWidget->setItem(row,3,SourceIp);
        QString desip=QString("%1.%2.%3.%4").arg(ih->daddr.byte1).arg(ih->daddr.byte2).arg(ih->daddr.byte3).arg(ih->daddr.byte4);
        QTableWidgetItem *DesIp=new QTableWidgetItem(desip);
        ui->tableWidget->setItem(row,4,DesIp);
        if(ih->proto==TCP) tcps++;
        if(ih->proto==UDP) udps++;
        if(ih->proto==ICMP) icmps++;
        if(ih->proto==IGMP) igmps++;
    }else if(eh->type==0x0608){
        arps++;
        arp_header * ah=(arp_header *)(pkt_data+14);
        QString sourceip=QString("%1.%2.%3.%4").arg(ah->send_ip.byte1).arg(ah->send_ip.byte2).arg(ah->send_ip.byte3).arg(ah->send_ip.byte4);
        QTableWidgetItem *SourceIp=new QTableWidgetItem(sourceip);
        ui->tableWidget->setItem(row,3,SourceIp);
        QString desip=QString("%1.%2.%3.%4").arg(ah->target_ip.byte1).arg(ah->target_ip.byte2).arg(ah->target_ip.byte3).arg(ah->target_ip.byte4);
        QTableWidgetItem *DesIp=new QTableWidgetItem(desip);
        ui->tableWidget->setItem(row,4,DesIp);
        QTableWidgetItem *pro=new QTableWidgetItem("ARP");
        pro->setBackground(QBrush(QColor(Qt::lightGray)));
        ui->tableWidget->setItem(row,5,pro);
    }else{
        QTableWidgetItem *pro=new QTableWidgetItem("Unrecognized");
        ui->tableWidget->setItem(row,5,pro);
    }
    row++;
    mutex_in.unlock();
}

u_short MainWindow::zijiexu(u_short port){
    u_short temp = port << 8;
    return temp | ((port) >> 8);
}

void MainWindow::on_pushButton_2_clicked()//统计数据
{
    Dialog *win=new Dialog(nullptr,ips,arps);
    win->show();
}
u_int MainWindow :: tozijiexu(u_int number){//overide function "zijiexu"
    return ((number&0xFF)<<24)|((number&0xFF00)<<8)|((number&0xFF0000)>>8)|(number>>24);
}

void MainWindow::on_action_2_triggered()//统计数据
{
    on_pushButton_2_clicked();
}

void MainWindow::on_TransButton_clicked()//统计数据
{
    Dialog_2 *win_2=new Dialog_2(nullptr,tcps,udps);
    win_2->show();
}

void MainWindow::on_action_3_triggered()//统计数据
{
    on_TransButton_clicked();
}

void MainWindow::on_pushButton_3_clicked()//清除按钮
{
    on_pushButton_clicked();//终止线程
    ui->TransButton->setEnabled(false);
    ui->pushButton_2->setEnabled(false);
    ui->pushButton->setEnabled(false);
    ui->action_2->setEnabled(false);
    ui->action_3->setEnabled(false);
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(0);
    ui->action_2->setEnabled(false);
    ui->action_3->setEnabled(false);
    ui->action_4->setEnabled(false);
    row=0;
    ips=0;
    arps=0;
    tcps=0;
    udps=0;
    icmps=0;
    igmps=0;
    //还需要删除文件
    QFile::remove("file.txt");
    ui->action_start->setEnabled(true);
}

void MainWindow::on_action_4_triggered()
{
    QString path=QFileDialog::getSaveFileName(nullptr,"选择文件夹","/","X-snifffile(*.xsw)");
    QFile::copy("file.txt",path);
}

void MainWindow::on_action_stop_triggered()//菜单停止
{
    on_pushButton_clicked();
}

void MainWindow::on_action_start_triggered()
{
    inter->start();
    anal->start();
    ui->action_stop->setEnabled(true);//菜单停止
    ui->pushButton->setEnabled(true);//按键停止
    ui->pushButton_2->setEnabled(true);//按键分析
    ui->action_2->setEnabled(true);
    ui->action_3->setEnabled(true);
    ui->pushButton_3->setEnabled(true);
    ui->TransButton->setEnabled(true);
}

void MainWindow::on_filter_button_clicked()
{

}
