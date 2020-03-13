#ifndef GLOABLE_H
#define GLOABLE_H


#define HAVE_REMOTE
#include <pcap.h>

#define RESERVED 0
#define ICMP 1
#define IGMP 2
#define TCP 6
#define UDP 17

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

#endif // GLOABLE_H
