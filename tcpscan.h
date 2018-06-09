#ifndef TCPSCAN_H
#define TCPSCAN_H

#include <QObject>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <math.h>
#include <pthread.h>
#include <cstring>
#include <unistd.h>
#include <curl/curl.h>


class tcpscan:public QObject
{
Q_OBJECT //必须包含的宏


public:
    tcpscan();

    static tcpscan *pThis;

    const char*  sourceIpAddress;
    unsigned char  gateMacAddress[6]={0x20,0x4e,0x71,0x61,0x97,0xc1};
    unsigned char  sourceMacAddress[6]={0x28,0xc2,0xdd,0x2b,0x5d,0xb9};

    void syn_scan(const char* DSTIP,int startP,int endP);
    void tcp_connect(const char* DSTIP,int startP,int endP);
    void fin_scan(const char* DSTIP,int startP,int endP);


    typedef struct _MAC_FRAME_HEADER
    {
        unsigned char m_cDstMacAddress[6];    //目的mac地址
        unsigned char m_cSrcMacAddress[6];    //源mac地址
        ushort m_cType;               //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
    }__attribute__((packed))MAC_FRAME_HEADER,*PMAC_FRAME_HEADER;



    typedef struct _MAC_FRAME_TAIL
    {
        unsigned int m_sCheckSum;    //数据帧尾校验和
    }__attribute__((packed))MAC_FRAME_TAIL, *PMAC_FRAME_TAIL;



    /*IP头定义，共40个字节*/
    typedef struct _IP_HEADER
    {
        unsigned char m_cVersionAndHeaderLen;          //版本信息(前4位)，头长度(后4位)
        unsigned char m_cTypeOfService;                // 服务类型8位
        ushort m_sTotalLenOfPacket;            //数据包长度
        ushort m_sPacketID;                    //数据包标识
        ushort m_sSliceinfo;                   //分片使用
        unsigned char m_cTTL;                          //存活时间
        unsigned char m_cTypeOfProtocol;               //协议类型
        short m_sCheckSum;                    //校验和
        unsigned int m_uiSourIp;              //源ip
        unsigned int m_uiDestIp;              //目的ip
    } __attribute__((packed))IP_HEADER, *PIP_HEADER ;

    typedef struct _TCP_HEADER
    {
        ushort m_sSourPort;                   // 源端口号16bit
        ushort m_sDestPort;                   // 目的端口号16bit
        unsigned int m_uiSequNum;            // 序列号32bit
        unsigned int m_uiAcknowledgeNum;     // 确认号32bit
        unsigned char m_sHeaderLen;           // 头长度
        unsigned char m_sFlag;                // 标记位置
        ushort m_sWindowSize;                 // 窗口大小16bit
        ushort m_sCheckSum;                   // 检验和16bit
        ushort m_surgentPointer;              // 紧急数据偏移量16bit
        //unsigned char m_optionsData[20];
    }__attribute__((packed))TCP_HEADER, *PTCP_HEADER;

    /*12字节的伪TCP头部*/
    struct _PSD_TCP
    {
        unsigned long  sAddr;    //源地址
        unsigned long  dAddr;   //目标地址
        char x;//
        char type;//协议号,6,表示TCP
        short dataLength;//整个TCP长度,
    };

signals:
    void sendMessage(QString msg);  //
private:
    void initIpAndMac();

    void parse_packet(const unsigned char *buf, const unsigned int len);
    static unsigned short checksum(unsigned short *packet, int size );
    static void HandlePacketCallBack_getIpAndMac(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket);
    static void HandlePacketCallBack_tcpSYN(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket);
    static void HandlePacketCallBack_tcpconnect(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket);
    static void HandlePacketCallBack_tcpFIN(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket);
};

#endif // TCPSCAN_H
