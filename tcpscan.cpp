#include "tcpscan.h"

tcpscan* tcpscan::pThis=NULL;

tcpscan::tcpscan()
{
    pThis=this;
    sourceIpAddress="10.0.153.247";
}

//解套接字分析
void tcpscan::parse_packet(const unsigned char *buf, const unsigned int len)
{
    int i ,j=0;

    printf("The buffer is:\n");
    for (i = 0; i < len; i++){
        printf("%02x ", buf[i]);
        if(j++==15){
            printf("\n");
            j=0;
        }

    }
    printf("\n%d",len);
}

void tcpscan::initIpAndMac(){
    CURL *curl = curl_easy_init();
    if(!curl)
        return;
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "101.132.136.121");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    pcap_if_t* alldevs;//利用winpcap发送数据包
    char err[10];
    pcap_findalldevs(&alldevs,err);
    char* name;
    name=alldevs->name;
    pcap_t* fp;
    fp=pcap_open_live(name,1500,1,1,err);
    unsigned char param[1];
    memset(param, 0x00, sizeof param );
    pcap_dispatch(fp, 0, HandlePacketCallBack_getIpAndMac, param);
    pcap_close(fp);
    pcap_freealldevs(alldevs);
}
unsigned short tcpscan::checksum(unsigned short *packet, int size )
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *packet++;
        size -= sizeof(ushort);
    }
    if (size)
    {
        cksum += *(unsigned char*)packet;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);

    return (ushort)(~cksum);
}

void tcpscan::HandlePacketCallBack_getIpAndMac(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)
{

//    MAC_FRAME_HEADER *pEthHeader = ( MAC_FRAME_HEADER *)recvPacket;    //利用指针指向ETH Header
//    IP_HEADER *pIpHeader = ( IP_HEADER *)(recvPacket + sizeof(MAC_FRAME_HEADER) );  //利用指针指向IP Header

//    pThis->sourceIpAddress= pIpHeader->m_uiDestIp;
//    pThis->sourceMacAddress=pEthHeader->m_cDstMacAddress;
//    pThis->gateMacAddress=pEthHeader->m_cSrcMacAddress;

//    pThis->pEther =pEthHeader;
//    return;
}

void tcpscan::HandlePacketCallBack_tcpSYN(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)
{


//    MAC_FRAME_HEADER *pEthHeader = ( MAC_FRAME_HEADER *)recvPacket;    //利用指针指向ETH Header
//    IP_HEADER *pIpHeader = ( IP_HEADER *)(recvPacket + sizeof(MAC_FRAME_HEADER) );  //利用指针指向IP Header
    TCP_HEADER *pTcpHeader = ( TCP_HEADER *)(recvPacket + sizeof(MAC_FRAME_HEADER) + sizeof(IP_HEADER) );  //利用指针指向TCP Header
    if(pTcpHeader->m_sFlag == 18){
        printf("[+]Port %0d is open \n",htons(pTcpHeader->m_sSourPort));
        emit pThis->sendMessage(QString("[+]Port %1 is open").arg(htons(pTcpHeader->m_sSourPort)));
    }
    else if(pTcpHeader->m_sFlag == 20){
        //printf("[-]Port %0d is close\n",htons(pTcpHeader->m_sSourPort));
        //emit pThis->sendMessage(QString("[-]Port %1 is close").arg(htons(pTcpHeader->m_sSourPort)));
    }
    return;
}

void tcpscan::HandlePacketCallBack_tcpconnect(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)
{
    //printf("callback/n");
    unsigned short localPort = *(unsigned short *)param;

    MAC_FRAME_HEADER *pEthHeader = ( MAC_FRAME_HEADER *)recvPacket;    //利用指针指向ETH Header
    IP_HEADER *pIpHeader = ( IP_HEADER *)(recvPacket + sizeof(MAC_FRAME_HEADER) );  //利用指针指向IP Header
    TCP_HEADER *pTcpHeader = ( TCP_HEADER *)(recvPacket + sizeof(MAC_FRAME_HEADER) + sizeof(IP_HEADER) );  //利用指针指向TCP Header
    if(pTcpHeader->m_sFlag == 18){          //收到SYN+ACK
        emit pThis->sendMessage(QString("[+]Port %1 is open        >>>Port%2").arg(htons(pTcpHeader->m_sSourPort)).arg(htons(pTcpHeader->m_sSourPort)));
        printf("[+]Port %0d is open .And Return ACK To Server\n",htons(pTcpHeader->m_sSourPort));
        //服务器发回ACK+SYN 主机发送Ack=seq+1 确认连接
        //初始化init
        _MAC_FRAME_HEADER macHeader;
        _IP_HEADER ipHeader;
        _TCP_HEADER tcpHeader;
        _PSD_TCP psdTcp;

        pcap_if_t* alldevs;//利用winpcap发送数据包
        char err[10];
        pcap_findalldevs(&alldevs,err);
        char* name;
        name=alldevs->name;
        pcap_t* fp;
        fp=pcap_open_live(name,1500,1,1,err);

        //Define TCP HEADER
            memset(&tcpHeader,0,sizeof tcpHeader);
            tcpHeader.m_sSourPort=htons(pTcpHeader->m_sDestPort);
            tcpHeader.m_sDestPort=htons(pTcpHeader->m_sSourPort);
            tcpHeader.m_uiSequNum=htonl(2);
            //printf("%d",rand());
            tcpHeader.m_uiAcknowledgeNum=htonl(0);
            tcpHeader.m_sHeaderLen=sizeof(tcpHeader)<<2; //1010 00
            tcpHeader.m_sFlag=16;          //00010000  --> ACK==1
            tcpHeader.m_sWindowSize=htons(8192);
            tcpHeader.m_surgentPointer=0;
            tcpHeader.m_sCheckSum=0;

            //PSD TCP
            memset(&psdTcp,0,sizeof psdTcp);
            psdTcp.sAddr=htons(pIpHeader->m_uiDestIp);
            psdTcp.dAddr=htons(pIpHeader->m_uiSourIp);
            psdTcp.type=0x06;
            psdTcp.x=0;
            psdTcp.dataLength=htons(sizeof(tcpHeader));

            u_char buf_tcp[100];
            int psdSize = sizeof(psdTcp);
            memcpy(buf_tcp,&psdTcp,psdSize);
            memcpy(buf_tcp+psdSize,&tcpHeader,sizeof(tcpHeader));
            psdSize+=sizeof(tcpHeader);
            tcpHeader.m_sCheckSum=tcpscan::checksum((unsigned short *)buf_tcp,psdSize);

            //Define IP HEADER
            memset(&ipHeader,0,sizeof ipHeader);
            ipHeader.m_cVersionAndHeaderLen=0x45;
            ipHeader.m_cTypeOfService=0;
            ipHeader.m_sTotalLenOfPacket=htons( sizeof(ipHeader) + sizeof(tcpHeader) );
            ipHeader.m_sPacketID=htons(2345);
            ipHeader.m_sSliceinfo=htons(0);
            ipHeader.m_cTTL=0x80;
            ipHeader.m_cTypeOfProtocol=6;
            ipHeader.m_uiDestIp=pIpHeader->m_uiSourIp;
            ipHeader.m_uiSourIp=pIpHeader->m_uiDestIp;
            ipHeader.m_sCheckSum=0;
            ipHeader.m_sCheckSum=tcpscan::checksum((unsigned short*)&ipHeader, sizeof(ipHeader));


            //Define MAC FREAM HEADER
            memset(&macHeader,0,sizeof macHeader);
            memcpy(macHeader.m_cDstMacAddress,pThis->gateMacAddress,6);
            memcpy(macHeader.m_cSrcMacAddress,pThis->sourceMacAddress,6);
            macHeader.m_cType=htons(0x0800);    //0x0008 = ipv4

            //合并数据包
            u_char buf[100];
            int len=0;
            memcpy(buf,&macHeader,sizeof(macHeader));

            len+=sizeof(macHeader);
            memcpy(buf+len,&ipHeader,sizeof(ipHeader));

            len+=sizeof(ipHeader);
            memcpy(buf+len,&tcpHeader,sizeof(tcpHeader));
            len+=sizeof(tcpHeader);

            if(fp==NULL){
                printf("NO devices found .Please run with root permission\n");
                return ;
            }

            //pcap_sendpacket(fp,buf,len);
    }
   else{
        printf("[-]Port %0d is closed \n",htons(pTcpHeader->m_sSourPort));
        emit pThis->sendMessage(QString("[-]Port %1 is close").arg(htons(pTcpHeader->m_sSourPort)));
    }

    return;

}

void tcpscan::HandlePacketCallBack_tcpFIN(unsigned char *param,const struct pcap_pkthdr* packet_header, const unsigned char *recvPacket)
{
//    MAC_FRAME_HEADER *pEthHeader = ( MAC_FRAME_HEADER *)recvPacket;    //利用指针指向ETH Header
//    IP_HEADER *pIpHeader = ( IP_HEADER *)(recvPacket + sizeof(MAC_FRAME_HEADER) );  //利用指针指向IP Header
    TCP_HEADER *pTcpHeader = ( TCP_HEADER *)(recvPacket + sizeof(MAC_FRAME_HEADER) + sizeof(IP_HEADER) );  //利用指针指向TCP Header
    emit pThis->sendMessage(QString("[+]Port %1 is open").arg(htons(pTcpHeader->m_sSourPort)));
    return;

}

void tcpscan::syn_scan(const char* DSTIP,int startP,int endP){

    const char* MYIP=sourceIpAddress;
    int startPort =startP;
    int endPort = endP;
    _MAC_FRAME_HEADER macHeader;
    _IP_HEADER ipHeader;
    _TCP_HEADER tcpHeader;
    _PSD_TCP psdTcp;

    pcap_if_t* alldevs;//利用winpcap发送数据包
    char err[10];
    pcap_findalldevs(&alldevs,err);
    char* name;
    name=alldevs->name;
    pcap_t* fp;
    fp=pcap_open_live(name,1500,1,50,err);
    pcap_setnonblock(fp,-1,err);

    /*[配置过滤规则,直接受目标条件*/
        struct bpf_program filter;
        char rex[256];

        sendMessage(QString("扫描的地址 %1 ").arg(DSTIP));
        sendMessage(QString("扫描方式: TCP SYN"));
        sendMessage(QString("起始端口: %1 ,结束端口: %2").arg(startPort).arg(endPort));
        sendMessage(QString("------------Scan Begining------------"));


    for(startPort;startPort<=endPort;startPort++){
        int Port =startPort;
        unsigned short srcPort = rand()%65535;
        //Define TCP HEADER
        memset(&tcpHeader,0,sizeof tcpHeader);
        tcpHeader.m_sSourPort=htons(srcPort);
        tcpHeader.m_sDestPort=htons(Port);
        tcpHeader.m_uiSequNum=htonl(2);
        tcpHeader.m_uiAcknowledgeNum=htonl(0);
        tcpHeader.m_sHeaderLen=sizeof(tcpHeader)<<2; //1010 00
        tcpHeader.m_sFlag=2;          //00010010  --> SYN ==1
        tcpHeader.m_sWindowSize=htons(8192);
        tcpHeader.m_surgentPointer=0;
        tcpHeader.m_sCheckSum=0;

        //PSD TCP
        memset(&psdTcp,0,sizeof psdTcp);
        //psdTcp.sAddr=inet_addr(MYIP);
        psdTcp.sAddr=inet_addr(MYIP);
        psdTcp.dAddr=inet_addr(DSTIP);
        psdTcp.type=0x06;
        psdTcp.x=0;
        psdTcp.dataLength=htons(sizeof(tcpHeader));

        u_char buf_tcp[100];
        int psdSize = sizeof(psdTcp);
        memcpy(buf_tcp,&psdTcp,psdSize);
        memcpy(buf_tcp+psdSize,&tcpHeader,sizeof(tcpHeader));
        psdSize+=sizeof(tcpHeader);
        tcpHeader.m_sCheckSum=checksum((unsigned short *)buf_tcp,psdSize);


        //Define IP HEADER
        memset(&ipHeader,0,sizeof ipHeader);

        ipHeader.m_cVersionAndHeaderLen=0x45;
        ipHeader.m_cTypeOfService=0;
        ipHeader.m_sTotalLenOfPacket=htons( sizeof(ipHeader) + sizeof(tcpHeader) );
        ipHeader.m_sPacketID=htons(2345);
        ipHeader.m_sSliceinfo=htons(0);
        ipHeader.m_cTTL=0x80;
        ipHeader.m_cTypeOfProtocol=6;
        ipHeader.m_uiDestIp=inet_addr(DSTIP);
        ipHeader.m_uiSourIp=inet_addr(MYIP);
        ipHeader.m_sCheckSum=0;
        ipHeader.m_sCheckSum=checksum((unsigned short*)&ipHeader, sizeof(ipHeader));

        //Define MAC FREAM HEADER
        memset(&macHeader,0,sizeof macHeader);
        //unsigned char dstMAC[6]={0x20,0x4e,0x71,0x61,0x97,0xc1}; //destination MAC Address (wang guan Address)
        //unsigned char srcMAC[6]={0x28,0xc2,0xdd,0x2b,0x5d,0xb9}; //source MAC Address (My PC Address)
        memcpy(macHeader.m_cDstMacAddress,gateMacAddress,6);
        memcpy(macHeader.m_cSrcMacAddress,sourceMacAddress,6);
        macHeader.m_cType=htons(0x0800);    //0x0008 = ipv4


        //合并数据包
        u_char buf[100];
        int len=0;
        memcpy(buf,&macHeader,sizeof(macHeader));

        len+=sizeof(macHeader);
        memcpy(buf+len,&ipHeader,sizeof(ipHeader));

        len+=sizeof(ipHeader);
        memcpy(buf+len,&tcpHeader,sizeof(tcpHeader));
        len+=sizeof(tcpHeader);

        if(fp==NULL){
            //printf("NO devices found .Please run with root permission\n");
            //print2textBrowser(textEdit,QString("Error:NO devices found .Please run with root permission"));
            return ;
        }
        //printf("scan port %d ",Port);
        //sendMessage(QString("scan port %1").arg(Port));
        pcap_sendpacket(fp,buf,len);

        /*设置过滤器 捕获指定源端口 且 Ack=seq+1*/
        snprintf(rex, sizeof rex, "(src host %s) && tcp[8:4] == %d",DSTIP,htonl(tcpHeader.m_uiSequNum)+1);
        pcap_compile(fp, &filter, rex, 1, 0);
        pcap_setfilter(fp, &filter);

        unsigned char param[100];
        memset(param, 0, sizeof param );

        //memset(param+);
        memcpy(param,this, sizeof this );
        //memcpy(param + sizeof srcPort, fp, 512 );

        /*捕获数据包*/

        pcap_dispatch(fp,1,HandlePacketCallBack_tcpSYN, param);
    }
    pcap_close(fp);
    pcap_freealldevs(alldevs);
    sendMessage(QString("------------Scan End------------"));
    return ;
}

void tcpscan::tcp_connect(const char* DSTIP,int startP,int endP){

    int startPort =startP;
    int endPort = endP;

    _MAC_FRAME_HEADER macHeader;
    _IP_HEADER ipHeader;
    _TCP_HEADER tcpHeader;
    _PSD_TCP psdTcp;


    pcap_if_t* alldevs;//利用winpcap发送数据包
    char err[10];
    pcap_findalldevs(&alldevs,err);
    char* name;
    name=alldevs->name;
    pcap_t* fp;
    fp=pcap_open_live(name,1500,1,1,err);
    //pcap_setnonblock(fp,1,err);

    /*[配置过滤规则,直接受目标条件*/
        struct bpf_program filter;
        char rex[256];
        emit sendMessage(QString("扫描的地址 %1 ").arg(DSTIP));
        emit sendMessage(QString("扫描方式: TCP connect"));
        emit sendMessage(QString("起始端口: %1 ,结束端口: %2").arg(startPort).arg(endPort));
        emit sendMessage(QString("------------Scan Begining------------"));

    for(startPort;startPort<=endPort;startPort++){
        int Port =startPort;
        unsigned short srcPort = rand()%65535;
        //Define TCP HEADER
        memset(&tcpHeader,0,sizeof tcpHeader);
        tcpHeader.m_sSourPort=htons(srcPort);
        tcpHeader.m_sDestPort=htons(Port);
        tcpHeader.m_uiSequNum=htonl(2);
        //printf("%d",rand());
        tcpHeader.m_uiAcknowledgeNum=htonl(0);
        tcpHeader.m_sHeaderLen=sizeof(tcpHeader)<<2; //1010 00
        tcpHeader.m_sFlag=2;          //00010010  --> SYN ==1
        tcpHeader.m_sWindowSize=htons(8192);
        tcpHeader.m_surgentPointer=0;
        tcpHeader.m_sCheckSum=0;

        //PSD TCP

        memset(&psdTcp,0,sizeof psdTcp);
        psdTcp.sAddr=inet_addr(sourceIpAddress);
        psdTcp.dAddr=inet_addr(DSTIP);
        psdTcp.type=0x06;
        psdTcp.x=0;
        psdTcp.dataLength=htons(sizeof(tcpHeader));

        u_char buf_tcp[100];
        int psdSize = sizeof(psdTcp);
        memcpy(buf_tcp,&psdTcp,psdSize);
        memcpy(buf_tcp+psdSize,&tcpHeader,sizeof(tcpHeader));
        psdSize+=sizeof(tcpHeader);
        tcpHeader.m_sCheckSum=checksum((unsigned short *)buf_tcp,psdSize);


        //Define IP HEADER
        memset(&ipHeader,0,sizeof ipHeader);



        ipHeader.m_cVersionAndHeaderLen=0x45;
        ipHeader.m_cTypeOfService=0;
        ipHeader.m_sTotalLenOfPacket=htons( sizeof(ipHeader) + sizeof(tcpHeader) );
        ipHeader.m_sPacketID=htons(2345);
        ipHeader.m_sSliceinfo=htons(0);
        ipHeader.m_cTTL=0x80;
        ipHeader.m_cTypeOfProtocol=6;
        ipHeader.m_uiDestIp=inet_addr(DSTIP);
        ipHeader.m_uiSourIp=inet_addr(sourceIpAddress);
        ipHeader.m_sCheckSum=0;
        ipHeader.m_sCheckSum=checksum((unsigned short*)&ipHeader, sizeof(ipHeader));


        //Define MAC FREAM HEADER
        memset(&macHeader,0,sizeof macHeader);
        memcpy(macHeader.m_cDstMacAddress,gateMacAddress,6);
        memcpy(macHeader.m_cSrcMacAddress,sourceMacAddress,6);
        macHeader.m_cType=htons(0x0800);    //0x0008 = ipv4

        //合并数据包
        u_char buf[100];
        int len=0;
        memcpy(buf,&macHeader,sizeof(macHeader));

        len+=sizeof(macHeader);
        memcpy(buf+len,&ipHeader,sizeof(ipHeader));

        len+=sizeof(ipHeader);
        memcpy(buf+len,&tcpHeader,sizeof(tcpHeader));
        len+=sizeof(tcpHeader);

        if(fp==NULL){
            printf("NO devices found .Please run with root permission\n");
            return ;
        }
        //printf("scan port %d ",Port);
        pcap_sendpacket(fp,buf,len);

        /*设置过滤器 捕获指定源端口 且 Ack=seq+1*/
        snprintf(rex, sizeof rex, "(src host %s) && tcp[8:4] == %d",DSTIP,htonl(tcpHeader.m_uiSequNum)+1);
        pcap_compile(fp, &filter, rex, 1, 0);
        pcap_setfilter(fp, &filter);

        unsigned char param[1];
        memset(param, 0x00, sizeof param );
        // memcpy(param, &srcPort, sizeof srcPort );
        // memcpy(param + sizeof srcPort, fp, 512 );

        /*捕获数据包*/
        //sleep(0.5);
        int a=pcap_dispatch(fp, 0, HandlePacketCallBack_tcpconnect, param);
        printf("%d",a);
    }
        pcap_close(fp);
        pcap_freealldevs(alldevs);
        sendMessage(QString("------------Scan End------------"));
        return ;
}

void tcpscan::fin_scan(const char* DSTIP,int startP,int endP){
    const char* MYIP=sourceIpAddress;
    int startPort =startP;
    int endPort = endP;
    _MAC_FRAME_HEADER macHeader;
    _IP_HEADER ipHeader;
    _TCP_HEADER tcpHeader;
    _PSD_TCP psdTcp;

    pcap_if_t* alldevs;//利用winpcap发送数据包
    char err[10];
    pcap_findalldevs(&alldevs,err);
    char* name;
    name=alldevs->name;
    pcap_t* fp;
    fp=pcap_open_live(name,1500,1,0,err);
    //pcap_setnonblock(fp,1,err);

    /*[配置过滤规则,直接受目标条件*/
        struct bpf_program filter;
        char rex[256];

        sendMessage(QString("扫描的地址 %1 ").arg(DSTIP));
        sendMessage(QString("扫描方式: TCP SYN"));
        sendMessage(QString("起始端口: %1 ,结束端口: %2").arg(startPort).arg(endPort));
        sendMessage(QString("------------Scan Begining------------"));


    for(startPort;startPort<=endPort;startPort++){
        int Port =startPort;
        unsigned short srcPort = rand()%65535;
        //Define TCP HEADER
        memset(&tcpHeader,0,sizeof tcpHeader);
        tcpHeader.m_sSourPort=htons(srcPort);
        tcpHeader.m_sDestPort=htons(Port);
        tcpHeader.m_uiSequNum=htonl(2);
        tcpHeader.m_uiAcknowledgeNum=htonl(0);
        tcpHeader.m_sHeaderLen=sizeof(tcpHeader)<<2; //1010 00
        tcpHeader.m_sFlag=1;          //0000001  --> FIN ==1
        tcpHeader.m_sWindowSize=htons(8192);
        tcpHeader.m_surgentPointer=0;
        tcpHeader.m_sCheckSum=0;

        //PSD TCP
        memset(&psdTcp,0,sizeof psdTcp);
        //psdTcp.sAddr=inet_addr(MYIP);
        psdTcp.sAddr=inet_addr(MYIP);
        psdTcp.dAddr=inet_addr(DSTIP);
        psdTcp.type=0x06;
        psdTcp.x=0;
        psdTcp.dataLength=htons(sizeof(tcpHeader));

        u_char buf_tcp[100];
        int psdSize = sizeof(psdTcp);
        memcpy(buf_tcp,&psdTcp,psdSize);
        memcpy(buf_tcp+psdSize,&tcpHeader,sizeof(tcpHeader));
        psdSize+=sizeof(tcpHeader);
        tcpHeader.m_sCheckSum=checksum((unsigned short *)buf_tcp,psdSize);


        //Define IP HEADER
        memset(&ipHeader,0,sizeof ipHeader);

        ipHeader.m_cVersionAndHeaderLen=0x45;
        ipHeader.m_cTypeOfService=0;
        ipHeader.m_sTotalLenOfPacket=htons( sizeof(ipHeader) + sizeof(tcpHeader) );
        ipHeader.m_sPacketID=htons(2345);
        ipHeader.m_sSliceinfo=htons(0);
        ipHeader.m_cTTL=0x80;
        ipHeader.m_cTypeOfProtocol=6;
        ipHeader.m_uiDestIp=inet_addr(DSTIP);
        ipHeader.m_uiSourIp=inet_addr(MYIP);
        ipHeader.m_sCheckSum=0;
        ipHeader.m_sCheckSum=checksum((unsigned short*)&ipHeader, sizeof(ipHeader));

        //Define MAC FREAM HEADER
        memset(&macHeader,0,sizeof macHeader);
        //unsigned char dstMAC[6]={0x20,0x4e,0x71,0x61,0x97,0xc1}; //destination MAC Address (wang guan Address)
        //unsigned char srcMAC[6]={0x28,0xc2,0xdd,0x2b,0x5d,0xb9}; //source MAC Address (My PC Address)
        memcpy(macHeader.m_cDstMacAddress,gateMacAddress,6);
        memcpy(macHeader.m_cSrcMacAddress,sourceMacAddress,6);
        macHeader.m_cType=htons(0x0800);    //0x0008 = ipv4


        //合并数据包
        u_char buf[100];
        int len=0;
        memcpy(buf,&macHeader,sizeof(macHeader));

        len+=sizeof(macHeader);
        memcpy(buf+len,&ipHeader,sizeof(ipHeader));

        len+=sizeof(ipHeader);
        memcpy(buf+len,&tcpHeader,sizeof(tcpHeader));
        len+=sizeof(tcpHeader);

        if(fp==NULL){
            //printf("NO devices found .Please run with root permission\n");
            emit sendMessage(QString("NO devices found .Please run with root permission\n"));
            return ;
        }
        pcap_sendpacket(fp,buf,len);

        /*设置过滤器 捕获指定源端口 且 Ack=seq+1*/
        snprintf(rex, sizeof rex, "(src host %s) && tcp[8:4] == %d",DSTIP,htonl(tcpHeader.m_uiSequNum)+1);
        pcap_compile(fp, &filter, rex, 1, 0);
        pcap_setfilter(fp, &filter);

        unsigned char param[100];
        memset(param, 0, sizeof param );
        memcpy(param,this, sizeof this );
        /*捕获数据包*/
        emit sendMessage(QString("%1").arg(pcap_dispatch(fp,1,HandlePacketCallBack_tcpFIN, param)));
    }
    pcap_close(fp);
    pcap_freealldevs(alldevs);
    sendMessage(QString("------------Scan End------------"));
    return ;
}
