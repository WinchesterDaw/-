#include"pcap.h"
#include<iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Windows.h>
using namespace std;
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack (1)
//进入字 节对齐方式
typedef struct FrameHeader_t{
	BYTE DesMAC[6];
	// 目的地址
	BYTE SrcMAC[6];
	//源地址
	WORD FrameType;
	//帧类型
}FrameHeader_t;
typedef struct IPHeader_t{
	//IP首部
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
} IPHeader_t;
typedef struct Data_t {
	//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
} Data_t;
#pragma pack() //恢复缺省对齐方式

void PrintEtherHeader(const u_char* packetData)
{
	
	struct FrameHeader_t* protocol;
	protocol = (struct FrameHeader_t*)packetData;

	u_short ether_type = ntohs(protocol->FrameType);  // 以太网类型
	u_char* ether_src = protocol->SrcMAC;         // 以太网原始MAC地址
	u_char* ether_dst = protocol->DesMAC;         // 以太网目标MAC地址

	printf("类型: 0x%x \t", ether_type);
	printf("原MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
	printf("目标MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}

int main() {
	//接口链表数据结构
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) !=-1) {
		cout << "获取设备列表成功" << endl;
	}
	else { cout << "获取设备列表失败" << endl; return 0; }

	int i = 1;
	pcap_pkthdr* Packet_Header;    // 数据包头
	const u_char* Packet_Data;
	for (d = alldevs; d != NULL; d = d->next) {
		
		//cout << "next_ex: " << pcap_next_ex(d, &Packet_Header, &Packet_Data) << endl;
		pcap_if_t* pname = d;
		pcap_t* handle = pcap_open(pname->name, 655340,  PCAP_OPENFLAG_PROMISCUOUS,1000, 0, 0);
		
		cout << "开始监听： " ;
		pcap_pkthdr* Packet_Header=NULL;    // 数据包头
		const u_char* Packet_Data=NULL;    // 数据本身
		int retValue;
		if((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) ==1 )
		{
			cout <<endl<< i << endl; i++;
			cout << "name: " << d->name << endl;
			cout << "description: " << d->description << endl;
			cout << "addresses: " << d->addresses << endl;

			printf("侦听长度: %d \n", Packet_Header->len);
			//cout<<Packet_Data<<endl;
			PrintEtherHeader(Packet_Data);
			//PrintIPHeader(Packet_Data);
		}
		else { cout << "超时" << endl; }

	}
	int num = i - 1;//接口总数


	







	pcap_freealldevs(alldevs);



}