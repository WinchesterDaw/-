#include"pcap.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Windows.h>
#include<iostream>
using namespace std;
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack (1)
//进入字 节对齐方式
typedef struct FrameHeader_t{
	BYTE DesMAC[6];// 目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;
typedef struct IPHeader_t{
	//IP首部
	BYTE Ver_HLen;//IP协议版本和IP首部长度。高4位为版本，低4位为首部的长度(单位为4bytes)
	BYTE TOS;//服务类型
	WORD TotalLen;//IP包总长度
	WORD ID;
	WORD Flag_Segment; 
	BYTE TTL;//一个网络层的网络数据包(package)的生存周期
	BYTE Protocol;//协议
	WORD Checksum;//校验和
	ULONG SrcIP;//源地址
	ULONG DstIP;//目标地址
} IPHeader_t;
typedef struct Data_t {
	//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
} Data_t;
#pragma pack() //恢复缺省对齐方式

void PrintEtherHeader(const u_char* packetData)
{
	struct FrameHeader_t* data;
	data = (struct FrameHeader_t*)packetData;
	//将一个16位数由网络字节顺序转换为主机字节顺序
	u_short ether_type = ntohs(data->FrameType);  // 以太网类型
	u_char* ether_src = data->SrcMAC;         // 以太网原始MAC地址
	u_char* ether_dst = data->DesMAC;         // 以太网目标MAC地址

	printf("类型: 0x%x \t", ether_type);
	printf("原MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
	printf("目标MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}

//void PrintIPHeader(const u_char* packetData) {
//	struct IPHeader_t* ip_protocol;
//
//	// +14 跳过数据链路层
//	ip_protocol = (struct IPHeader_t*)(packetData + 14);
//	SOCKADDR_IN Src_Addr, Dst_Addr = { 0 };
//
//	u_short check_sum = ntohs(ip_protocol->Checksum);
//	int ttl = ip_protocol->TTL;
//	int proto = ip_protocol->Protocol;
//
//	Src_Addr.sin_addr.s_addr = ip_protocol->SrcIP;
//	Dst_Addr.sin_addr.s_addr = ip_protocol->DstIP;
//
//	//printf("源地址: %15s --> ", inet_ntoa(Src_Addr.sin_addr));
//	//printf("目标地址: %15s --> ", inet_ntoa(Dst_Addr.sin_addr));
//	char buff1[17];
//	::inet_ntop(AF_INET, (const void*)&Src_Addr.sin_addr, buff1, 17);
//	printf("源地址: %s --> ", buff1);
//	char buff2[17];
//	::inet_ntop(AF_INET, (const void*)&Dst_Addr.sin_addr, buff2, 17);
//	printf("目标地址: %s --> ", buff2);
//	printf("校验和: %5X --> TTL: %4d --> 协议类型: ", check_sum, ttl);
//	switch (ip_protocol->Protocol)
//	{
//	case 1: printf("ICMP \n"); break;
//	case 2: printf("IGMP \n"); break;
//	case 6: printf("TCP \n");  break;
//	case 17: printf("UDP \n"); break;
//	case 89: printf("OSPF \n"); break;
//	default: printf("None \n"); break;
//	}
//}
int main() {
	//接口链表数据结构
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_if_t* d1;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	//获取设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) !=-1) {
		cout << "获取设备列表成功" << endl;
	}
	else { cout << "获取设备列表失败" << endl; return 0; }
	//显示获取的设备列表
	int i1 = 1;
	for (d1 = alldevs; d1 != NULL; d1 = d1->next) {
		cout <<  i1 <<endl; i1++;
		cout << "name: " << d1->name << endl;
		cout << "description: " << d1->description << endl;
		cout << "addresses: " << d1->addresses << endl;
	}

	int i = 1;
	pcap_pkthdr* Packet_Header;    // 数据包头
	const u_char* Packet_Data;
	for (d = alldevs; d != NULL; d = d->next) {

		pcap_if_t* pname = d;
		//打开网络接口
		pcap_t* handle = pcap_open(pname->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
		//不初始化会报错
		pcap_pkthdr* Packet_Header=NULL;    // 数据包头
		const u_char* Packet_Data=NULL;    // 数据本身
		
		cout << i << " :"; i++;
		int ex_value;
		int k = 0;
		while (k >= 0) {
			//pcap_open 数据包基本信息 指向数据包
			if ((ex_value = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) == 1)
			{
				//if (retValue == 0) { continue; }
				cout << "name: " << d->name << endl;
				cout << "description: " << d->description << endl;
				cout << "addresses: " << d->addresses << endl;
				cout << "侦听长度: " << Packet_Header->len << endl;
				//cout<<Packet_Data<<endl;
				PrintEtherHeader(Packet_Data);
				//PrintIPHeader(Packet_Data);
				cout << endl;
			}
			else { k--; cout <<ex_value<< "超时" << endl; }
		}
	}
	int num = i - 1;//接口总数
	//释放设备列表
	pcap_freealldevs(alldevs);
}