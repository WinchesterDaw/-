#include"pcap.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Windows.h>
#include<iostream>
using namespace std;
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

int main() {
	//接口链表数据结构
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_if_t* d1;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	//获取设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1) {
		cout << "获取设备列表成功" << endl;
	}
	else { cout << "获取设备列表失败" << endl; return 0; }
	//显示获取的设备列表
	int i1 = 1;
	for (d1 = alldevs; d1 != NULL; d1 = d1->next) {
		cout << i1 << endl; i1++;
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
		pcap_pkthdr* Packet_Header = NULL;    // 数据包头
		const u_char* Packet_Data = NULL;    // 数据本身

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
				//PrintEtherHeader(Packet_Data);
				//PrintIPHeader(Packet_Data);
				cout << endl;
			}
			else { k--; cout << ex_value << "超时" << endl; }
		}
	}
	int num = i - 1;//接口总数
	//释放设备列表
	pcap_freealldevs(alldevs);
}