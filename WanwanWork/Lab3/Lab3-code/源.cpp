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
	//�ӿ��������ݽṹ
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_if_t* d1;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	//��ȡ�豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) != -1) {
		cout << "��ȡ�豸�б�ɹ�" << endl;
	}
	else { cout << "��ȡ�豸�б�ʧ��" << endl; return 0; }
	//��ʾ��ȡ���豸�б�
	int i1 = 1;
	for (d1 = alldevs; d1 != NULL; d1 = d1->next) {
		cout << i1 << endl; i1++;
		cout << "name: " << d1->name << endl;
		cout << "description: " << d1->description << endl;
		cout << "addresses: " << d1->addresses << endl;
	}

	int i = 1;
	pcap_pkthdr* Packet_Header;    // ���ݰ�ͷ
	const u_char* Packet_Data;
	for (d = alldevs; d != NULL; d = d->next) {

		pcap_if_t* pname = d;
		//������ӿ�
		pcap_t* handle = pcap_open(pname->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
		//����ʼ���ᱨ��
		pcap_pkthdr* Packet_Header = NULL;    // ���ݰ�ͷ
		const u_char* Packet_Data = NULL;    // ���ݱ���

		cout << i << " :"; i++;
		int ex_value;
		int k = 0;
		while (k >= 0) {
			//pcap_open ���ݰ�������Ϣ ָ�����ݰ�
			if ((ex_value = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) == 1)
			{
				//if (retValue == 0) { continue; }
				cout << "name: " << d->name << endl;
				cout << "description: " << d->description << endl;
				cout << "addresses: " << d->addresses << endl;
				cout << "��������: " << Packet_Header->len << endl;
				//cout<<Packet_Data<<endl;
				//PrintEtherHeader(Packet_Data);
				//PrintIPHeader(Packet_Data);
				cout << endl;
			}
			else { k--; cout << ex_value << "��ʱ" << endl; }
		}
	}
	int num = i - 1;//�ӿ�����
	//�ͷ��豸�б�
	pcap_freealldevs(alldevs);
}