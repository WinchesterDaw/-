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
//������ �ڶ��뷽ʽ
typedef struct FrameHeader_t{
	BYTE DesMAC[6];
	// Ŀ�ĵ�ַ
	BYTE SrcMAC[6];
	//Դ��ַ
	WORD FrameType;
	//֡����
}FrameHeader_t;
typedef struct IPHeader_t{
	//IP�ײ�
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
	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
} Data_t;
#pragma pack() //�ָ�ȱʡ���뷽ʽ

void PrintEtherHeader(const u_char* packetData)
{
	
	struct FrameHeader_t* protocol;
	protocol = (struct FrameHeader_t*)packetData;

	u_short ether_type = ntohs(protocol->FrameType);  // ��̫������
	u_char* ether_src = protocol->SrcMAC;         // ��̫��ԭʼMAC��ַ
	u_char* ether_dst = protocol->DesMAC;         // ��̫��Ŀ��MAC��ַ

	printf("����: 0x%x \t", ether_type);
	printf("ԭMAC��ַ: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
	printf("Ŀ��MAC��ַ: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}
void PrintIPHeader(const u_char* packetData) {
	struct IPHeader_t* ip_protocol;

	// +14 ����������·��
	ip_protocol = (struct IPHeader_t*)(packetData + 14);
	SOCKADDR_IN Src_Addr, Dst_Addr = { 0 };

	u_short check_sum = ntohs(ip_protocol->Checksum);
	int ttl = ip_protocol->TTL;
	int proto = ip_protocol->Protocol;

	Src_Addr.sin_addr.s_addr = ip_protocol->SrcIP;
	Dst_Addr.sin_addr.s_addr = ip_protocol->DstIP;

	//printf("Դ��ַ: %15s --> ", inet_ntoa(Src_Addr.sin_addr));
	//printf("Ŀ���ַ: %15s --> ", inet_ntoa(Dst_Addr.sin_addr));
	char buff1[17];
	::inet_ntop(AF_INET, (const void*)&Src_Addr.sin_addr, buff1, 17);
	printf("Դ��ַ: %s --> ", buff1);
	char buff2[17];
	::inet_ntop(AF_INET, (const void*)&Dst_Addr.sin_addr, buff2, 17);
	printf("Ŀ���ַ: %s --> ", buff2);
	printf("У���: %5X --> TTL: %4d --> Э������: ", check_sum, ttl);
	switch (ip_protocol->Protocol)
	{
	case 1: printf("ICMP \n"); break;
	case 2: printf("IGMP \n"); break;
	case 6: printf("TCP \n");  break;
	case 17: printf("UDP \n"); break;
	case 89: printf("OSPF \n"); break;
	default: printf("None \n"); break;
	}
}


int main() {
	//�ӿ��������ݽṹ
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_if_t* d1;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];
	//��ȡ�豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) !=-1) {
		cout << "��ȡ�豸�б�ɹ�" << endl;
	}
	else { cout << "��ȡ�豸�б�ʧ��" << endl; return 0; }
	//��ʾ��ȡ���豸�б�
	int i1 = 1;
	for (d1 = alldevs; d1 != NULL; d1 = d1->next) {
		cout <<  i1 ; i1++;
		cout << "name: " << d1->name << endl;
		//cout << "description: " << d1->description << endl;
		//cout << "addresses: " << d1->addresses << endl;
	}
	//ѡ��Ҫ����������
	cout << "��ѡ��Ҫ������������";
	int cho_i;
	cin >> cho_i;

	int i = 1;
	pcap_pkthdr* Packet_Header;    // ���ݰ�ͷ
	const u_char* Packet_Data;
	for (d = alldevs; d != NULL; d = d->next) {
		
		//cout << "next_ex: " << pcap_next_ex(d, &Packet_Header, &Packet_Data) << endl;
		pcap_if_t* pname = d;
		//������ӿ�
		pcap_t* handle = pcap_open(pname->name, 655340,  PCAP_OPENFLAG_PROMISCUOUS,1000, 0, 0);
		
		
		pcap_pkthdr* Packet_Header=NULL;    // ���ݰ�ͷ
		const u_char* Packet_Data=NULL;    // ���ݱ���
		int retValue;
		cout << endl << i << endl; i++;
		if (i == cho_i) {
			cout << "��ʼ������ "<<i<<"  :";
			while (1) {
				if ((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) >= 0)
				{
					if (retValue == 0) { continue; }
					cout << "name: " << d->name << endl;
					cout << "description: " << d->description << endl;
					cout << "addresses: " << d->addresses << endl;

					printf("��������: %d \n", Packet_Header->len);
					//cout<<Packet_Data<<endl;
					PrintEtherHeader(Packet_Data);
					PrintIPHeader(Packet_Data);
				}
				else { cout << "��ʱ" << endl; }
			}
			

		}
		

	}
	int num = i - 1;//�ӿ�����


	






	//�ͷ��豸�б�
	pcap_freealldevs(alldevs);



}