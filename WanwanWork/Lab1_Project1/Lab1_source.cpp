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

int main() {
	//�ӿ��������ݽṹ
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) !=-1) {
		cout << "��ȡ�豸�б�ɹ�" << endl;
	}
	else { cout << "��ȡ�豸�б�ʧ��" << endl; return 0; }

	int i = 1;
	pcap_pkthdr* Packet_Header;    // ���ݰ�ͷ
	const u_char* Packet_Data;
	for (d = alldevs; d != NULL; d = d->next) {
		
		//cout << "next_ex: " << pcap_next_ex(d, &Packet_Header, &Packet_Data) << endl;
		pcap_if_t* pname = d;
		pcap_t* handle = pcap_open(pname->name, 655340,  PCAP_OPENFLAG_PROMISCUOUS,1000, 0, 0);
		
		cout << "��ʼ������ " ;
		pcap_pkthdr* Packet_Header=NULL;    // ���ݰ�ͷ
		const u_char* Packet_Data=NULL;    // ���ݱ���
		int retValue;
		if((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) ==1 )
		{
			cout <<endl<< i << endl; i++;
			cout << "name: " << d->name << endl;
			cout << "description: " << d->description << endl;
			cout << "addresses: " << d->addresses << endl;

			printf("��������: %d \n", Packet_Header->len);
			//cout<<Packet_Data<<endl;
			PrintEtherHeader(Packet_Data);
			//PrintIPHeader(Packet_Data);
		}
		else { cout << "��ʱ" << endl; }

	}
	int num = i - 1;//�ӿ�����


	







	pcap_freealldevs(alldevs);



}