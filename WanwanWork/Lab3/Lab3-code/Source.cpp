#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include"pcap.h"
#include <WinSock2.h>
#include <Windows.h>
#include<iostream>
#include<stdio.h>
#include<cstring>
using namespace std;

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack (1)//�����ֽڶ��뷽ʽ
//��̫��֡ 14�ֽ�
typedef struct FrameHeader_t {
	BYTE DesMAC[6];// Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;
//ARP֡ 28�ֽ�
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//��̫��֡ͷ
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ����
	WORD Operation;
	BYTE SendHa[6];	//���Ͷ���̫����ַ
	DWORD SendIP;	//���Ͷ�IP��ַ
	BYTE RecvHa[6];	//Ŀ����̫����ַ
	DWORD RecvIP;	//Ŀ��IP��ַ
} ARPFrame_t;
#pragma pack ()

//ȫ��
pcap_t* adhandle;				 //��׽ʵ��,��pcap_open���صĶ���
string iplist[100];
int i = 0;                       //��������������

//α��
ARPFrame_t MakeARP(pcap_addr* a) {
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//��ʾ�㲥
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;

	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����

	//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x0f;
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr("100.100.100.100");
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//��ʾĿ�ĵ�ַδ֪
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
	return ARPFrame;
}

//����
int Send(pcap_t* adhandle, ARPFrame_t ARPFrame) {
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0) { cout << "����ʧ��" << endl; return 1; }// !=0��ʱ��Ϊsend��������
	else { return 1; }
}

//�հ�
void Recv(pcap_t* adhandle) {
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	int res;
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		ARPFrame_t* RecPacket = (ARPFrame_t*)pkt_data;
		if (
			*(unsigned short*)(pkt_data + 12) == htons(0x0806)	//0x0806Ϊ��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
			&& *(unsigned short*)(pkt_data + 20) == htons(2)	//ARPӦ��
			&& *(unsigned long*)(pkt_data + 38)== inet_addr("100.100.100.100")
			) 
		{
			printf("%s:\t%02x-%02x-%02x-%02x-%02x-%02x\n", "MAC��ַ",
				RecPacket->FrameHeader.SrcMAC[0], 
				RecPacket->FrameHeader.SrcMAC[1], 
				RecPacket->FrameHeader.SrcMAC[2], 
				RecPacket->FrameHeader.SrcMAC[3], 
				RecPacket->FrameHeader.SrcMAC[4],
				RecPacket->FrameHeader.SrcMAC[5]);
			break;
		}
	}
}

//�����ӿ��б�
void Devslist(pcap_if_t* alldevs,int ip_i) {
	//ip_i=0 ȫ����ʾ
	//ip_i!=0 ���ض�ip
	i = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)//��ʾ�ӿ��б�
	{
		//��ȡ������ӿ��豸��ip��ַ��Ϣ
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//��ӡip��ַ
				i++;
				if (ip_i == 0)
				{
					//��ӡ�����Ϣ
					//inet_ntoa��ip��ַת���ַ�����ʽ
					printf("%d\n", i);
					printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
					printf("%s\t\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					iplist[i] = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
				}
				
				//����IP�鿴MAC����
				else if(ip_i==i){
					printf("%s\t\t%s\n%s\t%s\n", "name:", d->name, "description:", d->description);
					printf("%s\t\t%s\n", "IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					//�ڵ�ǰ������α��һ����
					ARPFrame_t ARPFrame = MakeARP(a);

					//�򿪸�����������ӿ�
					adhandle = pcap_open(d->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
					if (adhandle == NULL) { cout << "�򿪽ӿ�ʧ��"; }

					//����
					if (Send(adhandle, ARPFrame) == 0) { break; };

					//�հ�
					Recv(adhandle);
				}
				
			}
		}
	}

}

int main() {
	pcap_if_t* alldevs;				 //��������������
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
	//��һ�α��� ��ʾ����������Ϣ
	Devslist(alldevs, 0);

	//�������ѯ��IP��ַ
	string ip;
	cout << "--------------------------------------" << endl << "��������Ҫ��ѯ��ip��ַ��";
	while (cin >> ip) {
		int ip_i;
		for (int j = 1; j <= i; j++) {
			//��iplist���ҵ���
			if (iplist[j] == ip) {
				ip_i = j;
				break;
			}
			//û�ҵ�
			else if (j == i && ip != iplist[j]) { cout << "�������"; return 0; }
		}
		//��ѯ����ip����ʾ������Ϣ
		Devslist(alldevs, ip_i);
		cout << "--------------------------------------" << endl;
		cout << "��������Ҫ��ѯ��ip��ַ��";
	}
	
	//�ͷ���Դ
	pcap_freealldevs(alldevs);
}