// Sinffer.cpp : Defines the entry point for the console application.
//
#include<stdio.h>
#include<pcap.h>
#include<string.h> 
#pragma comment(lib,"wpcap.lib") 

//
void CallbackFunctionPacket(unsigned char *user, const struct pcap_pkthdr *winpcaphead, const unsigned char *packetdata)
{
    int IpDataLength =0,i=0;
	IpDataLength= winpcaphead->len;
    for (i = 0; i < IpDataLength; i++)
    {
		
        printf("%02X ", packetdata[i]);
		if((i+1)%25==0)
			putchar('\n');
    }
	printf("\n");//��Ӧ��readLine������û�С�\n���������
	if((packetdata[22]&0xF0)==0x40)
	{
		printf("version��ipv4\n");
		if(packetdata[31]==0x06)
			printf("protocal:TCP\n");
		else if(packetdata[31]==0x11)
			printf("protocal:UDP\n");
		printf("Total Length:%d\n",packetdata[25]);
		printf("Source IP:%d.%d.%d.%d\n",packetdata[34],packetdata[35],packetdata[36],packetdata[37]);
		printf("Destination IP:%d.%d.%d.%d\n",packetdata[38],packetdata[39],packetdata[40],packetdata[41]);
		printf("Source Port:%d\n",packetdata[42]*256+packetdata[43]);
		printf("Destination Port:%d\n",packetdata[44]*256+packetdata[45]);
	}
	else
		printf("version��ipv6\n");
	putchar('\n');
//	if((packetdata[13]&0x0F)==4)
}
//������ʼִ��
int main(int argc, char **argv)
{
	//wpcap��һЩ����
    int Result;
    pcap_if_t *NetwokDevice;//�����豸��ָ��
    pcap_t *WinpcapHandle;//�������豸ʱ�ķ���ֵ
    pcap_if_t *Device;//�豸��ָ��
    char WinpcapError[PCAP_ERRBUF_SIZE];//һЩ����
    int DeviceIndex = 0;
    char DeviceName[100][1000];
    int i;
//��ȡ�����豸���Ƿ���������豸
    Result = pcap_findalldevs(&NetwokDevice, WinpcapError);//�Ƿ���óɹ�
	//δ�ɹ�����-1
    if (Result ==  - 1)
    {
        printf("pcap_findalldevs Error");
        return 0;
    }
	//�����������豸ʱ ����ӡ�豸�б�,�г�һ���ж��ٸ��豸�������ܹ������������������ͱ�������
    for (Device = NetwokDevice, i = 0; Device && i < 10; Device = Device->next, i++)
    {   
        printf("Numb%d:", i);
        printf("%s:", Device->name);
        printf("%s\n", Device->description);
        sprintf(DeviceName[i], "%s", Device->name);
    }
    for (;;)
    {
        //printf("Please Choose the Device Number:(0-%d)", i - 1);
        //scanf("%d", &DeviceIndex);
		DeviceIndex=0;//���������趨 ����0�豸
        if (DeviceIndex > i - 1 || DeviceIndex < 0)
        {
            printf("Device Number Error\n");
            continue;
        }
        else
            break;
    }
	
//һֱѭ����ת��ѡ�е��豸���б�
    for (Device = NetwokDevice, i = 0; i < DeviceIndex; Device = Device->next, i++) 
		;
    WinpcapHandle = pcap_open_live(DeviceName[DeviceIndex], 65535, 1, 1000,WinpcapError);//���ص����򿪵�������ָ��
	//δ�ɹ����豸�򱨸����
    if (WinpcapHandle == NULL)
    {
        printf("pcap_open_live error");
        pcap_freealldevs(NetwokDevice);
        return 0;
    }
	//����ͣ����CallbackFunctiongPacket�������ݰ�������ת��Ϊ16������������ʽ
    pcap_loop(WinpcapHandle,  -1, CallbackFunctionPacket, NULL);
	//��ʱ����1000���ر��豸
    pcap_freealldevs(NetwokDevice);
    pcap_close(WinpcapHandle);
    return 1;
}

