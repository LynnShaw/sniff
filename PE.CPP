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
	printf("\n");//对应于readLine函数，没有“\n”不会结束
	if((packetdata[22]&0xF0)==0x40)
	{
		printf("version：ipv4\n");
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
		printf("version：ipv6\n");
	putchar('\n');
//	if((packetdata[13]&0x0F)==4)
}
//主程序开始执行
int main(int argc, char **argv)
{
	//wpcap的一些变量
    int Result;
    pcap_if_t *NetwokDevice;//网络设备的指针
    pcap_t *WinpcapHandle;//打开网络设备时的返回值
    pcap_if_t *Device;//设备的指针
    char WinpcapError[PCAP_ERRBUF_SIZE];//一些错误
    int DeviceIndex = 0;
    char DeviceName[100][1000];
    int i;
//获取本机设备，是否存在网卡设备
    Result = pcap_findalldevs(&NetwokDevice, WinpcapError);//是否调用成功
	//未成功返回-1
    if (Result ==  - 1)
    {
        printf("pcap_findalldevs Error");
        return 0;
    }
	//当存在网卡设备时 ，打印设备列表,列出一共有多少个设备，本机总共有两个，无线网卡和本地连接
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
		DeviceIndex=0;//在这里制设定 调用0设备
        if (DeviceIndex > i - 1 || DeviceIndex < 0)
        {
            printf("Device Number Error\n");
            continue;
        }
        else
            break;
    }
	
//一直循环跳转到选中的设备的列表
    for (Device = NetwokDevice, i = 0; i < DeviceIndex; Device = Device->next, i++) 
		;
    WinpcapHandle = pcap_open_live(DeviceName[DeviceIndex], 65535, 1, 1000,WinpcapError);//返回的所打开的网卡的指针
	//未成功打开设备则报告错误
    if (WinpcapHandle == NULL)
    {
        printf("pcap_open_live error");
        pcap_freealldevs(NetwokDevice);
        return 0;
    }
	//否则不停调用CallbackFunctiongPacket处理数据包，将其转换为16进制数据流形式
    pcap_loop(WinpcapHandle,  -1, CallbackFunctionPacket, NULL);
	//超时大于1000，关闭设备
    pcap_freealldevs(NetwokDevice);
    pcap_close(WinpcapHandle);
    return 1;
}


