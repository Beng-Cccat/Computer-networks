#include<iostream>
#include<WinSock2.h>
#include <WS2tcpip.h>
#include<time.h>
#include <string>
#include<fstream>
using namespace std;
#pragma comment(lib,"ws2_32.lib")

unsigned char FIN = 0b100;
unsigned char ACK = 0b10;
unsigned char SYN = 0b1;
unsigned char ACK_SYN = 0b11;
unsigned char ACK_FIN = 0b110;
unsigned char OVER = 0b111;
double MAX_TIME = 0.5 * CLOCKS_PER_SEC;
int MAXSIZE = 1024;

void printBinary(unsigned int num) {
	// 48位整数，从最高位开始逐位输出
	for (int bit = 47; bit >= 0; --bit) {
		printf("%d", (num >> bit) & 1);
		if (bit % 4 == 0) {
			printf(" "); // 添加空格以便阅读
		}
	}
	printf("\n");
}

u_short cksum(u_short* message, int size) {
	int count = (size + 1) / 2;//16位是两个字节
	u_long sum = 0;

	unsigned short* buf = (unsigned short*)malloc(size);
	memset(buf, 0, size);
	memcpy(buf, message, size);
	//防止message中的数据没有按照16位对其而导致的错误

	while (count--) {
		sum += *buf++;
		if (sum & 0xffff0000) {
			sum &= 0xffff;
			sum++;
		}
		//处理了反码溢出的情况
	}
	u_short result = ~(sum & 0xffff);
	return result;
}

#pragma pack(2)
class Header {
	/*
	根据数据长度选择类型：
	char-8位;short-16位;int-32位;long-32/64位;long long-64位
	*/
	unsigned short datasize = 0;
	//数据长度为16位，而int为32位所以不选择int
	unsigned short sum = 0;
	//校验和sum同样为16位
	unsigned char tag = 0;
	//tag为标志位，低三位分别为FIN,ACK,SYN
	unsigned char ack = 0;
	//ack为传输数据包的序号，0-255循环使用
public:
	Header() :datasize(0), sum(0), tag(0), ack(0) {};
	//初始化
	void set_tag(unsigned char tag) {
		this->tag = tag;
	}
	void clear_sum() {
		sum = 0;
	}
	void set_sum(unsigned short sum) {
		this->sum = sum;
	}
	unsigned char get_tag() {
		return tag;
	}
	unsigned short get_sum() {
		return sum;
	}
	void set_datasize(unsigned short datasize) {
		this->datasize = datasize;
	}
	void set_ack(unsigned char ack) {
		this->ack = ack;
	}
	int get_datasize() {
		return datasize;
	}
	unsigned char get_ack() {
		return ack;
	}
	void print_header() {
		printf("datasize:%d，ack:%d，tag:%d\n", get_datasize(), get_ack(),get_tag());
	}
};

class Packet {
private:
	Header header;
	char data_content[1024];
public:
	Packet() :header() { memset(data_content, 0, 1024); }
	Header get_header() {
		return header;
	}
	void set_datacontent(char* data_content) {
		memcpy(this->data_content, data_content, sizeof(data_content));
	}
	int get_size() {
		return sizeof(header) + header.get_datasize();
	}
	void print_pkt() {
		printf("bytes:%d\nseq:%d\n\n", header.get_datasize(), header.get_ack());
	}
	char* get_data_content() {
		return data_content;
	}
	void set_datasize(int datasize) {
		header.set_datasize(datasize);
	}
	int get_datasize() {
		return header.get_datasize();
	}
	void set_ack(unsigned char ack) {
		header.set_ack(ack);
	}
	u_char get_ack() {
		return header.get_ack();
	}
	void set_tag(unsigned char tag) {
		header.set_tag(tag);
	}
	void clear_sum() {
		header.clear_sum();
	}
	void set_sum(unsigned short sum) {
		header.set_sum(sum);
	}
	unsigned char get_tag() {
		return header.get_tag();
	}
	unsigned short get_sum() {
		return header.get_sum();
	}
	void printpacketmessage() {
		printf("Packet size=%d bytes，tag=%d，seq=%d，sum=%d，datasize=%d\n", get_size(), get_tag(), get_ack(), get_sum(), get_datasize());
	}
};

void printTime()
{
	// 获取当前系统时间
	std::time_t currentTime;
	std::time(&currentTime);

	// 本地时间获取
	std::tm localTimeInfo;
	localtime_s(&localTimeInfo, &currentTime);

	// 打印本地时间
	std::cout << "["
		<< localTimeInfo.tm_year + 1900 << '-' // 年份，需要加上1900
		<< localTimeInfo.tm_mon + 1 << '-'     // 月份，范围是0-11，所以需要加1
		<< localTimeInfo.tm_mday << ' '        // 日
		<< localTimeInfo.tm_hour << ':'        // 时
		<< localTimeInfo.tm_min << ':'         // 分
		<< localTimeInfo.tm_sec << "]" << std::endl;  // 秒
}

int connect(SOCKET& server, SOCKADDR_IN& client_addr, int& clientaddr_len) {
	printf("————————<begin connect>————————\n\n");

	Header header;
	char* recv_buffer = new char[sizeof(header)];

	//第一次握手：接受SYN
	while (true) {
		if (recvfrom(server, recv_buffer, sizeof(header), 0, (sockaddr*)&client_addr, &clientaddr_len) == -1)
		{
			printf("错误代码：%d", WSAGetLastError());
			return -1;
		}

		//进行检验和的检验并判断其中标志位是否为SYN
		memcpy(&header, recv_buffer, sizeof(header));
		if (header.get_tag() == SYN && cksum((u_short*)&header, sizeof(header)) == 0)
		{
			printTime();
			printf("[recv]\nSYN\n\n");
			break;
		}
	}

	char* send_buffer = new char[sizeof(header)];
	//第二次握手：发送SYN+ACK
	header.set_tag(ACK_SYN);
	header.clear_sum();
	header.set_sum(cksum((u_short*)&header, sizeof(header)));
	memcpy(send_buffer, &header, sizeof(header));
	if (sendto(server, send_buffer, sizeof(header), 0, (sockaddr*)&client_addr, clientaddr_len) == -1)
	{
		printf("[Failed send]\nACK & SYN\n\n");
		return -1;
	}
	printTime();
	printf("[send]\nSYN & ACK\n\n");

	//记录第二次握手的时间
	clock_t start = clock();

	//设置为非阻塞模式
	u_long mode = 1;
	ioctlsocket(server, FIONBIO, &mode);

	//第三次握手：接收ACK
	//memcpy(recv_buffer, 0, sizeof(recv_buffer));
	while (recvfrom(server, recv_buffer, sizeof(header), 0, (sockaddr*)&client_addr, &clientaddr_len) <= 0) {
		//进行超时检测
		//printf("%d", WSAGetLastError());
		if (clock() - start > MAX_TIME) {
			//超时，重新发送ACK+SYN
			printf("[time out]\nRetransmitting ACK & SYN again……………………\n\n");

			header.set_tag(ACK_SYN);
			header.clear_sum();
			header.set_sum(cksum((u_short*)&header, sizeof(header)));
			memcpy(send_buffer, &header, sizeof(header));
			if (sendto(server, send_buffer, sizeof(header), 0, (sockaddr*)&client_addr, clientaddr_len) == -1)
			{
				printf("[Failed send]\nACK & SYN\n\n");
				return -1;
			}
			//更新第二次握手的时间
			clock_t start = clock();
		}
	}

	//设置为阻塞模式
	mode = 0;
	ioctlsocket(server, FIONBIO, &mode);

	//接收到数据后：开始检验和检测和ACK的判断
	memcpy(&header, recv_buffer, sizeof(header));
	if (header.get_tag() == ACK && cksum((unsigned short*)&header, sizeof(header)) == 0) {
		printTime();
		printf("[recv]\nACK\n\n");
		printf("————————<connect!>————————\n\n");
		return 1;
	}
	else {
		printf("[Failed recv]\nACK\n\n");
		return -1;
	}
}

int disconnect(SOCKET& server, SOCKADDR_IN& client_addr, int clientaddr_len) {
	printf("————————<begin disconnect>————————\n\n");

	Header header;
	
	char* recv_buffer = new char[sizeof(header)];
	//第一次挥手：接收FIN
	while (true) {
		int length = recvfrom(server, recv_buffer, sizeof(header), 0, (sockaddr*)&client_addr, &clientaddr_len);
		memcpy(&header, recv_buffer, sizeof(header));
		if (header.get_tag()==FIN&&cksum((unsigned short*)&header,sizeof(header))==0){
			printTime();
			printf("[recv]\nFIN\n\n");
			break;
		}
	}

	char* send_buffer = new char[sizeof(header)];

	//开始第二次挥手：发送ACK
	header.set_tag(ACK);
	header.clear_sum();
	header.set_sum(cksum((unsigned short*)&header, sizeof(header)));
	memcpy(send_buffer, &header, sizeof(header));
	if (sendto(server, send_buffer, sizeof(header), 0, (sockaddr*)&client_addr, clientaddr_len) == -1) {
		return -1;
	}
	printTime();
	printf("[send]\nACK\n\n");

	//开始第三次挥手：发送FIN+ACK
	header.set_tag(ACK_FIN);
	header.clear_sum();
	header.set_sum(cksum((unsigned short*)&header, sizeof(header)));
	memcpy(send_buffer, &header, sizeof(header));
	if (sendto(server, send_buffer, sizeof(header), 0, (sockaddr*)&client_addr, clientaddr_len) == -1) {
		return -1;
	}
	clock_t start = clock();
	//记录第三次挥手的时间
	printTime();
	printf("[send]\nFIN & ACK\n\n");
	
	u_long mode = 1;
	ioctlsocket(server, FIONBIO, &mode);

	//开始第四次挥手：等待ACK
	while (recvfrom(server, recv_buffer, sizeof(header), 0, (sockaddr*)&client_addr, &clientaddr_len) <= 0) {
		//检测超时
		if (clock() - start > MAX_TIME) {
			printf("[time out]\nRetransmitting ACK & FIN again……………………\n\n");

			header.set_tag(ACK_FIN);
			header.clear_sum();
			header.set_sum(cksum((unsigned short*)&header, sizeof(header)));
			memcpy(send_buffer, &header, sizeof(header));
			if (sendto(server, send_buffer, sizeof(header), 0, (sockaddr*)&client_addr, clientaddr_len) == -1) {
				return -1;
			}
			clock_t start = clock();
			//记录第三次挥手的时间
			printTime();
			printf("[send]\nFIN & ACK\n\n");
		}
	}

	mode = 0;
	ioctlsocket(server, FIONBIO, &mode);

	//接收到信息，开始判断是否为ack且是否校验和是否为0
	memcpy(&header, recv_buffer, sizeof(header));
	if (header.get_tag() == ACK && cksum((u_short*)&header, sizeof(header)) == 0) {
		printTime();
		printf("[recv]\nACK\n\n");
		printf("————————<disconnect>————————\n\n");
		return 1;
	}
	else {
		//校验包出错
		printf("[Failed recv]\nACK\n\n");
		return -1;
	}
}

int recvdata(SOCKET& server,SOCKADDR_IN& client_addr,int&clientaddr_len,char* data) {
	printf("————————开始接收当前文件————————\n\n");
	Packet* recvpkt = new Packet();//接收传过来的数据包（带数据的那种）
	Header header;//发送的确认头（不带数据的那种）

	int seq_predict = 0;//seq_predict是期待收到的序列号（确认号）

	int file_len = 0;
	//目前已经保存的文件的长度——用于标识data应该从哪里开始存

	char* recv_buffer = new char[MAXSIZE + sizeof(recvpkt->get_header())];
	//接收缓存区
	char* send_buffer = new char[sizeof(header)];
	//发送缓存区

	while (true) {
		//循环接受所有的数据包，退出条件是数据包接收完毕
		int length = recvfrom(server, recv_buffer, sizeof(recvpkt->get_header())+MAXSIZE, 0, (SOCKADDR*)&client_addr, &clientaddr_len);
		if (length == -1) {
			printf("[Failed recv]\n");
		}

		memcpy(recvpkt, recv_buffer, sizeof(recvpkt->get_header()) + MAXSIZE);
		//判断是否结束，如果已经是最后一个包，则退出接收
		if (recvpkt->get_tag() == OVER && cksum((u_short*)recvpkt, sizeof(recvpkt->get_header()))==0) {
			printTime();
			printf("[recv]\nOVER\n\n");
			break;
		}

		//判断当前包是否是我们需要的包
		if (seq_predict!=int(recvpkt->get_ack())) {
			printTime();
			printf("该数据包重复发送，不进行存储！\n");
			continue;//这个包不做存储，继续接受下一个包
		}

		//这个包是我们需要的包，存储数据并打印提示信息
		printTime();
		printf("接收到目标数据包:\n");
		recvpkt->printpacketmessage();

		memcpy(data + file_len, recvpkt->get_data_content(), int(recvpkt->get_datasize()));
		//data+file_len表示数据应该从哪里开始存储
		//recvpkt->get_data_content()表示应该存储的数据
		//recvpkt->get_datasize()表示存储数据的长度

		//更新已存储文件长度
		file_len += recvpkt->get_datasize();

		//存储完毕，返回ACK以及当前文件的ack（seq）
		header.set_tag(ACK);
		header.set_datasize(0);
		header.clear_sum();
		
		//收到需要的包，返回的确认号为当前包的序列号
		header.set_ack((u_char)seq_predict);

		//计算cksum
		header.set_sum(cksum((u_short*) &header, sizeof(header)));

		memcpy(send_buffer, &header, sizeof(header));

		if (sendto(server, send_buffer, sizeof(header), 0, (SOCKADDR*)&client_addr, clientaddr_len)==-1) {
			printf("[Failed send]\n\n");
		}
		printTime();
		printf("已发送确认：\n");
		header.print_header();
		printf("\n");

		//更新seq和seq_predict
		//下一个期待接收到的包为当前期待接收到的包的序号+1，模256（0-255循环使用）
		seq_predict = (seq_predict + 1) % 256;

	}
	//文件接收完毕，发送OVER
	header.clear_sum();
	header.set_tag(OVER);
	header.set_datasize(0);
	header.set_sum((cksum((u_short*)&header, sizeof(header))));
	memcpy(send_buffer, &header, sizeof(header));
	if (sendto(server, send_buffer, sizeof(header), 0, (SOCKADDR*)&client_addr, clientaddr_len)==-1) {
		printf("[Failed send]\n\n");
		return -1;
	}
	printTime();
	printf("[send]\nOVER\n\n");
	printf("————————成功接收当前文件————————\n\n");
	return file_len;//返回读取的字节数，为了之后的存储数据
}

int main() {
	WSADATA wsadata;
	int error=WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (error != 0) {
		perror("WSAStartup Failed!");
		exit(1);
	}

	int port = 8080;
	SOCKADDR_IN server_addr;
	//存储服务器的地址信息

	SOCKET server = socket(AF_INET, SOCK_DGRAM, 0);
	//AF_INET：IPv4协议族
	//AF_INET6：IPv6协议族
	//SOCK_STREAM：字节流套接字，适用于TCP或SCTP协议
	//SOCK_DGRAM：数据报套接字，适用于UDP协议
	if (server == SOCKET_ERROR) {
		perror("create socket fail!");
		WSACleanup();
		exit(1);
	}

	server_addr.sin_family = AF_INET;//地址族
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	//32位IPv4地址
	//INADDR_ANY表示服务器将接受来自本地计算机上的任何网络接口的连接请求
	server_addr.sin_port = htons(port);

	if (bind(server, (SOCKADDR*)&server_addr, sizeof(server_addr)) == -1) {
		perror("Bind Failed!");
		closesocket(server);
		WSACleanup();
		exit(1);
	}

	printf("Server listening on port 8080...\n");
	//开始监听

	int len = sizeof(server_addr);
	connect(server, server_addr, len);

	char* name = new char[50];
	char* data = new char[1000000000];
	int namelen = recvdata(server, server_addr, len, name);
	int datalen = recvdata(server, server_addr, len, data);
	string a;
	for (int i = 0; i < namelen; i++)
	{
		a = a + name[i];
	}
	disconnect(server, server_addr, int(sizeof(server_addr)));
	ofstream fout(a.c_str(), ofstream::binary);
	for (int i = 0; i < datalen; i++)
	{
		fout << data[i];
	}
	fout.close();
	cout << "文件已成功下载到本地" << endl;
}