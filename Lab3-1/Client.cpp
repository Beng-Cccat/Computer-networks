#include<iostream>
#include <WINSOCK2.h>
#include <WS2tcpip.h>
#include <time.h>
#include <string>
#include<fstream>
using namespace std;
#pragma comment(lib,"ws2_32.lib")

const int MAXSIZE = 1024;
unsigned char FIN = 0b100;
unsigned char ACK = 0b10;
unsigned char SYN = 0b1;
unsigned char ACK_SYN = 0b11;
unsigned char ACK_FIN = 0b110;
unsigned char OVER = 0b111;
double MAX_TIME = 0.5 * CLOCKS_PER_SEC;

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
	int count = (size + 1) / 2;
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
	//tag为标志位，低三位分别为FIN,ACK,SYN，若全为1则是OVER
	unsigned char ack = 0;
	//ack为传输数据包的序号，0-255循环使用
public:
	Header() :datasize((u_short)0), sum((u_short)0), tag((u_char)0), ack((u_char)0) {};
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
		//printf("ack为%d\n", ack);
		this->ack = ack;
		//cout << "已设置ack=";
		//printf("%d\n", this->ack);
	}
	int get_datasize() {
		return datasize;
	}
	unsigned char get_ack() {
		return ack;
	}
	void print_header() {
		printf("datasize:%d，ack:%d\n", get_datasize(), get_ack());
	}
};

class Packet {
private:
	Header header;
	char data_content[MAXSIZE];
	//这里要用char数组而不能用指针，因为传过去的是数组中的内容而不是地址，（两个程序中的地址肯定不一样）
public:
	Packet():header(){
		memset(data_content,0,MAXSIZE); 
	}
	Header get_header() {
		return header;
	}
	void set_datacontent(char* data_content) {
		memcpy(this->data_content, data_content, header.get_datasize());
		//这里cpy的长度要是MAXSIZE/header.get_datasize()（但是要保证在每一次设置数据内容的时候头部数据中的数据大小已经初始化了）
	}
	int get_size() {
		return sizeof(header) + get_datasize();
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

int connect(SOCKET& client, SOCKADDR_IN& serv_addr, int& servaddr_len) {
	printf("————————<begin connect>————————\n\n");
	//三次握手建立连接
	Header header;
	//进行第一次握手：发送SYN
	header.set_tag(SYN);
	//置位
	header.clear_sum();
	//将校验和置0
	header.set_sum(cksum((unsigned short*)&header, sizeof(header)));

	char* send_buffer = new char[sizeof(header)];//创建发送缓存区
	/*
	注意这里sizeof(header)和sizeof(sned_buffer)不一样
	一个是指针所占的字节数，一个是类所占的字节数*/
	memcpy(send_buffer, &header, sizeof(header));//将header中的内容复制给发送缓存区
	if (sendto(client, send_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, servaddr_len) == -1)
	{
		printf("[Failed send]\nSYN\n\n");
		return -1;
	}
	printTime();
	printf("[send]\nSYN\n\n");
	/*
	int WSAAPI sendto(
	  [in] SOCKET         s,
	  [in] const char     *buf,
	  [in] int            len,
	  [in] int            flags,
	  [in] const sockaddr *to,
	  [in] int            tolen//由 to 参数指向的地址的大小（以字节为单位）
	);*/

	clock_t start = clock();
	//开启计时器

	/*此时默认是阻塞模式，当应用程序执行套接字操作（如读取或写入数据）时，操作会一直等待，直到它完成为止。*/
	u_long mode = 1;
	ioctlsocket(client, FIONBIO, &mode);

	//第二次握手：接收ACK+SYN
	//首先有一个超时重传
	char* recv_buffer = new char[sizeof(header)];
	while (recvfrom(client, recv_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, &servaddr_len) <= 0) {
		/*
		int recvfrom(
		  [in]                SOCKET   s,
		  [out]               char     *buf,
		  [in]                int      len,
		  [in]                int      flags,
		  [out]               sockaddr *from,
		  [in, out, optional] int      *fromlen
		);
		如果未发生错误， recvfrom 将返回收到的字节数。
		如果连接已正常关闭，则返回值为零。
		否则，将返回值 SOCKET_ERROR  */
		if (clock() - start > MAX_TIME) {
			//超时重传，重新进行第一次握手
			header.set_tag(SYN);
			header.clear_sum();
			header.set_sum(cksum((unsigned short*)&header, sizeof(header)));

			memcpy(send_buffer, &header, sizeof(header));//将header中的内容复制给发送缓存区
			if (sendto(client, send_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, servaddr_len) == -1)
			{
				printf("[Failed send]\nSYN\n\n");
				return -1;
			}
			start = clock();
			printf("[timeout]\nRetransmitting SYN……………………\n");
		}
	}

	mode = 0;
	ioctlsocket(client, FIONBIO, &mode);

	//如果没有超时的话，就进行校验和检验并且查看是否是0，且传回的头部中SYN和ACK是否置1
	memcpy(&header, recv_buffer, sizeof(header));
	if (header.get_tag() == ACK_SYN && cksum((unsigned short*)&header, sizeof(header)) == 0) {
		printTime();
		printf("[recv]\nSYN & ACK\n\n");

		//如果接收成功，进行第三次握手：发送ACK
		header.set_tag(ACK);
		header.clear_sum();
		header.set_sum(cksum((unsigned short*)&header, sizeof(header)));
		memcpy(send_buffer, &header, sizeof(header));//将header中的内容复制给发送缓存区
		if (sendto(client, send_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, servaddr_len) == -1)
		{
			printf("[Failed send]\nACK\n\n");
			return -1;
		}
		printTime();
		printf("[send]\nACK\n\n");
		printf("————————<connect!>————————\n\n");
		return 1;
	}
	else {
		//收到的数据包有误
		printf("[incorruptible]\nRetransmitting SYN……………………\n\n");
		return -1;
	}

}

int disconnect(SOCKET& client, SOCKADDR_IN& serv_addr, int servaddr_len) {
	printf("————————<begin disconnect>————————\n\n");

	Header header;
	char* send_buffer = new char[sizeof(header)];

	//进行第一次挥手：发送FIN
	header.set_tag(FIN);
	header.clear_sum();
	header.set_sum(cksum((u_short*)&header, sizeof(header)));
	memcpy(send_buffer, &header, sizeof(header));
	if (sendto(client, send_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, servaddr_len) == -1)
	{
		printf("[Failed send]\nFIN\n\n");
		return -1;
	}
	printTime();
	printf("[send]\nFIN\n\n");

	clock_t start = clock();
	//记录第一次挥手时间

	/*此时仍然默认为阻塞模式，需要设置为非阻塞模式*/
	u_long mode = 1;
	ioctlsocket(client, FIONBIO, &mode);

	//进行第二次挥手：接受ACK
	char* recv_buffer = new char[sizeof(header)];
	while (recvfrom(client, recv_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, &servaddr_len) <=0)
	{
		if (clock() - start > MAX_TIME)//超时，重新第一次挥手
		{
			header.set_tag(FIN);
			header.clear_sum();
			header.set_sum(cksum((u_short*)&header, sizeof(header)));
			memcpy(send_buffer, &header, sizeof(header));//将首部放入缓冲区
			if(sendto(client, send_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, servaddr_len))
			{
				printf("[Failed send]\nFIN\n\n");
				return -1;
			}
			start = clock();
			//更新时间
			printf("[timeout]\nRetransmitting FIN……………………\n\n");
		}
	}

	//进行校验和检验以及ACK
	memcpy(&header, recv_buffer, sizeof(header));
	if (header.get_tag() == ACK && cksum((unsigned short*)&header, sizeof(header) == 0)) {
		printTime();
		printf("[recv]\nACK\n\n");

	}
	else {
		//检验包出错
		printf("[Failed recv]\nACK\n\n");
		return -1;
	}

	//设置为阻塞模式
	mode = 0;
	ioctlsocket(client, FIONBIO, &mode);

	//进行第三次挥手：等待FIN+ACK
	while (recvfrom(client, recv_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, &servaddr_len) != SOCKET_ERROR) {
		//进行校验和检验，且对ACK标志位进行检测
		memcpy(&header, recv_buffer, sizeof(header));
		if (header.get_tag() == ACK_FIN && cksum((unsigned short*)&header, sizeof(header) == 0)) {
			//检测成功
			printTime();
			printf("[recv]\nFIN & ACK\n\n");

			//第四次挥手：发送ACK
			header.set_tag(ACK);
			header.clear_sum();
			header.set_sum(cksum((u_short*)&header, sizeof(header)));
			memcpy(send_buffer, &header, sizeof(header));//将首部放入缓冲区
			if (sendto(client, send_buffer, sizeof(header), 0, (sockaddr*)&serv_addr, servaddr_len)==-1)
			{
				printf("[Failed send]\nACK\n\n");
				return -1;
			}
			printTime();
			printf("[send]\nACK\n\n");
			start = clock();
			printf("Bye……………………\n\n");
			break;
		}
	}
	/*while (clock() - start == 2 * MSL) {
		printf("Bye……………………\n");
		break;
	}*/
	printf("————————<disconnect>————————\n\n");
	return 1;
}

int send_package(SOCKET& client, SOCKADDR_IN& server_addr, int& serveraddr_len, char* data_content, int datasize, int& seq) {
	//传输单个数据包：每个数据包=头部+数据
	//printf("%d\n", (u_char)seq);
	Packet* sendpkt = new Packet();
	//要发送的内容，包括头和数据部分
	
	//初始化数据头：
	sendpkt->set_datasize(datasize);//初始化数据长度
	sendpkt->clear_sum();//对序列号进行清零
	sendpkt->set_ack((unsigned char)seq);//初始化序列号seq，注意此时seq是u_char类型
	//sendpkt->print_pkt();
	//此时数据部分不为0，所以要等数据部分初始化后再开始计算校验和

	//初始化数据：
	sendpkt->set_datacontent(data_content);

	//初始化数据头的校验和：
	sendpkt->set_sum(cksum((u_short*)sendpkt, sendpkt->get_size()));

	//检验发送数据包
	printTime();
	printf("检查数据包内容：\n");
	sendpkt->printpacketmessage();

	//发送数据包
	if (sendto(client, (char*)sendpkt, sendpkt->get_size(), 0, (SOCKADDR*)&server_addr, serveraddr_len) == -1) {
		printf("[Failed send]\nPacket\n\n");
		return -1;
	}
	printTime();
	printf("已成功发送数据包：");
	sendpkt->printpacketmessage();

	//记录当前时间
	clock_t start = clock();

	Header* header=new Header();
	//等待接收ACK等信息，同时验证seq
	while (true) {
		//首先设置为非阻塞状态，不然recvfrom会一直停住
		//recvfrom() 函数在没有可用数据时将立即返回，而不会阻塞程序
		u_long mode = 1;
		ioctlsocket(client, FIONBIO, &mode);

		//首先进行超时检测
		while (recvfrom(client, (char*)header, MAXSIZE, 0, (SOCKADDR*)&server_addr, &serveraddr_len) <= 0) {
			//进行超时检测
			if (clock() - start > MAX_TIME) {
				//超时，重新发送数据
				printf("[timeout]\nRetransmitting Packet……………………\n");
				if (sendto(client, (char*)sendpkt, sendpkt->get_size(), 0, (SOCKADDR*)&server_addr, serveraddr_len) == -1) {
					printf("[Failed]\nPacket\n\n");
					return -1;
				}
				//重置发送时间
				start = clock();
			}
		}
		//接收到数据，进行序列号的检测和ACK的确认
		if (header->get_ack() == (u_char)seq && header->get_tag() == ACK) {
			printTime();
			printf("对方已接受到数据包并发送确认：");
			header->print_header();
			break;
		}
		else {
			continue;
		}
	}
	//改回阻塞模式
	u_long mode = 0;
	ioctlsocket(client, FIONBIO, &mode);

	return 1;
}
int send(SOCKET& client,SOCKADDR_IN& server_addr,int &serveraddr_len,char* data_content,int datasize) {
	//先算要发多少包：num=len/MAXSIZE+是否有余数（有余数就要多一个包）
	int package_num = datasize / MAXSIZE + (datasize % MAXSIZE == 0 ? 0 : 1);
	
	//确认号（序列号）从0开始
	int seqnum = 0;

	printf("——————即将开始发送当前文件——————\n\n");

	for (int i = 0; i < package_num; i++) {
		//循环发送所有分开后的数据包
		printf("即将发送当前文件中的第%d号数据包：\n", i);
		int len=0;//每次要发送数据包的长度，前面都为MAXSIZE，最后一次发送剩下的
		if (i == package_num - 1)
			len = datasize - (package_num - 1) * MAXSIZE;
		else
			len = MAXSIZE;

		//发送每一个数据包
		if (send_package(client, server_addr, serveraddr_len, data_content + i * MAXSIZE, len, seqnum) == -1) {
			//如果发送失败的话
			printf("[send package Failed]\n\n");
			//重新发送该数据包
			i--;
			continue;
		}
		//如果发送成功
		seqnum = (seqnum + 1) % 256;
		printf("当前文件中的第%d号数据包发送成功！\n\n", i);
	}

	//for循环结束，发送数据包结束，接着开始发送结束标志：over
	//初始化要发送的结束包：
	Header header;
	header.set_tag(OVER);
	header.set_datasize((u_short)0);
	header.set_ack((u_char)0);
	header.clear_sum();
	header.set_sum(cksum((u_short*)&header, sizeof(header)));

	//初始化要发送的数据：
	char* send_buffer = new char[sizeof(header)];
	memcpy(send_buffer, &header, sizeof(header));
	if (sendto(client, send_buffer, sizeof(header), 0, (SOCKADDR*)&server_addr, serveraddr_len) == -1) {
		printf("[Failed send]\nOVER\n\n");
		return -1;
	}
	printTime();
	printf("[send]\nOVER\n\n");

	//存储当前时间
	clock_t start = clock();

	u_long mode = 1;
	ioctlsocket(client, FIONBIO, &mode);

	char* recv_buffer = new char[sizeof(header)];

	while(true)
	{
		while (recvfrom(client, recv_buffer, sizeof(header), 0, (SOCKADDR*)&server_addr, &serveraddr_len) <= 0) {
			if (clock() - start > MAX_TIME) {
				printf("[timeout]\nresend OVER again……………………\n\n");
				if (sendto(client, send_buffer, sizeof(header), 0, (SOCKADDR*)&server_addr, serveraddr_len) == -1) {
					printf("[Failed send]\nOVER\n\n");
				}
				start = clock();
			}
		}

		mode = 0;
		ioctlsocket(client, FIONBIO, &mode);

		memcpy(&header, recv_buffer, sizeof(header));
		if (header.get_tag() == OVER && cksum((u_short*)&header, sizeof(header)) == 0) {
			printTime();
			printf("[recv]\nOVER\n\n");
			printf("——————对方已接受到文件——————\n\n");
			break;
		}
		else
			continue;
	}
	return 1;
}

int main() {
	SOCKADDR_IN server_addr;

	WSADATA wsadata;
	int err=WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (err != 0) {
		perror("WSAStartup Failed!");
		exit(1);
	}

	SOCKET server = socket(AF_INET, SOCK_DGRAM, 0);
	//建立套接字
	if (server == SOCKET_ERROR) {
		perror("create client failed!");
		WSACleanup();
		exit(1);
	}

	if (InetPton(AF_INET, TEXT("127.0.0.1"), &server_addr.sin_addr.s_addr) != 1)
		perror("ADDR Invalid!");
	//将点分十进制形式的IPv4地址转换为32位二进制形式的IP地址存储于server_addr的地址中
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8081);
	//初始化服务器端的ip地址和端口信息

	int len = sizeof(server_addr);
	if (connect(server, server_addr, len) == -1) {
		perror("Connection Failed!");
		exit(1);
	}

	string file;
	printf("请输入要传输的文件名称：\n");
	cin >> file;
	ifstream fin(file.c_str(), ifstream::binary);
	int ptr = 0;
	unsigned char temp = fin.get();
	int index = 0;
	char* buffer = new char[1000000000];
	while (fin) {
		buffer[index] = temp;
		temp = fin.get();
		index++;
	}
	fin.close();

	send(server, server_addr, len, (char*)(file.c_str()), file.length());
	
	clock_t start_data = clock();
	send(server, server_addr, len, buffer, index);
	clock_t end_data = clock();

	printf("传输时间：%ds\n", (end_data - start_data) / CLOCKS_PER_SEC);
	printf("吞吐率：%fbytes/s\n\n", ((float)index) / ((end_data - start_data) / CLOCKS_PER_SEC));
	disconnect(server, server_addr, int(sizeof(server_addr)));
}