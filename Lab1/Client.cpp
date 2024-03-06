/*
1.创建套接字：调用 socket 函数
2.指定服务器地址和端口：客户端需要知道服务器的地址（通常是IP地址或主机名）和端口号，以便连接到服务器(明确指定)。
3.连接到服务器：使用 connect 函数来与服务器建立连接
4.进行数据传输:使用套接字进行数据传输
5.处理连接关闭：调用 close 函数来关闭套接字连接
*/
#include<iostream>
#include<winsock2.h>
#include<netioapi.h>
#include <Ws2tcpip.h>
#include<string.h>
#include<string>
using namespace std;

DWORD WINAPI handlerSend(LPVOID lParam);
int main() {
	struct sockaddr_in server_addr;
	WSADATA wsadata;
	int err = WSAStartup(MAKEWORD(2, 2), &wsadata);
	//MAKEDORD用于创建一个16位的版本号值
	//以指定你希望使用的Winsock库的版本
	//第一个参数表示winsock的主要版本号，常用于指定winsock的主要功能
	//第二个参数表示次要版本号，指定次要功能
	//后一个参数指向WSADATA数据结构的指针,该数据结构将接收Windows套接字实现的详细信息。
	if (err != 0) {
		perror("WSAStartup Failed!");
		exit(1);
	}
	//初始化Socket DLL，协商使用的Socket版本，若失败则报错

	SOCKET client=socket(AF_INET, SOCK_STREAM, 0);
	//建立套接字
	if (client == SOCKET_ERROR) {
		perror("create client failed!");
		WSACleanup();
		exit(1);
	}
	if (InetPton(AF_INET, TEXT("127.0.0.1"), &server_addr.sin_addr) != 1)
		perror("ADDR Invalid!");
	//将点分十进制形式的IPv4地址转换为32位二进制形式的IP地址存储于server_addr的地址中
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(8080);
	//初始化服务器端的ip地址和端口信息

	if (connect(client, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
		perror("Connection Failed!");
		exit(1);
	}
	printf("connect successful!\n");

	DWORD threadID;
	HANDLE hThread = CreateThread(NULL, NULL, handlerSend, LPVOID(client), 0, &threadID);
	CloseHandle(hThread);
	while (1) {
		char recv_buff[1024];

		memset(recv_buff, 0, sizeof(recv_buff));
		int bytes_received = recv(client, recv_buff, sizeof(recv_buff) - 1, 0);
		recv_buff[bytes_received] = '\0';

		if (strcmp(recv_buff, "exit;\0") == 0)
			break;
		if (bytes_received > 0)
			printf("Received from server: %s\n", recv_buff);
		else
			perror("Sorry, there was an error receiving data ");

	}
	closesocket(client);
	WSACleanup();
	return 0;
}

DWORD WINAPI handlerSend(LPVOID lParam) {
	SOCKET client = (SOCKET)lParam;
	while (1) {
		string temp;
		char send_buff[1024];
		char flag_str[6];

		getline( cin,temp);
		strncpy_s(flag_str, temp.c_str(), 5);

		if (strcmp(flag_str, "exit;\0") != 0 && strcmp(flag_str, "send:\0") != 0) {
			printf("unknown order!\n");
			continue;
		}
		else if (strcmp(flag_str, "exit;\0") == 0) {
			strncpy_s(send_buff, flag_str,5);
			send(client, send_buff, strlen(send_buff), 0);
			break;
		}
		strncpy_s(send_buff, temp.c_str() + 5, sizeof(temp) - 5);

		if (strlen(send_buff) > 1024)
			perror("send_buff out of bound!");

		if (send(client, send_buff, strlen(send_buff), 0) > 0)
			printf("send successfully!\n");
		else
			perror(" Sorry, there was an error sending data!\n");


	}
	printf("end successfully!\n");
	closesocket(client);
	WSACleanup();
	return 0;
}