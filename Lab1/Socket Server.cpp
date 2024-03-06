/*
1.创建套接字（使用 socket 函数）。
2.绑定套接字到本地地址和端口（使用 bind 函数）。
3.调用 listen 函数，将套接字设置为被动模式，准备接受连接请求。
4.进入一个循环，使用 accept 函数接受连接请求，并创建新的套接字用于与客户端通信。
5.在新的套接字上执行通信操作，如读取和写入数据。
6.当通信完成后，关闭连接的套接字（使用 closesocket 或 close，具体取决于操作系统）。
7.重复步骤 4 和 5，以处理更多的客户端连接请求。
*/
#include<iostream>
#include<winsock2.h>
#include<netioapi.h>
#include<Windows.h>
#include <Ws2tcpip.h>
#include<string.h>
#include<string>
using namespace std;

DWORD WINAPI handlerRequest(LPVOID lParam);
SOCKET* socket_arr = new SOCKET();
int socket_ptr = 0;
char** ip=new char*();
int* port_arr = new int();
int main(){
	int port = 8080;
	struct sockaddr_in server_addr;
	//存储服务器的地址信息
	struct sockaddr_in client_addr;
	//存储客户端的信息

	WSADATA wsadata;
	int err=WSAStartup(MAKEWORD(2, 2), &wsadata);
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

	SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
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
	server_addr.sin_addr.s_addr = INADDR_ANY;
	//32位IPv4地址
	//INADDR_ANY表示服务器将接受来自本地计算机上的任何网络接口的连接请求
	server_addr.sin_port = htons(port);

	if (bind(server,(struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
		perror("Bind Failed!");
		closesocket(server);
		WSACleanup();
		exit(1);
	}
	//将一个本地地址保存到socket，若无法保存输出错误信息

	listen(server, 5);

	printf("Server listening on port 8080...\n");
	//开始监听

	while (true) {
		//服务器会在一个循环中多次调用 accept，以接受多个客户端的连接请求
		//每个连接请求都会创建一个新的套接字，所以可以同时与多个客户端通信
		SOCKET sockconn = accept(server,(struct sockaddr*)&client_addr, NULL);
		//第二个参数是客户端地址，第三个参数是地址长度
		//如果不关心客户端信息，则可以设置为NULL
		
		if (sockconn != INVALID_SOCKET) {
			DWORD threadID;
			int clientAddressLength = sizeof(client_addr);

			getpeername(sockconn, (struct sockaddr*)&client_addr, &clientAddressLength);
			// 获取客户端的IP地址
			char clientIP[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(client_addr.sin_addr), clientIP, INET_ADDRSTRLEN);

			// 获取客户端的端口号
			int clientPort = ntohs(client_addr.sin_port);
			socket_arr[socket_ptr] = sockconn;
			ip[socket_ptr] = clientIP;
			port_arr[socket_ptr] = clientPort;
			socket_ptr++;

			printf("client connect! ip=%s，port=%d\n", clientIP, clientPort);
			HANDLE hThread = CreateThread(NULL, NULL, handlerRequest, LPVOID(sockconn), 0, &threadID);

			CloseHandle(hThread);
			//第一个NULL表示不需要特殊安全设置
			//第二个NULL表示新线程的堆栈大小默认
			//第三个参数：新线程的执行开始函数
			//第四个参数：传递给线程函数的参数
			//第五个参数： 用于控制线程的创建方式的标志
			//第六个参数：指向 DWORD 变量的指针，用于接收新线程的标识符
			//如果 CreateThread 函数成功创建了新线程，那么第六个参数指向的变量将包含新线程的标识符
		}
		else {
			perror("Accept Failed!");
		}
	}

	closesocket(server);
	WSACleanup();
	return 0;
}

DWORD WINAPI handlerRequest(LPVOID lParam) {
	SOCKET clientSocket = (SOCKET)lParam;
	int flag = 0;
	while (flag<socket_ptr) {
		if (clientSocket != socket_arr[flag])
			flag++;
		else
			break;
	}
	while (1) {
		char send_buff[1024];
		char recv_buff[1024];

		memset(recv_buff, 0, sizeof(recv_buff));
		int bytes_received = recv(clientSocket, recv_buff, sizeof(recv_buff) - 1, 0);
		if (strcmp(recv_buff,"exit;\0")==0) {//客户端关闭
			printf("client close! ip=%s port=%d \n", ip[flag], port_arr[flag]);
			memset(send_buff, 0, sizeof(send_buff));
			strcat_s(send_buff, "exit;");
			send(socket_arr[flag], send_buff, strlen(send_buff), 0);
			port_arr[flag] = 0;
			break;
		}
		else if (bytes_received == SOCKET_ERROR) {
			printf("Error receiving data from client.\n");
		}
		else {
			recv_buff[bytes_received] = '\0';
			printf("Received from client %s %d: %s\n", ip[flag], port_arr[flag], recv_buff);
		}
		// 处理接收到的数据

		memset(send_buff, 0, sizeof(send_buff));
		strcat_s(send_buff, "from client ip=");
		strcat_s(send_buff, ip[flag]);
		strcat_s(send_buff, " port=");
		strcat_s(send_buff, to_string(port_arr[flag]).c_str());
		strcat_s(send_buff, " ");
		strcat_s(send_buff, recv_buff);
		for(int i=0;i<socket_ptr;i++)
		{
			if (port_arr[i] == 0)
				continue;
			if (i == flag)
				continue;
			int bytes_sent = send(socket_arr[i], send_buff, strlen(send_buff), 0);
			if (bytes_sent == 0 || bytes_sent == SOCKET_ERROR) {
				perror("Error sending data to client.");
				return 0;
			}
			printf("sendto client %s %d successfully!\n", ip[i], port_arr[i]);
		}
	}
	closesocket(clientSocket);
	return 0;
}
