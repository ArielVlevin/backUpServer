#pragma once
#ifndef SERVER_H
#define SERVER_H


#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h> 



#define BUFFERSIZE 1024



class TCPClient {
private:
    SOCKET _socket;
    sockaddr_in server_address_info;
    WSADATA _wsa_data;
    std::string _ip_address;
    int _port;
public:
    
    TCPClient(const std::string ip_address = "127.0.0.1", int port = 1234);
    void updateServerData(std::string);
    void crateClientServer();
    bool connectToServer();
    SOCKET getSocket();
    void close();
    ~TCPClient() {
        close();
    }
};


#endif /* SERVER_H */