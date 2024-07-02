

#include "Server.h"




void TCPClient::crateClientServer() {
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &_wsa_data) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        exit(1);
    }

    _socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (_socket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        exit(1);
    }
    server_address_info.sin_family = AF_INET;
    server_address_info.sin_port = htons(_port);

    // Convert server address from string to binary format
    if (inet_pton(AF_INET, _ip_address.c_str(), &server_address_info.sin_addr) != 1) {
        std::cerr << "Invalid server address: " << _ip_address << std::endl;
        closesocket(_socket);
        WSACleanup();
        exit(1);
    }



}
TCPClient::TCPClient(const std::string ip_address, int port) {
    _ip_address = ip_address;
    _port = port;
}

void TCPClient::updateServerData(std::string serverConnData) {
    size_t colonPos = serverConnData.find(":");
    if (colonPos != std::string::npos) {
       // colon found, so split the string into IP and port
          _ip_address = serverConnData.substr(0, colonPos);
          _port = (stoi(serverConnData.substr(colonPos + 1)));
    }
}


bool TCPClient::connectToServer() {
    // Connect to server
    if ((connect(_socket, reinterpret_cast<const sockaddr*>(&server_address_info), sizeof(server_address_info))) == SOCKET_ERROR) {
        std::cerr << "Failed to connect to server: " << WSAGetLastError() << std::endl;
        closesocket(_socket);
        WSACleanup();
        return false;
    }
    return true;
}

SOCKET TCPClient::getSocket() {
    return _socket;
}


void TCPClient::close() {
    shutdown(_socket, SD_BOTH);
    closesocket(_socket);
    WSACleanup();
}

