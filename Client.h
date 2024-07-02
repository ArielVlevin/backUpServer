#pragma once
#ifndef CLIENT_H
#define CLEINT_H

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <functional>


#pragma comment(lib, "ws2_32.lib")

#include <winsock2.h>

////////////////////////////
/////////defines////////////
/////////////////////////s//

#define CLIENTVERSION 3

#define CODEREGISTER 1100
#define CODERSASENDING 1101
#define CODELOGIN 1102
#define CODEFILESENDING 1103
#define CODECRCOK 1104
#define CODECRCERROR1 1105
#define CODECRCERROR2 1106

#define CODEREGISTEROK 2100
#define CODEREGISTERFAILED 2101
#define CODERSASUCCESS 2102
#define CODECRCSUCCESS 2103
#define CODEFINISH 2104
#define CODELOGINFAILED 2106
#define CODEFAILED 2107

#define CLIENTIDSIZE 16
#define INPUTSIZE 997
#define AESSIZE 128
#define CKNUMINSTRUCT 276

#define FAILTRY 3
#define FUNCNUMLOGIN 4
#define FUNCNUMNEW 5

#define PROTOCOLMESSAGESIZE 1024

#define FIRSTEMPTYUID "0000000000000000"

#define NAMESIZE 255



typedef uint8_t uid[CLIENTIDSIZE];
typedef uint8_t input[INPUTSIZE];
typedef uint8_t aeskey[AESSIZE];


struct Clientmessage {
    uid id;
    char version;
    unsigned short code;
    unsigned int payload_size;
    input payload;
};

struct Servermessage {
    char version;
    unsigned short code;
    unsigned int payload_size;
    input payload;
};



class Client {
private:
    SOCKET _socket;
    Clientmessage _clientStruct;
    Servermessage _serverStruct;
    unsigned short _serverstage;
    unsigned int _clientCRC;
    unsigned int _serverCRC;
    std::vector<uint8_t>  _decryptedEASKey;
    using Func = std::function<void()>;

    Func existUser[4] = { [this]() { sendLoginRequest(); }, [this]() { sendFile(); }, [this]() { fileCRCHandle(); }, [this]() { finish(); } };
    Func newUser[5] = { [this]() { sendName(); }, [this]() { sendPublicKey(); },[this]() { sendFile(); }, [this]() { fileCRCHandle(); }, [this]() { finish(); } };

    Client() {
        _socket = NULL;
        _serverstage = 0;
        _clientStruct = {};
        _serverStruct = {};
        _clientCRC = 0;
        _serverCRC = 0;
        _decryptedEASKey = {};
    };
public:
    Client(SOCKET);
    ~Client();
    unsigned short getServerStage();
    unsigned short updateServerStage();
    void setID(uid&);

    void getData();

    void sendLoginRequest();

    void newRegister();
    void login();
    
    
    void sendName();
    void sendPublicKey();
    void sendMassage(unsigned short, unsigned int);
    void sendFile();

    void sendEncryptFile();
    void sendLargeData(const std::vector<uint8_t>&);
    void clientCRCcalculation();
    void fileCRCHandle();
    void finish();

};


#endif /* CLEINT_H */