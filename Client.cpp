#include "Client.h"
#include "KeyHandler.h"
#include "FileHandler.h"
#include "Server.h"


Client::Client(SOCKET socket)
{   
    _socket = socket;
    uid id;
    std::memcpy(id, &FIRSTEMPTYUID, sizeof(uid));
    setID(id);
    _clientStruct.version = CLIENTVERSION;
    _clientStruct.code = CODEREGISTER;
    _clientStruct.payload_size = CLIENTIDSIZE;
    _decryptedEASKey = {};
    _serverstage = CODEREGISTEROK;
    
}
Client::~Client() {

}

unsigned short Client::getServerStage() {
    return _serverstage;
}

unsigned short Client::updateServerStage() {
    _serverstage = _serverStruct.code;
    return _serverstage;
}

void Client::newRegister() {
    int funcnumber = 0, failed = 0;
    std::cout << '\n' << "New Register!" << "\n";

    while (funcnumber < FUNCNUMNEW && failed < FAILTRY) {
        newUser[funcnumber]();
        if (_serverstage == CODEREGISTERFAILED)   return;
        else if (_serverstage == CODEFAILED) {
            std::cout << '\n' << "error an with responded server " << "\n";
            failed++;
        }else {
            funcnumber++;
            failed = 0;
        }
    }

}

void Client::login() {
    int funcnumber = 0, failed = 0, crcfailed = 0;
    std::cout << '\n' << "User exist!" << "\n";

    while (funcnumber < FUNCNUMLOGIN && failed < FAILTRY) {
        existUser[funcnumber]();
        if (_serverstage == CODELOGINFAILED)   return newRegister();
        else if (_serverstage == CODEFAILED) {
            std::cout << "\nerror an with responded server \n";
            failed++;
        }
        else if(funcnumber == 2){
            if (_serverCRC != _clientCRC) {
                if (++crcfailed == FAILTRY) funcnumber++;
            }else funcnumber++;
        }else {
            funcnumber++;
            failed = 0;
        }
    }
    if (failed >= FAILTRY)
        std::cout << '\n' << "failed to finish " << "\n";
}

/*else if (funcnumber = 2 && _serverCRC != _clientCRC) {
            std::cout << "\nproblem with crc calculation, sending the file again\n";
            if (++crcfailed == FAILTRY)    funcnumber++;
        }
*/









void Client::getData() {
    if ((recv(_socket, (char*)&_serverStruct, BUFFERSIZE, 0)) < 0)     std::cerr << "Failed to receive data from server" << std::endl;
    updateServerStage();
}

void Client::setID(uid &id) {
    std::memcpy(_clientStruct.id, &id, sizeof(uid));
}


void Client::sendMassage(unsigned short code, unsigned int payload_size) {
    _clientStruct.code = code;
    _clientStruct.payload_size = payload_size;

    char buffer[sizeof(Clientmessage)];
    std::memcpy(buffer, &_clientStruct, sizeof(Clientmessage));
    send(_socket, buffer, sizeof(Clientmessage), 0);
}


void Client::sendName() {
    std::memcpy(&_clientStruct.payload[0], &File::getUserName()[0], NAMESIZE);
    sendMassage(CODEREGISTER, NAMESIZE);
    getData();
}

void Client::clientCRCcalculation() {
    _clientCRC = File::crc32File(File::read_file(FILETRANSFER)[2].data());
}


void Client::sendPublicKey() {
    RSAKey rsa;
    uid id;
    //coppy the uid from the server to Client
    std::memcpy(&id, &_serverStruct.payload[0], sizeof(uid));
    setID(id);

    //crate rsa private&public keys and save to files
    std::string hexeduid = Hex::stringToHex(std::begin(id), std::end(id));
    File::crateMeFile(File::read_file(FILETRANSFER)[1], hexeduid, rsa.savePrivateKey());
    
    // send the second msg
    std::string publickey = rsa.getPublicKey();
    std::memcpy(&_clientStruct.payload[0], &File::getUserName()[0], NAMESIZE);
    std::memcpy(&_clientStruct.payload[NAMESIZE], &publickey[0], publickey.length());
    sendMassage(CODERSASENDING, NAMESIZE + RSASIZE);
    getData();
}


void Client::sendLoginRequest() {
    uid id;
    std::vector<uint8_t> bytes = Hex::hexToBytes(File::getId());
    std::copy(bytes.begin(), bytes.end(), id);
    setID(id);

    std::memcpy(&_clientStruct.payload[0], &File::getUserNameM()[0], NAMESIZE);
    sendMassage(CODELOGIN, NAMESIZE);
    getData();
}



void Client::finish() {
    
    if (_serverCRC == _clientCRC)    // code 1104
        sendMassage(CODECRCOK, NAMESIZE);
    else {                           // code 1106
        sendMassage(CODECRCERROR2, NAMESIZE);
        std::cout << '\n' << "Exit after 3 time calculate wrong!" << "\n";
    }
    getData();
}



void Client::fileCRCHandle() {
    
    // calculate client file crc
    clientCRCcalculation();
    // copy the file name and the server crc from struct
    std::memcpy(&_clientStruct.payload[0], &_serverStruct.payload[sizeof(uid) + sizeof(int)], NAMESIZE);
    std::memcpy(&_serverCRC, &_serverStruct.payload[CKNUMINSTRUCT], sizeof(int));
    if (_serverCRC != _clientCRC) { //if there is problem in crc calculation send the file again
        sendMassage(CODECRCERROR1, NAMESIZE);
        sendEncryptFile();
        getData();
    }
}



void Client::sendFile() {
    std::string file_name = (File::read_file(FILETRANSFER)[2]);
    //if the private key file or the file we asked to send do not exist
    if (!File::fileExist(file_name) || !File::fileExist(PRIVATEKEYFILE) ) {
        _serverstage = CODEFAILED;
        return;
    }
    aeskey serverAESKey;
    // copy the key from the file
    std::string decodedPrivateKey = Base64::decode(RSAKey::loadPrivateKey());
    // copy the aes key from the payload and decrypt
    std::memcpy(&serverAESKey[0], &_serverStruct.payload[sizeof(uid)], sizeof(serverAESKey));
    // encrypt file and send to server
    _decryptedEASKey = RSAKey::decryptAesKey(decodedPrivateKey, serverAESKey, sizeof(serverAESKey));
    sendEncryptFile();
    getData();
}


std::vector<uint8_t> structToBytes(const Clientmessage& s, int size ) {
    std::vector<uint8_t> bytes;
    bytes.resize(size);
    std::memcpy(bytes.data(), &s, size);
    return bytes;
}


void Client::sendEncryptFile() {
    std::string file_name = (File::read_file(FILETRANSFER)[2]);
    std::vector<uint8_t> file_data_encrypt = aesEncrypt(File::file_open(file_name), _decryptedEASKey);

    int file_size = file_data_encrypt.size();
    std::memcpy(&_clientStruct.payload[0], &file_size, sizeof(int));
    std::memcpy(&_clientStruct.payload[sizeof(int)], &File::remove_path(file_name)[0], NAMESIZE);
    _clientStruct.code = CODEFILESENDING;
    _clientStruct.payload_size = sizeof(int) + NAMESIZE + file_size;

    // Convert struct without the file to vector of bytes and insert to the encrypt vector
    std::vector<uint8_t> structBytes = structToBytes(_clientStruct, NAMESIZE + sizeof(int) + sizeof(uid)+ sizeof(char) +sizeof(unsigned short)+sizeof(unsigned int)); 
    file_data_encrypt.reserve(file_data_encrypt.size() + structBytes.size());
    file_data_encrypt.insert(file_data_encrypt.begin(), structBytes.begin(), structBytes.end());
    sendLargeData(file_data_encrypt);
}


void Client::sendLargeData(const std::vector<uint8_t>& data) {
    unsigned int bytesSent = 0;
    while (bytesSent < data.size()) {
        int size = static_cast<int>(data.size() - bytesSent);
        int bytesToSend = min(BUFFERSIZE, size);
        const char* chunkData = reinterpret_cast<const char*>(data.data() + bytesSent);
        int sendResult = send(_socket, chunkData, bytesToSend, 0);
        if (sendResult == SOCKET_ERROR) {
            std::cerr << "Error sending data\n";
            return;
        }
        bytesSent += sendResult;
    }
}

