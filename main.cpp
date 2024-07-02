#include <iostream>
#include "Client.h"
#include "FileHandler.h"
#include "Server.h"



int main() {

    int failed = 0;

    TCPClient clientserver;
    clientserver.updateServerData(File::getServerConnData());
    clientserver.crateClientServer();

    while (!(clientserver.connectToServer()) && ++failed < FAILTRY) {
        std::cout << "error an with responded server" << '\n';
    }

    if (failed < FAILTRY) {
        Client client(clientserver.getSocket());
        if (File::fileExist(FILEME))   // if me file exist
            client.login();
        else     // if the me file do not exist
            client.newRegister();

        std::cout << "\nServer ending stage: " << client.getServerStage() << "\n";

        clientserver.close();
    }else

    return 0;
}

