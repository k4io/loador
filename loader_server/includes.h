#pragma once
#undef UNICODE

#define WIN32_LEAN_AND_MEAN


#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <iomanip>
#include <random>
#include <string>
#include <array>
#include <string_view>
#include <cstdlib>
#include <chrono>
#include <ctime>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#ifdef OPENSSL_NO_HMAC
#error HMAC is disabled.
#endif

#include "database.hpp"
#include "sqlite3.h"
#include <TlHelp32.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_PORT "51001"
#define DEFAULT_ALPHA_PORT "51069"

sqlitelib::Sqlite* p_db;
FILE* out_file;
const int BUFFERSIZE = 1024;
int i_connections = 0;
char* b1;
//long authkey = 0;


std::string								encryptDecrypt(std::string toEncrypt, long authkey);
void									manageConnection(SOCKET s, int clientnumber);
void									manageAlphaConnection(SOCKET s, int clientnumber);
std::string								hmac256(std::string data, std::string key);
static std::vector<unsigned char>		hmac_sha256(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);
long 									getBigLong();
std::vector<std::string>				GetModulesForUser(std::string username);

void sha256_string(char* string, char outputBuffer[65])
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Final(hash, &sha256);
	int i = 0;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
}
int64_t GetFileSize(const std::string& fileName) {
    FILE* f;
    if (fopen_s(&f, fileName.c_str(), "rb") != 0) {
        return -1;
    }
    _fseeki64(f, 0, SEEK_END);
    const int64_t len = _ftelli64(f);
    fclose(f);
    return len;
}
int SendBuffer(SOCKET s, const char* buffer, int bufferSize, int chunkSize = 4 * 1024) {

    int i = 0;
    while (i < bufferSize) {
        const int l = send(s, &buffer[i], __min(chunkSize, bufferSize - i), 0);
        if (l < 0) { return l; } // this is an error
        i += l;
    }
    return i;
}
int64_t SendFile(SOCKET s, const std::string& fileName, int chunkSize = 64 * 1024, std::string authkey = "slapemsmokey") {
    const int64_t fileSize = GetFileSize(fileName);
    if (fileSize < 0) { return -1; }

    std::ifstream file(fileName, std::ifstream::binary);
    if (file.fail()) { return -1; }

    if (SendBuffer(s, reinterpret_cast<const char*>(&fileSize),
        sizeof(fileSize)) != sizeof(fileSize)) {
        return -2;
    }

    char* buffer = new char[chunkSize];
    bool errored = false;
    int64_t i = fileSize;
    while (i != 0) {
        const int64_t ssize = __min(i, (int64_t)chunkSize);
        if (!file.read(buffer, ssize)) { errored = true; break; }

        std::string k = authkey;

        buffer[0] = buffer[0] ^ k[0];
        buffer[1] = buffer[1] ^ k[1];
        buffer[2] = buffer[2] ^ k[2];
        buffer[3] = buffer[3] ^ k[3];
        buffer[4] = buffer[4] ^ k[4];
        buffer[5] = buffer[5] ^ k[5];
        buffer[6] = buffer[6] ^ k[6];
        buffer[7] = buffer[7] ^ k[7];

        const int l = SendBuffer(s, buffer, (int)ssize);
        if (l < 0) { errored = true; break; }
        i -= l;
    }
    delete[] buffer;

    file.close();

    return errored ? -3 : fileSize;
}
std::vector<std::string> explode(std::string const& s, char delim)
{
    std::vector<std::string> result;
    std::istringstream iss(s);
    for (std::string token; std::getline(iss, token, delim); )
        result.push_back(std::move(token));
    
    return result;
}
inline bool exists(const std::string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}