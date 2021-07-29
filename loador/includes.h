#pragma once
//global defines
#define WIN32_LEAN_AND_MEAN
#define getURL              URLOpenBlockingStreamA
#define BuffSize            512
#define DEFAULTPORT         55015

#define WHITE               7
#define RED                 4
#define BLACK               0
#define GREEN               10
#define YELLOW              14 
#define MAGENTA             13

//global includes

#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <intrin.h>
#include <tchar.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

//ssl - global 
#include <openssl/err.h>
#include <openssl/ssl.h>    
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "Memory/Memory.h"
//#include "str.hpp"

//global libs
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "urlmon.lib")

bool connected = false;
SSL* ssl;
BIO* bio;

static std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);

std::string         xorKey = "";
int authkey         = 0;

std::string WExePathStr() {
    TCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

std::string xored(std::string toEncrypt) {
    if (authkey == 0)
        xorKey = { '\x12', '\x01', '\xFF', '\x12', '\x01', '\x21' };
    else
        xorKey = std::to_string(authkey);
    std::string output = toEncrypt;

    for (int i = 0; i < toEncrypt.size(); i++)
        output[i] = (toEncrypt[i] ^ xorKey[i % xorKey.size()]);

    return output;
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

inline void ccolor(int textcol, int backcol)
{
    if ((textcol % 16) == (backcol % 16))textcol++;
    textcol %= 16; backcol %= 16;
    unsigned short wAttributes = ((unsigned)backcol << 4) | (unsigned)textcol;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    SetConsoleTextAttribute(hStdOut, wAttributes);
}

std::vector<std::string> explode(std::string const& s, char delim)
{
    std::vector<std::string> result;
    std::istringstream iss(s);

    for (std::string token; std::getline(iss, token, delim); )
    {
        result.push_back(std::move(token));
    }

    return result;
}

std::string getpass()
{
    const char BACKSPACE = 8;
    const char RETURN = 13;

    std::string password;
    unsigned char ch = 0;

    ccolor(WHITE, BLACK);
    printf("\n # ");
    ccolor(YELLOW, BLACK);
    printf("Password: ");
    ccolor(WHITE, BLACK);

    DWORD con_mode;
    DWORD dwRead;

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

    GetConsoleMode(hIn, &con_mode);
    SetConsoleMode(hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));

    while (ReadConsoleA(hIn, &ch, 1, &dwRead, NULL) && ch != RETURN)
    {
        if (ch == BACKSPACE)
        {
            if (password.length() != 0)
            {
                printf("\b \b");
                password.resize(password.length() - 1);
            }
        }
        else
        {
            password += ch;
            printf("*");
        }
    }
    printf("\n");
    return password;
}

//ssl funcs
void report_and_exit(const char* msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_ssl() {
    SSL_load_error_strings();
    SSL_library_init();
}

void cleanup(SSL_CTX* ctx, BIO* bio) {
    SSL_CTX_free(ctx);
    BIO_free_all(bio);
}

void sendpacket(BIO* bio, std::string request)
{
    BIO_puts(bio, xored(request).c_str());
}

int receivepacket(BIO* bio, char buf[BuffSize])
{
    int res = BIO_read(bio, buf, BuffSize);
    strcpy(buf, xored(buf).c_str());
    return res;
}

std::string cpuinfo()
{
    std::ostringstream _os;
    int CPUInfo[4] = { -1 };
    unsigned   nExIds, i = 0;
    char CPUBrandString[0x40];

    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    for (i = 0x80000000; i <= nExIds; ++i)
    {
        __cpuid(CPUInfo, i);
        // Interpret CPU brand string
        if (i == 0x80000002)
            memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
        else if (i == 0x80000003)
            memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
        else if (i == 0x80000004)
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
    }
    _os << CPUBrandString << "|";

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    _os << sysInfo.dwNumberOfProcessors << "|";

    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    _os << (statex.ullTotalPhys / 1024) / 1024 << "|";
    return _os.str();
}

std::string info()
{
    std::ostringstream os;
    os << cpuinfo();
    TCHAR volumeName[MAX_PATH + 1] = { 0 };
    TCHAR fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;
    if (GetVolumeInformation(
        _T("C:\\"),
        volumeName,
        ARRAYSIZE(volumeName),
        &serialNumber,
        &maxComponentLen,
        &fileSystemFlags,
        fileSystemName,
        ARRAYSIZE(fileSystemName)))
    {
        //string f = volumeName;
        os << "C:" << serialNumber << ":";
        char szString[MAX_COMPUTERNAME_LENGTH + 1];
        size_t nNumCharConverted;
        std::string s(fileSystemName);
        std::wstring ws(s.begin(), s.end());
        wcstombs_s(&nNumCharConverted, szString, 16, ws.c_str(), 16);
        os << szString << ":" << maxComponentLen << "|";
    }
    else throw;

    TCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(computerName[0]);
    if (GetComputerName(
        computerName,
        &size))
    {
        char szString[MAX_COMPUTERNAME_LENGTH + 1];
        size_t nNumCharConverted;
        std::string s(computerName);
        std::wstring ws(s.begin(), s.end());
        wcstombs_s(&nNumCharConverted, szString, 15, ws.c_str(), 15);
        os << szString << "|";
    }
    else throw;

    int cpuinfo[4] = { 0, 0, 0, 0 }; //EAX, EBX, ECX, EDX
    __cpuid(cpuinfo, 0);
    char16_t hash = 0;
    char16_t* ptr = (char16_t*)(&cpuinfo[0]);
    for (char32_t i = 0; i < 8; i++)
        hash += ptr[i];
    os << hash;

    return os.str();
}