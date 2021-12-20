#pragma once
//global defines
#define DISABLE_OUTPUT
#define WIN32_LEAN_AND_MEAN
#define getURL              URLOpenBlockingStreamA
#define BuffSize            1024
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
#include <fstream>
#include <vector>
#include <intrin.h>
#include <tchar.h>
#include <TlHelp32.h>

#include <filesystem>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#include <VMProtectSDK.h>

//ssl - global 
#include <openssl/err.h>
#include <openssl/ssl.h>    
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "xorstr.hpp"

#include <BlackBone/Process/Process.h>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/Syscalls/Syscall.h>
#include "li.hpp"

#include "ka-io/injector.h"

//global libs
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")
#pragma comment(lib, "urlmon.lib")

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef  _WIN64						//Relocation neccesity check
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif //  _WIN64

using namespace blackbone;

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddr = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

HRESULT URLDownloadToFile(
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	_Reserved_ DWORD                dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
);

struct MAP_DATA
{
    f_LoadLibraryA				pLoadLibA;
    f_GetProcAddr				pGetProcAddr;
    HINSTANCE					hModule;
};

bool connected = false;
SSL* ssl;
BIO* bio;

static std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);

std::string			allowed_characters = { 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','!','_','@','$','%','^','&','*', 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };
std::string         xorKey = { '\x12', '\x01', '\xFF', '\x12', '\x01', '\x21' };
long authkey        = 0;
std::string			authkeyHash = "";
std::string			m_username = "";
std::string			m_pwdhash = "";

int setenv(const char* name, const char* value, int overwrite)
{
	int errcode = 0;
	if (!overwrite) {
		size_t envsize = 0;
		errcode = getenv_s(&envsize, NULL, 0, name);
		if (errcode || envsize) return errcode;
	}
	return _putenv_s(name, value);
}

DWORD FindProcessId(std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processSnapshot);
	return 0;
}

DWORD EnumProcess(std::string name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 ProcessEntry = { NULL };
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	for (BOOL bSuccess = Process32First(hSnapshot, &ProcessEntry); bSuccess; bSuccess = Process32Next(hSnapshot, &ProcessEntry))
	{
		if (!strcmp(ProcessEntry.szExeFile, name.c_str()))
			return ProcessEntry.th32ProcessID;
	}

	return NULL;
}

bool IsProcessRunning(const wchar_t* processName)
{
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry)) {
			std::string s(entry.szExeFile);
			std::wstring ws(s.begin(), s.end());
			if (!_wcsicmp(ws.c_str(), processName))
				exists = true;
		}

	CloseHandle(snapshot);
	return exists;
}

std::string WExePathStr() {
    TCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

std::string xored(std::string toEncrypt) {
	if (authkey != 0)
		xorKey = std::to_string(authkey);
	std::string output = toEncrypt;

	for (int i = 0; i < toEncrypt.size(); i++)
		output[i] = (toEncrypt[i] ^ xorKey[i % xorKey.size()]);

	return output;
}

std::string zxored(std::string toEncrypt) {
	xorKey = xorstr("37dbc166ac0b1e91e28358bd3453d27c540f54478ea6421");
	std::string output = toEncrypt;

	for (int i = 0; i < toEncrypt.size(); i++)
		output[i] = (toEncrypt[i] ^ xorKey[i % xorKey.size()]);

	return output;
}

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
		sprintf(outputBuffer + (i * 2), xorstr("%02x"), hash[i]);
	}
	outputBuffer[64] = 0;
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

inline bool exists(const std::string& name) {
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
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

std::string getpass(const char* prompt = xorstr("Password: "), bool asterisk = true, bool f = false)
{
    const char BACKSPACE = 8;
    const char RETURN = 13;

    std::string password;
    unsigned char ch = 0;

    ccolor(WHITE, BLACK);
	if(!f)
		printf(xorstr("\n # "));
    ccolor(YELLOW, BLACK);
    printf(prompt);
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
				printf(xorstr("\b \b"));
                password.resize(password.length() - 1);
            }
        }
        else
        {
            password += ch;
			if (asterisk)
				printf(xorstr("*"));
			else printf(xorstr("%c"), ch);
        }
    }
    printf(xorstr("\n"));
    return password;
}

void killProcessByName(const char* filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
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

void sendpacket(SOCKET sockfd, std::string request)
{
	send(sockfd, xored(request).c_str(), BuffSize, 0);
}

int receivepacket(SOCKET sockfd, char buf[BuffSize])
{
	int res = recv(sockfd, buf, BuffSize, 0);
    strcpy(buf, xored(buf).c_str());
    return res;
}

int RecvBuffer(SOCKET s, char* buffer, int bufferSize, std::vector<char> &buf, int chunkSize = 4 * 1024) {
	int i = 0;
	while (i < bufferSize) {
		const int l = recv(s, &buffer[i], __min(chunkSize, bufferSize - i), 0);
		if (l < 0) { return l; } // this is an error
		i += l;
	}
	return i;
}

int64_t RecvFile(SOCKET s, std::vector<char> &buf, int chunkSize = 64 * 1024) {
	//std::string fileName = "out.dll";
	//std::ofstream file(fileName, std::ofstream::binary);
	//if (file.fail()) { return -1; }
	std::vector<char> v;
	int64_t fileSize;
	if (RecvBuffer(s, reinterpret_cast<char*>(&fileSize),
		sizeof(fileSize), v) != sizeof(fileSize)) {
		return -2;
	}

	char* buffer = new char[chunkSize];
	bool errored = false;
	int64_t i = fileSize;
	while (i != 0) {
		int _z = (int)__min(i, (int64_t)chunkSize);
		const int r = RecvBuffer(s, buffer, _z, buf);
		std::string k = std::to_string(authkey);
		buffer[0] = buffer[0] ^ k[0];
		buffer[1] = buffer[1] ^ k[1];
		buffer[2] = buffer[2] ^ k[2];
		buffer[3] = buffer[3] ^ k[3];
		buffer[4] = buffer[4] ^ k[4];
		buffer[5] = buffer[5] ^ k[5];
		buffer[6] = buffer[6] ^ k[6];
		buffer[7] = buffer[7] ^ k[7];
		for (size_t f = 0; f < _z; f++)
		{
			buf.push_back(buffer[f]);
		}
		if (r < 0) { errored = true; break; }
		i -= r;
	}
	delete[] buffer;

	return errored ? -3 : fileSize;
}
void strip_string(std::string& str)
{
	str.erase(std::remove_if(str.begin(), str.end(), [](int c) {return !(c > 32 && c < 127); }), str.end());
}
std::string getdriveinfo()
{
	std::string result = std::string(xorstr(""));

	HANDLE hDevice = li(CreateFileA)(xorstr("\\\\.\\PhysicalDrive0"), (DWORD)nullptr, FILE_SHARE_READ | FILE_SHARE_WRITE, (LPSECURITY_ATTRIBUTES)nullptr, OPEN_EXISTING, (DWORD)nullptr, (HANDLE)nullptr);

	if (hDevice == INVALID_HANDLE_VALUE) return result;

	STORAGE_PROPERTY_QUERY storagePropertyQuery;
	ZeroMemory(&storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY));
	storagePropertyQuery.PropertyId = StorageDeviceProperty;
	storagePropertyQuery.QueryType = PropertyStandardQuery;

	STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader = { 0 };
	DWORD dwBytesReturned = 0;

	li(DeviceIoControl)
		(
			hDevice,
			IOCTL_STORAGE_QUERY_PROPERTY,
			&storagePropertyQuery,
			sizeof(STORAGE_PROPERTY_QUERY),
			&storageDescriptorHeader,
			sizeof(STORAGE_DESCRIPTOR_HEADER),
			&dwBytesReturned,
			nullptr
			);

	const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
	BYTE* pOutBuffer = new BYTE[dwOutBufferSize];
	ZeroMemory(pOutBuffer, dwOutBufferSize);

	li(DeviceIoControl)
		(
			hDevice,
			IOCTL_STORAGE_QUERY_PROPERTY,
			&storagePropertyQuery,
			sizeof(STORAGE_PROPERTY_QUERY),
			pOutBuffer,
			dwOutBufferSize,
			&dwBytesReturned,
			nullptr
			);

	STORAGE_DEVICE_DESCRIPTOR* pDeviceDescriptor = (STORAGE_DEVICE_DESCRIPTOR*)pOutBuffer;

	if (pDeviceDescriptor->SerialNumberOffset)
	{
		result += std::string((char*)(pOutBuffer + pDeviceDescriptor->SerialNumberOffset));
	}

	if (pDeviceDescriptor->ProductRevisionOffset)
	{
		result += std::string((char*)(pOutBuffer + pDeviceDescriptor->ProductRevisionOffset));
	}

	if (pDeviceDescriptor->ProductIdOffset)
	{
		result += std::string((char*)(pOutBuffer + pDeviceDescriptor->ProductIdOffset));
	}

	uint32_t regs[4];
	__cpuid((int*)regs, 0);

	std::string vendor;

	vendor += std::string((char*)&regs[1], 4);
	vendor += std::string((char*)&regs[3], 4);
	vendor += std::string((char*)&regs[2], 4);

	result += std::string(vendor);

	strip_string(result);

	delete[] pOutBuffer;
	li(CloseHandle)(hDevice);

	return result;
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
        _T(xorstr("C:\\")),
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


    int cpuinfo[4] = { 0, 0, 0, 0 }; //EAX, EBX, ECX, EDX
    __cpuid(cpuinfo, 0);
    char16_t hash = 0;
    char16_t* ptr = (char16_t*)(&cpuinfo[0]);
    for (char32_t i = 0; i < 8; i++)
        hash += ptr[i];
    os << hash;

    return os.str();
}

DWORD getProcess(std::string procName)
{
	PROCESSENTRY32 pe32{ 0 };
	pe32.dwSize = sizeof(pe32);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!snap)
	{
		printf(xorstr("CreateToolhelp32Snapshot failed with code: 0x%X\n"), std::to_string(GetLastError()));
		SleepEx(3000, 0);
		return false;
	}

	BOOL ret = Process32First(snap, &pe32);
	DWORD PID = 0;
	while (ret)
	{
		if (!strcmp(procName.c_str(), pe32.szExeFile))
		{
			PID = pe32.th32ProcessID;
			break;
		}

		ret = Process32Next(snap, &pe32);
	}
	return PID;
}

void __stdcall shell(MAP_DATA* pData)
{
	if (!pData)
		return;

	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLib = pData->pLoadLibA;
	auto _GetProc = pData->pGetProcAddr;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* locDelta = pBase - pOpt->ImageBase;

	if (locDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pReloc->VirtualAddress)
		{
			UINT amntOfEntry = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD));
			WORD* pRelInfo = reinterpret_cast<WORD*>(pReloc + 1);
			for (UINT i = 0; i != amntOfEntry; ++i, ++pRelInfo)
			{
				if (RELOC_FLAG(*pRelInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pReloc->VirtualAddress + ((*pRelInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(locDelta);
				}
			}
			pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDesc->Name)
		{
			char* szModule = reinterpret_cast<char*>(pBase + pImportDesc->Name);
			HINSTANCE hDll = _LoadLib(szModule);
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProc(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProc(hDll, pImport->Name);
				}
			}
			++pImportDesc;
		}
	}

	//tls callbacks
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTlsDir = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTlsDir->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
		{
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}
	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hModule = reinterpret_cast<HINSTANCE>(pBase);

	return;
}

inline bool _map(HANDLE proc, std::vector<char>* bytes)
{
	BYTE* pSrcDat = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	DWORD dwCheck = 0;

	auto filesize = bytes->size();

	if (filesize < 0x1000)
	{
		printf(xorstr("Invalid filesize!"));
		return false;
	}

	pSrcDat = new BYTE[static_cast<UINT_PTR>(filesize)];
	if (!pSrcDat)
	{
		printf(xorstr("Memory allocation failed: 0x%X"), GetLastError());
		SleepEx(3000, 0);
		return 0;
	}

	pSrcDat = reinterpret_cast<BYTE*>(bytes->data());
	
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcDat)->e_magic != 0x5A4D) //0x5A4D == 'MZ' 
	{
		printf(xorstr("Invalid file after cast!"));
		SleepEx(3000, 0);
		//delete[] pSrcDat;
		return 0;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcDat + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcDat)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;
	
#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) //not valid 64-bit file
	{
		printf(xorstr("Invalid platform! (64-bit)"));
		SleepEx(3000, 0);
		delete[] pSrcDat;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) //not valid 32-bit file
	{
		printf(xorstr("Invalid platform! (32-bit)");
		SleepEx(3000, 0);
		delete[] pSrcDat;
		return false;
	}
#endif

	pTargetBase = reinterpret_cast<BYTE*>
		(VirtualAllocEx(proc,
			reinterpret_cast<void*>(pOldOptHeader->ImageBase),
			pOldOptHeader->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE)
			);

	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>
			(VirtualAllocEx(proc,
				nullptr,					//Attempt with nullptr
				pOldOptHeader->SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE)
				);

		if (!pTargetBase)
		{
			printf(xorstr("Allocation failed (ex): 0x%X\n", GetLastError()));
			SleepEx(3000, 0);
			delete[] pSrcDat;
			return 0;
		}
	}

	//sections
	MAP_DATA data{ nullptr };
	data.pLoadLibA = LoadLibraryA;
	data.pGetProcAddr = reinterpret_cast<f_GetProcAddr>(GetProcAddress);

	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	for (UINT i = 0; i < pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(proc,
				pTargetBase + pSectionHeader->VirtualAddress,
				pSrcDat + pSectionHeader->PointerToRawData,
				pSectionHeader->SizeOfRawData,
				nullptr))
			{
				printf(xorstr("WriteProcessMemory failed: 0x%X\n"), GetLastError());
				SleepEx(3000, 0);
				delete[] pSrcDat;
				VirtualFreeEx(proc, pTargetBase, 0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcDat, &data, sizeof(data));
	WriteProcessMemory(proc, pTargetBase, pSrcDat, 0x1000, nullptr);

	//delete[] pSrcDat;

	void* pShellcode = VirtualAllocEx(proc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		printf(xorstr("Shellcode allocation failed: 0x%X\n"), GetLastError());
		SleepEx(3000, 0);
		VirtualFreeEx(proc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(proc, pShellcode, shell, 0x1000, nullptr);

	//WriteProcessMemory(proc, pTargetBase, &data, sizeof(data), nullptr); //this will always work if the code gets to this point

	HANDLE hThread = CreateRemoteThread(proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);

	if (!hThread)
	{
		printf(xorstr("CreateRemoteThread failed: 0x%X\n"), GetLastError());
		SleepEx(3000, 0);
		VirtualFreeEx(proc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(proc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	HINSTANCE hCheck = 0;
	while (!hCheck)
	{
		MAP_DATA checked{ 0 };
		ReadProcessMemory(proc, pTargetBase, &checked, sizeof(checked), nullptr);
		hCheck = checked.hModule;
		SleepEx(10, false);
	}

	VirtualFreeEx(proc, pShellcode, 0, MEM_RELEASE);

	return true;
}
