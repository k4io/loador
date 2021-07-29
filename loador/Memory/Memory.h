#pragma once
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <TlHelp32.h>
#include <vector>

//#include "str.hpp"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef  _WIN64						//Relocation neccesity check
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif //  _WIN64

using f_LoadLibraryA			= HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddr				= UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName);
using f_DLL_ENTRY_POINT			= BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);


struct MAP_DATA
{
	f_LoadLibraryA				pLoadLibA;
	f_GetProcAddr				pGetProcAddr;
	HINSTANCE					hModule;
};

DWORD getProcess		(std::string procName);
bool _map				(HANDLE proc, std::vector<char>* bytes);
void __stdcall shell	(MAP_DATA* pData);

