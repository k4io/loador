#include "Memory.h"

DWORD getProcess(std::string procName)
{
	PROCESSENTRY32 pe32{ 0 };
	pe32.dwSize = sizeof(pe32);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (!snap) 
	{
		printf("CreateToolhelp32Snapshot failed with code: 0x%X\n", std::to_string(GetLastError()));
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

	BYTE* pBase		= reinterpret_cast<BYTE*>(pData);
	auto* pOpt		= &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLib	= pData->pLoadLibA;
	auto _GetProc	= pData->pGetProcAddr;
	auto _DllMain	= reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* locDelta	= pBase - pOpt->ImageBase;

	if (locDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pReloc->VirtualAddress)
		{
			UINT amntOfEntry	= (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD));
			WORD* pRelInfo		= reinterpret_cast<WORD*>(pReloc + 1);
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
			char* szModule				= reinterpret_cast<char*>(pBase + pImportDesc->Name);
			HINSTANCE hDll				= _LoadLib(szModule);
			ULONG_PTR* pThunkRef		= reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
			ULONG_PTR* pFuncRef			= reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

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
	BYTE						*pSrcDat			= nullptr;
	IMAGE_NT_HEADERS			*pOldNtHeader		= nullptr;
	IMAGE_OPTIONAL_HEADER		*pOldOptHeader		= nullptr;
	IMAGE_FILE_HEADER			*pOldFileHeader		= nullptr;
	BYTE* pTargetBase = nullptr;

	DWORD dwCheck = 0;

	auto filesize = bytes->size();

	if (filesize < 0x1000)
	{
		printf("Invalid filesize!");
		return false;
	}

	pSrcDat = new BYTE[static_cast<UINT_PTR>(filesize)];
	if (!pSrcDat)
	{
		printf("Memory allocation failed: 0x%X", GetLastError());
		SleepEx(3000, 0);
		return 0;
	}
	pSrcDat = reinterpret_cast<BYTE*>(bytes->data());

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcDat)->e_magic != 0x5A4D) //0x5A4D == 'MZ' 
	{
		printf("Invalid file after cast!");
		SleepEx(3000, 0);
		//delete[] pSrcDat;
		return 0;
	}

	pOldNtHeader	= reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcDat + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcDat)->e_lfanew);
	pOldOptHeader	= &pOldNtHeader->OptionalHeader;
	pOldFileHeader	= &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) //not valid 64-bit file
	{
		printf("Invalid platform! (64-bit)");
		SleepEx(3000, 0);
		delete[] pSrcDat;
		return false;
	}   
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386) //not valid 32-bit file
	{
		printf("Invalid platform! (32-bit)");
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
			printf("Allocation failed (ex): 0x%X\n", GetLastError());
			SleepEx(3000, 0);
			delete[] pSrcDat;
			return 0;
		}
	}

	//sections
	MAP_DATA data{ nullptr };
	data.pLoadLibA			= LoadLibraryA;
	data.pGetProcAddr		= reinterpret_cast<f_GetProcAddr>(GetProcAddress);

	auto	*	pSectionHeader		= IMAGE_FIRST_SECTION(pOldNtHeader);

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
				printf("WriteProcessMemory failed: 0x%X\n", GetLastError());
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
		printf("Shellcode allocation failed: 0x%X\n", GetLastError());
		SleepEx(3000, 0);
		VirtualFreeEx(proc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	WriteProcessMemory(proc, pShellcode, shell, 0x1000, nullptr);

	//WriteProcessMemory(proc, pTargetBase, &data, sizeof(data), nullptr); //this will always work if the code gets to this point

	HANDLE hThread = CreateRemoteThread(proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);

	if (!hThread)
	{
		printf("CreateRemoteThread failed: 0x%X\n", GetLastError());
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