// dllmain.cpp : Defines the entry point for the DLL application.
// original code by: timb3r
// website: https://guidedhacking.com/threads/how-to-hook-import-address-table-iat-hooking.13555/

#include "stdafx.h"
#include <stdio.h>
#include <string.h>

#define PtrFromRva( base, rva ) ( ( ( PBYTE ) base ) + rva )

BOOL HOOKED = FALSE;

int EnableWrite(int* offset, int size) {
	unsigned long prevPerm;
	if (!VirtualProtect(offset, size, PAGE_EXECUTE_READWRITE, &prevPerm)) return 0;
	return prevPerm;
}

//just make sure our replacement function prototype matchs expected 
//int _cdecl m_strcmp(const char * arg1, const char* arg2) {
//
//	char buf[200];
//	sprintf_s(buf, "Inside hooked m_strcmp.\n\nArg1=%s\nArg2=%s", arg1, arg2);
//	MessageBox(0, (LPCWSTR)&buf[0], L"", 0);
//
//	return strcmp(arg1, arg2); //also we could fake return value if want
//}

DWORD WINAPI CreateMessageBox(LPCWSTR lpParam) {
	MessageBox(NULL, lpParam, L"Dll says:", MB_OK);
	return 0;
}

int _cdecl multiply(int code) {
	return code * 20;
}

BOOL HookIAT(const char *szModuleName, const char *szFuncName, PVOID pNewFunc, PVOID *pOldFunc)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)PtrFromRva(pDosHeader, pDosHeader->e_lfanew);

	// Make sure we have valid data
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	// Grab a pointer to the import data directory
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)PtrFromRva(pDosHeader, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (UINT uIndex = 0; pImportDescriptor[uIndex].Characteristics != 0; uIndex++)
	{
		char *szDllName = (char*)PtrFromRva(pDosHeader, pImportDescriptor[uIndex].Name);

		// Is this our module?
		if (_strcmpi(szDllName, szModuleName) != 0)
			continue;

		if (!pImportDescriptor[uIndex].FirstThunk || !pImportDescriptor[uIndex].OriginalFirstThunk)
			return FALSE;

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)PtrFromRva(pDosHeader, pImportDescriptor[uIndex].FirstThunk);
		PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)PtrFromRva(pDosHeader, pImportDescriptor[uIndex].OriginalFirstThunk);

		for (; pOrigThunk->u1.Function != NULL; pOrigThunk++, pThunk++)
		{
			// We can't process ordinal imports just named
			if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				continue;

			PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)PtrFromRva(pDosHeader, pOrigThunk->u1.AddressOfData);

			// Is this our function?
			if (_strcmpi(szFuncName, (char*)import->Name) != 0)
				continue;

			DWORD dwJunk = 0;
			MEMORY_BASIC_INFORMATION mbi;

			// Make the memory section writable
			VirtualQuery(pThunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect))
				return FALSE;

			// Save the old pointer
			*pOldFunc = (PVOID*)(DWORD_PTR)pThunk->u1.Function;

			// Write the new pointer based on CPU type
#ifdef _WIN64
			pThunk->u1.Function = (ULONGLONG)(DWORD_PTR)pNewFunc;
#else
			pThunk->u1.Function = (DWORD)(DWORD_PTR)pNewFunc;
#endif

			if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwJunk))
				return TRUE;
		}
	}
	return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

	CreateMessageBox(L"DLL Loaded");
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		if (!HOOKED) {
			PVOID pOldProc;
			if (!HookIAT("dummylibC.dll", "multiply", (PVOID)multiply, &pOldProc)) {
				CreateMessageBox(L"load failure");
			}
			CreateMessageBox(L"load success!");

			HOOKED = TRUE;
		}

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

