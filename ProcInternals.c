/*
ProcInternals.c - simple reference point for retrieving/querying assets of a Windows process

includes:
-TEB
-PEB
-TIB
-File Headers
-TlsCallback Pointers
-Sections
-Import Directory
-Export Directory

alsch092 @ github
*/

#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <ImageHlp.h>
#include <tlhelp32.h>

#pragma comment(lib, "ImageHlp")

typedef LONG NTSTATUS;
typedef DWORD KPRIORITY;
typedef WORD UWORD;

void NTAPI __stdcall TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PVOID FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	UCHAR Spare2[0x4];
	ULARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	PVOID ProcessWindowStation;
} *_PPEB;

typedef struct TEB {
	PVOID Reserved1[12];
	PEB* ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} *PTEB;

typedef struct TIB {
	PVOID ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	PVOID FiberData;
	PVOID ArbitraryUserPointer;
	PVOID Self;
} *PTIB;

PEB* GetPEB()
{
	TEB* teb = (PTEB)__readgsqword(0x30); //Offset 0x30 points to the PEB field in the TEB
	PEB* peb = teb->ProcessEnvironmentBlock;
	return peb;
}

void *getTIB() 
{
#ifdef _M_IX86
	return (void *)__readfsdword(0x18);
#elif _M_AMD64
	return (void *)__readgsqword(0x30);
#else
#error unsupported architecture
#endif
}

void NTAPI __stdcall TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	DWORD threadId = GetCurrentThreadId();

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		printf("New process attached\n");
		break;

	case DLL_THREAD_ATTACH:
		printf("New thread spawned!\n");
		//ExitThread(0); //we can stop DLL injecting + DLL debuggers this way, but make sure you're handling your threads carefully.. uncomment line for added anti-debug + injection method!
		break;

	case DLL_THREAD_DETACH:
		printf("Thread detached!\n");
		break;
	};
}

void ParsePEB() 
{
	PEB* peb = GetPEB();

	printf("PEB Information (at 0x%llX):\n", (UINT64)peb);
	printf("OS Major Version: %u\n", peb->OSMajorVersion);
	printf("OS Minor Version: %u\n", peb->OSMinorVersion);
	printf("_______________________________\n");
}

void ParseTIB() 
{
	TIB* tib = (TIB*)getTIB();
	printf("TIB Information:\n");
	printf("Exception List: 0x%p\n", tib->ExceptionList);
	printf("Stack Base: 0x%p\n", tib->StackBase);
	printf("_______________________________\n");
}

//The Thread Environment Block (TEB structure) describes the state of a thread.
void ParseTEB()
{
	PTEB TEB = (PTEB)NtCurrentTeb();
	printf("TEB: %llX\n", (UINT64)TEB);
	printf("TEB->PEB: %llX\n", TEB->ProcessEnvironmentBlock);
	printf("TEB->TlsSlots: %llX\n", TEB->TlsSlots);
	printf("_______________________________\n");
}

//parses the Export Directory of the current module
void ParseExportDirectory(PCSTR Module) 
{
	DWORD* dNameRVAs(0); //array: addresses of export names
	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
	unsigned long cDirSize;
	_LOADED_IMAGE LoadedImage;
	char* sName;

	if (MapAndLoad(Module, NULL, &LoadedImage, TRUE, TRUE))
	{
		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

		if (ImageExportDirectory != NULL)
		{
			//load list of function names from DLL, the third parameter is an RVA to the data we want
			dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

			for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
			{
				sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);
				UINT64 funcName_Address = (UINT64)GetModuleHandleA(Module) + dNameRVAs[i]; //get VA From RVA + imagebase
				printf("Found function %s at %llX\n", sName, funcName_Address);
			}
		}
		else
		{
			printf("[ERROR] ImageExportDirectory was NULL!\n");
			UnMapAndLoad(&LoadedImage);
			return;
		}
	}
	else
	{
		printf("MapAndLoad failed: %d\n", GetLastError());
		return;
	}

	printf("_______________________________\n");
	UnMapAndLoad(&LoadedImage);
}

//Function to parse the Import Directory of the current module
void ParseImportDirectory() 
{
	HMODULE hModule = GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);

	IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (importDesc->OriginalFirstThunk != 0) 
	{
		char* moduleName = (char*)((BYTE*)hModule + importDesc->Name);
		printf("Imported module: %s\n", moduleName);

		IMAGE_THUNK_DATA* thunkData = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->OriginalFirstThunk);

		while (thunkData->u1.AddressOfData != 0) 
		{
			if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) 
			{
				printf("Imported by ordinal: %u\n", IMAGE_ORDINAL(thunkData->u1.Ordinal));
			}
			else 
			{
				IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)hModule + thunkData->u1.AddressOfData);
				printf("Imported by name: %s, %llx\n", importByName->Name, thunkData->u1.Function);
			}

			thunkData++;
		}

		importDesc++;
	}
}

void ParseSections() 
{
	HMODULE hModule = GetModuleHandle(NULL);
	
	if (!hModule) 
	{
		printf("Module error: %d\n", GetLastError());
		return;
	}

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

	IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) 
	{
		printf("Section Name: %s\n", sectionHeader->Name);
		printf("Virtual Address: 0x%llX\n", sectionHeader->VirtualAddress);
		printf("Virtual Size: 0x%llX\n", sectionHeader->Misc.VirtualSize);
		printf("Pointer to Raw Data: 0x%llX\n", sectionHeader->PointerToRawData);
		printf("Size of Raw Data: 0x%llX\n", sectionHeader->SizeOfRawData);
		printf("Characteristics: 0x%llX\n", sectionHeader->Characteristics);
		sectionHeader++;
	}
	printf("_______________________________\n");
}

void ModifyTlsCallbacks(UINT64 newTlsCallback) {
	
	// Load the image using MapAndLoad from dbghelp library
	LOADED_IMAGE loadedImage;
	if (!MapAndLoad(NULL, NULL, &loadedImage, TRUE, TRUE)) {
		printf("Failed to load the image.\n");
		return;
	}

	// Get the address of the TLS directory
	IMAGE_TLS_DIRECTORY32* tlsDirectory = (IMAGE_TLS_DIRECTORY32*)ImageDirectoryEntryToData(loadedImage.MappedAddress, FALSE, IMAGE_DIRECTORY_ENTRY_TLS, NULL);

	if (!tlsDirectory) {
		printf("Failed to locate the TLS directory.\n");
		UnMapAndLoad(&loadedImage);
		return;
	}

	// Modify the pointer to the TLS callback
	tlsDirectory->AddressOfCallBacks = newTlsCallback;

	// Unmap the image from memory, saving the changes
	if (!UnMapAndLoad(&loadedImage)) {
		printf("Failed to unmap and save the image.\n");
		return;
	}

	printf("TLS Callbacks modified successfully.\n");
}

//Function to parse the TLS callbacks of the current module
void ParseTLSCallbacks() 
{
	HMODULE hModule = GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);

	IMAGE_TLS_DIRECTORY* tlsDir = (IMAGE_TLS_DIRECTORY*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("TlsCallback Address: %llX\n", tlsDir->AddressOfCallBacks);
	printf("_______________________________\n");
}

inline PIMAGE_DOS_HEADER GetDosHeader() 
{
	TEB* teb = (PTEB)__readgsqword(0x30);
	PEB* peb = teb->ProcessEnvironmentBlock;
	return (PIMAGE_DOS_HEADER)(peb->ImageBaseAddress);
}

//get the TEB for a specific thread
PTEB GetThreadTeb(HANDLE hThread) 
{
	PTEB teb = nullptr;
	CONTEXT context = { };
	if (GetThreadContext(hThread, &context))	
		return (PTEB)context.SegFs;
	
	return nullptr;
}

//Function to get the TEB address for a specific thread
PVOID GetTebAddress(HANDLE hThread) 
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_SEGMENTS;

	if (GetThreadContext(hThread, &context)) 	
		return (PVOID)context.SegFs;
	
	return nullptr;
}

PTEB GetThreadTEB(HANDLE hThread)
{
	bool loadedManually = false;
	PTEB teb = nullptr;

	HMODULE module = GetModuleHandleA("ntdll.dll");

	if (!module)
	{
		module = LoadLibraryA("ntdll.dll");
		loadedManually = true;
	}

	NTSTATUS(__stdcall *NtQueryInformationThread)(HANDLE ThreadHandle, int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));

	if (NtQueryInformationThread)
	{
		NT_TIB tib = { 0 };
		THREAD_BASIC_INFORMATION tbi = { 0 };

		NTSTATUS status = NtQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), nullptr);
		if (status >= 0)
		{
			teb = (PTEB)tbi.TebBaseAddress;
			
			if (loadedManually)
			{
				FreeLibrary(module);
			}

			return teb;
		}
	}

	if (loadedManually)
	{
		FreeLibrary(module);
	}

	return nullptr;
}


//iterate all threads, do whatever with TEBs
void GetAllThreadTEBs()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) 
	{
		perror("Error creating thread snapshot");
		return;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnapshot, &threadEntry)) 
	{
		do 
		{
			if (GetCurrentProcessId() == threadEntry.th32OwnerProcessID) 
			{
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, threadEntry.th32ThreadID);
				if (hThread) 
				{
					PVOID tebAddress = GetThreadTEB(hThread);

					if (tebAddress) 
					{
						printf("Thread ID: %lu\nTEB Address: 0x%p\n", threadEntry.th32ThreadID, tebAddress);
					}
					else 
					{
						printf("Error getting TEB address for Thread ID: %lu\n", threadEntry.th32ThreadID);
					}

					CloseHandle(hThread);
				}
				else 
				{
					printf("Error opening thread: %lu\n", threadEntry.th32ThreadID);
				}
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}
	else 
	{
		perror("Error enumerating threads");
	}

	CloseHandle(hSnapshot);
}

void ParseHeaders()
{
	HMODULE hModule = GetModuleHandle(NULL);
	if (hModule == NULL)
	{
		perror("Error getting module handle");
		return;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER optHeader = (PIMAGE_OPTIONAL_HEADER)&ntHeader->OptionalHeader;
	PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)&ntHeader->FileHeader;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Not a valid PE file.\n");
		return;
	}
	else
	{
		printf("DOS Header Information:\n");
		printf("e_magic (Magic Number): 0x%X\n", dosHeader->e_magic);
		printf("e_lfanew (File address of PE Header): 0x%X\n", dosHeader->e_lfanew);
		printf("AddressOfEntryPoint: %llX\n", optHeader->AddressOfEntryPoint);
		printf("NumberOfSections: %llX\n", fileHeader->NumberOfSections);
	}

	printf("_______________________________\n");
}

int main()
{
	ModifyTlsCallbacks((UINT64)main);
	GetAllThreadTEBs();
	ParsePEB();
	ParseTIB();
	ParseHeaders();
	ParseSections();
	ParseTLSCallbacks();
	ParseExportDirectory("KERNEL32.dll");
	ParseImportDirectory();

	system("pause");
	return 0;
}
