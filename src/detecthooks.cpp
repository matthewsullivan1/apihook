
/*
Workflow for unhooking
    - Need unhooking DLL present with stub
    - Either on disk or encrypted within the stub
    - Does DLL need to be injected in the manually mapped PE ? Or the parent process that is running the PE
    - Either way, the DLL needs to be injected before the PE is executed

    - Detecting hooks
        - get clean version of function (somehow)
        - compare to the version returned from the DLL in memory
    
    - Unhooking
        - restore in memory version to clean verison

    - bypassing hooks
        - use syscall stubs or undocumented WinAPI calls



    Testing
        Detection
            - Need to hook a few calls - use hooking DLL and DLL injector
            - need helper function to obtain clean version of hooked function
            - need helper function to compare clean version to version in memory


        unhooking
            - have the DLL injected that hooks the calls
            - run the 


    - lets start with just printing the funciton setup to see the hook
    - the hooking DLL needs to be injected into this process


*/

#include <iostream>
#include <Windows.h>
#include <psapi.h>

using namespace std;

typedef NTSTATUS (WINAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);



void checkNtdll(){
	PDWORD functionAddress = (PDWORD)0;
	
	// Get ntdll base address
	//HMODULE libraryBase = LoadLibraryA("ntdll");
    HMODULE libraryBase = LoadLibraryA("ntdll");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	// Locate export address table
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Offsets to list of exported functions and their names
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions of ntdll
	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
	{
		// Resolve exported function name
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		
		// Resolve exported function address
		DWORD_PTR functionAddressRVA = 0;
		functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

		// Syscall stubs start with these bytes
		unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

		// Only interested in Nt|Zw functions
		if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0)
		//if (strncmp(functionName, (char*)"NtAllocateVirtualMemory", 23) == 0)
        {
			
        //cout << "Checking "<< functionName << endl;
        // Check if the first 4 instructions of the exported function are the same as the sycall's prologue
        if (memcmp(functionAddress, syscallPrologue, 4) != 0) {

            unsigned char firstByte = *((unsigned char*)functionAddress);

            if(firstByte == 0xE9){
                DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));
                PDWORD jumpTarget = functionAddress + 5;
                char moduleNameBuffer[512];
                GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
                
                printf("Hooked with relative jump: %s : %p into module %s\n", functionName, functionAddress, moduleNameBuffer);
            } else if (firstByte == 0x48 && *((unsigned char*)functionAddress + 1) == 0xB8) {
                // Check for mov rax, <address>
                void* hookAddress = *(void**)((char*)functionAddress + 2);
                printf("Hooked with absolute JMP via rax: %s : %p, Hook Address: %p\n", functionName, functionAddress, hookAddress);
            } else {
                // Unusual prologue, potentially hooked
                printf("Potentially hooked: %s : %p\n", functionName, functionAddress);
            }
			

                /*
				if (*((unsigned char*)functionAddress) == 0xE9) // first byte is a jmp instruction, where does it jump to?
				{
					DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));
					PDWORD jumpTarget = functionAddress + 5  + jumpTargetRelative; //Instruction pointer after our jmp instruction  
					char moduleNameBuffer[512];
					GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);
					
					printf("Hooked: %s : %p into module %s\n", functionName, functionAddress, moduleNameBuffer);
				}
				else
				{
					printf("Potentially hooked: %s : %p\n", functionName, functionAddress);
				}
                */
			}
		}
	}
}

int main()
{
    cout << "inject dll\n";
    cin.get();


    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if(!hNtdll){
        cerr << "Failed to get handle to ntdll.dll with error " << GetLastError();
        return 1;
    }

    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    if(!NtAllocateVirtualMemory){
        cerr << "Failed to resolve address of NtAllocateVirtualMemory with error " << GetLastError() << endl;
        return 1;
    }

    HANDLE processHandle = GetCurrentProcess();
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;
    ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_READWRITE;

    NTSTATUS status = NtAllocateVirtualMemory(
        processHandle,
        &baseAddress,
        0,
        &regionSize,
        allocationType,
        protect
    );

    // Print the results after the call
    if (status == 0 /* STATUS_SUCCESS */) {
        std::cout << "Memory allocated successfully.\n";
        std::cout << "Base Address: " << baseAddress << "\n";
        std::cout << "Requested Region Size: 0x" << std::hex << regionSize << "\n";

        // Query the memory region to verify the actual size and protection
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQuery(baseAddress, &memInfo, sizeof(memInfo))) {
            std::cout << "Allocated Region Size: 0x" << std::hex << memInfo.RegionSize << "\n";
            std::cout << "Memory State: " << memInfo.State << " (Commit: " << MEM_COMMIT << ")\n";
            std::cout << "Memory Protection: 0x" << std::hex << memInfo.Protect << "\n";
        } else {
            std::cerr << "Failed to query allocated memory.\n";
        }
    } else {
        std::cerr << "NtAllocateVirtualMemory failed with status: 0x" << std::hex << status << "\n";
    }
    if(baseAddress){
        VirtualFree(baseAddress, 0, MEM_RELEASE);
    }

    MessageBoxW(NULL, L"Test call", L"Test call", MB_OK);
    checkNtdll();


	return 0;
}