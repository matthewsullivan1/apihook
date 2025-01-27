#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <iomanip>

bool DEBUG = false;

using namespace std;

// Extends the official _LDR_DATA_TABLE_ENTRY in winternl.h to include the BaseDllName field 
typedef struct _LDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName; // Accessing this requires manual reinterpretation
} LDR_DATA_TABLE_ENTRY_EX, *PLDR_DATA_TABLE_ENTRY_EX;

// Process environment block is a windows data structure that contains information about the current process, including loaded modules 
// The GS register contains a pointer to the thread environment block 
PEB* get_peb() {
#ifdef _WIN64
    return (PEB*)__readgsqword(0x60);  // GS register points to TEB on x64
#endif
}

// Used to get module handles rather than making a call to GetModuleHandle
/*
The PEB contains a pointer to Ldr (loader data) which holds the module list for the process
InMemoryOrderModuleList is a doubly linked list of modules sorted by their memory load order

- current_entry starts at the first module in the list and traverses the list using Flink
- The current entry module information is extracted and cast to a LDR_DATA_TABLE_ENTRY_EX structure
- The name (BaseDllName) field is compared to the target DLL name
- if the name matches, the modules DllBase field is returned 
*/

HMODULE get_ntdll_base() {
    PEB* peb = get_peb();
    LIST_ENTRY* module_list = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current_entry = module_list->Flink;

    while (current_entry != module_list) {
        auto entry = CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY_EX, InMemoryOrderLinks);
        wchar_t* module_name = entry->BaseDllName.Buffer;
        if (_wcsicmp(module_name, L"ntdll.dll") == 0) {
            return (HMODULE)entry->DllBase;
        }
        current_entry = current_entry->Flink;
    }
    return nullptr;
}


void *resolve_nt(HMODULE hModule, const char *function_name){

    // Cast dos header to module handle argument
    // Nt headers offset is a field in the dos header
    // The export directory relative virtual address is found from nt headers optional header data directory
    auto dos_header = (PIMAGE_DOS_HEADER)hModule;
    auto nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos_header->e_lfanew);
    auto export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + export_dir_rva);

    // The export directory contains arrays of the names, addresses, and ordinals of functions that it exports 
    auto names = (DWORD*)((BYTE*)hModule + export_dir->AddressOfNames);
    auto functions = (DWORD*)((BYTE*)hModule + export_dir->AddressOfFunctions);
    auto ordinals = (WORD*)((BYTE*)hModule + export_dir->AddressOfNameOrdinals);

    // Iterate through the export directory until a the target function is found by name
    // Once the name is found, use the iterator to index to ordinal array, and use the corresponding ordinal
    // To point the function RVA array to the corresponding function RVA, and return the address
    for(DWORD i  = 0; i < export_dir->NumberOfNames; i++){
        const char *name = (const char*)hModule + names[i];
        if(strcmp(name, function_name) == 0){
            WORD ordinal = ordinals[i];
            DWORD function_rva = functions[ordinal];
            
            return (void*)((BYTE*)hModule + function_rva);
        }
    }

    return nullptr;
}



// Undocumented function prototypes
// Need to be defined manually since Windows does not provide definitions
// VirtualAlloc()
typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle, 
    PVOID* BaseAddress, 
    ULONG_PTR ZeroBits, 
    PSIZE_T RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
    );


// VirtualProtect()
typedef NTSTATUS(NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

//CreateThread
typedef NTSTATUS(NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// WaitForSingleObject
typedef NTSTATUS(NTAPI *NtWaitForSingleObject_t)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);


// CloseHandle
typedef NTSTATUS(NTAPI *NtClose_t)(
    HANDLE Handle
);

// VirtualFree
typedef NTSTATUS(NTAPI *NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

void print_prologue(void *addr, size_t count = 8){
    // Cast void address to unsigned char pointer, so it can be treated as a pointer to raw bytes
    unsigned char *byte_ptr = reinterpret_cast<unsigned char*>(addr);

    for(size_t i = 0; i < count; i++){
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte_ptr[i]) << " ";
    }

    cout << dec << endl;

}


/*DYN_GLOBALS*/
 
void execute() {
    
    cout << "inject nthook.dll\n";
    cin.get();
    //const char * path = "C:\\Users\\18161\\Desktop\\dllinject\\dll\\apihook.dll";
    //LoadLibraryA(path);

    // Get handle to ntdll.dll without using GetModuleHandle call
    // Resolve function addresses and cast them to the respective type
    HMODULE ntdllBase = get_ntdll_base();
    void* pNtAllocateVirtualMemory = resolve_nt(ntdllBase, "NtAllocateVirtualMemory");
    auto NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)pNtAllocateVirtualMemory;

    void* pNtProtectVirtualMemory = resolve_nt(ntdllBase, "NtProtectVirtualMemory");
    auto NtProtectVirtualMemory = (NtProtectVirtualMemory_t)pNtProtectVirtualMemory;

    void* pNtCreateThreadEx = resolve_nt(ntdllBase, "NtCreateThreadEx");
    auto NtCreateThreadEx = (NtCreateThreadEx_t)pNtCreateThreadEx;

    void* pNtWaitForSingleObject = resolve_nt(ntdllBase, "NtWaitForSingleObject");
    auto NtWaitForSingleObject = (NtWaitForSingleObject_t)pNtWaitForSingleObject;

    void* pNtClose = resolve_nt(ntdllBase, "NtClose");
    auto NtClose = (NtClose_t)pNtClose;

    void* pNtFreeVirtualMemory = resolve_nt(ntdllBase, "NtFreeVirtualMemory");
    auto NtFreeVirtualMemory = (NtFreeVirtualMemory_t)pNtFreeVirtualMemory;


    // Get module handle and resolve function addresses using GetModuleHandle and GetProcAddress
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    FARPROC p1 = GetProcAddress(hModule, "NtAllocateVirtualMemory");
    FARPROC p2 = GetProcAddress(hModule, "NtProtectVirtualMemory");
    FARPROC p3 = GetProcAddress(hModule, "NtCreateThreadEx");
    FARPROC p4 = GetProcAddress(hModule, "NtWaitForSingleObject");
    FARPROC p5 = GetProcAddress(hModule, "NtClose");
    FARPROC p6 = GetProcAddress(hModule, "NtFreeVirtualMemory");


    // Compare addresses
    cout << "NtAllocateVirtualMemory " << (void*)p1 << " : " << pNtAllocateVirtualMemory << endl;
    cout << "NtProtectVirtualMemory " << (void*)p2 << " : " << pNtProtectVirtualMemory << endl;
    cout << "NtCreateThreadEx " << (void*)p3 << " : " << pNtCreateThreadEx << endl;
    cout << "NtWaitForSingleObject " << (void*)p4 << " : " << pNtWaitForSingleObject << endl;
    cout << "NtClose " << (void*)p5 << " : " << pNtClose << endl;
    cout << "NtFreeVirtualMemory " << (void*)p6 << " : " << pNtFreeVirtualMemory << endl;

    cout << "NtAllocateVirtualMemory: \n";
    print_prologue(pNtAllocateVirtualMemory);
    cout << "NtProtectVirtualMemory: \n";
    print_prologue(pNtProtectVirtualMemory);


    print_prologue(pNtCreateThreadEx);
    print_prologue(pNtWaitForSingleObject);
    print_prologue(pNtClose);
    print_prologue(pNtFreeVirtualMemory);
    //cout << "input\n";
    //cin.get();
    
    HANDLE hProc = GetCurrentProcess();
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 0x1000;
    ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_READWRITE;

    NTSTATUS status = NtAllocateVirtualMemory(
        hProc,
        &baseAddress,
        0,
        &regionSize,
        allocationType,
        protect
    );
    if(status == 0){
        cout << "NtAllocate good " << endl;
    } else {
        cerr << "NtAllocate bad " << status << endl;
    }
    // Test both calls
    
    /*
    DWORD oldProtect;
    cout << "Before NtProtectVirtualMemory call " << flush;
    cin.get();
    */
   /*
    status = NtProtectVirtualMemory (
        hProc,
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );
    if(status == 0){
        cout << "NtProtect good " << endl;
    } else {
        cerr << "NtProtect bad " << status << endl;
    }*/
}




int main() {

    execute();
    if(DEBUG){cin.get();}

    return 0;
}
