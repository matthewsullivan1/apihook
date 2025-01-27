#include <windows.h>
#include <iostream>

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
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
/*
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
*/

// Resolved Function Pointer
NtAllocateVirtualMemory_t OriginalNtAllocateVirtualMemory = nullptr;
NtProtectVirtualMemory_t OriginalNtProtectVirtualMemory = nullptr;
uintptr_t ResolvedNtProtectVirtualMemory = 0;
/*
NtCreateThreadEx_t OriginalNtCreateThreadEx = nullptr;
NtWaitForSingleObject_t OriginalWaitForSingleObject = nullptr;
NtClose_t OriginalNtClose = nullptr;
NtFreeVirtualMemory_t OriginalNtFreeVirtualMemory = nullptr;
*/

BYTE original_NtAVM[14] = { 0 };
BYTE original_NtPVM[14] = { 0 };
BYTE original_NtCTE[14] = { 0 };
BYTE original_NtWFSO[14] = { 0 };
BYTE original_NtC[14] = { 0 };
BYTE original_NtFVM[14] = { 0 }; 



// DEP violation
/*
void* AllocateExecutableStub() {
    // Allocate memory for the syscall stub
    void* pStub = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pStub) {
        OutputDebugStringA("Failed to allocate memory for syscall stub\n");
        return nullptr;
    }

    // Write the syscall stub into the allocated memory
    unsigned char syscallStub[] = {
        0x4C, 0x8B, 0xD1,              // mov r10, rcx
        0xB8, 0x50, 0x00, 0x00, 0x00,  // mov eax, 0x50 (NtProtectVirtualMemory syscall)
        0x0F, 0x05,                    // syscall
        0xC3                           // ret
    };

    memcpy(pStub, syscallStub, sizeof(syscallStub));

    return pStub;
}

typedef NTSTATUS(NTAPI* SyscallStub_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

SyscallStub_NtProtectVirtualMemory SyscallNtProtectVirtualMemory = (SyscallStub_NtProtectVirtualMemory)AllocateExecutableStub();
*/

extern "C" NTSTATUS NTAPI Syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

    
NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    OutputDebugStringA("Hooked NtAllocateVirtualMemory called\n");
    

    // Temporarily uninstall hook by writing the clean function prologue back to the function
    DWORD oldProtect;
    VirtualProtect(OriginalNtAllocateVirtualMemory, sizeof(original_NtAVM), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(OriginalNtAllocateVirtualMemory, original_NtAVM, sizeof(original_NtAVM));
    VirtualProtect(OriginalNtAllocateVirtualMemory, sizeof(original_NtAVM), oldProtect, &oldProtect);

    // Call clean function with intercepted arguments
    NTSTATUS status = OriginalNtAllocateVirtualMemory(
        ProcessHandle, 
        BaseAddress, 
        ZeroBits, 
        RegionSize, 
        AllocationType, 
        Protect
    );

    // Reinstall hook to intercept future calls
    VirtualProtect(OriginalNtAllocateVirtualMemory, sizeof(original_NtAVM), PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtAllocateVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy(OriginalNtAllocateVirtualMemory, jmp, sizeof(jmp));
    VirtualProtect(OriginalNtAllocateVirtualMemory, sizeof(original_NtAVM), oldProtect, &oldProtect);

    // Return clean function return to callee 
    return status;
}


NTSTATUS NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    OutputDebugStringA("Hooked NtProtectVirtualMemory called\n");
    

    // Temporarily uninstall hook by writing the clean function prologue back to the function
    //SIZE_T regionSize = sizeof(original_NtPVM);
    DWORD oldProtect;
    SIZE_T regionSize = 14;
    PVOID targetAddress = (PVOID)OriginalNtProtectVirtualMemory;

    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READWRITE, 
        &oldProtect
    );

    memcpy((void*)OriginalNtProtectVirtualMemory, original_NtPVM, sizeof(original_NtPVM));

    // Update target address in case the kernel changed it
    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    regionSize = 14;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READ, 
        &oldProtect
    );

    // Call clean function with intercepted arguments
    NTSTATUS cleanStatus = OriginalNtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        NewProtect,
        OldProtect
    );

    // Reinstall hook to intercept future calls
    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    regionSize = 14;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READWRITE, 
        &oldProtect
    ); 

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtProtectVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy((void*)OriginalNtProtectVirtualMemory, jmp, sizeof(jmp));

    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    regionSize = 14;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READ, 
        &oldProtect
    );

    // Return clean function return to callee 
    return cleanStatus;
}

// Installing the hook initially
void HookNtAllocateVirtualMemory() {
    // Get a handle to ntdll.dll
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == NULL) {
        OutputDebugStringA("Failed to load ntdll.dll\n");
        return;
    }

    // Resolve the address of the function to be hooked 
    OriginalNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    if (OriginalNtAllocateVirtualMemory == NULL) {
        OutputDebugStringA("Failed to get address of NtAllocateVirtualMemory\n");
        return;
    }

    // Save the original bytes of the clean function into a global buffer
    memcpy(original_NtAVM, OriginalNtAllocateVirtualMemory, sizeof(original_NtAVM));

    // Apply the hook
    // Write a jump to the hook function to the clean function prologue\
    // Need to use NtProtect syscall stub
    DWORD oldProtect;
    SIZE_T regionSize = sizeof(original_NtAVM);
    PVOID targetAddress = (PVOID)OriginalNtAllocateVirtualMemory;

    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    if(status != 0){
        OutputDebugStringA("Failed to change memory protections for NtAllocate hook installation\n");
    }
    //VirtualProtect(OriginalNtAllocateVirtualMemory, sizeof(original_NtAVM), PAGE_EXECUTE_READWRITE, &oldProtect);

    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedNtAllocateVirtualMemory
    *(void**)(jmp + 2) = (void*)HookedNtAllocateVirtualMemory;
    jmp[10] = 0xFF; 
    jmp[11] = 0xE0; // jmp rax
    memcpy(OriginalNtAllocateVirtualMemory, jmp, sizeof(jmp));
    //VirtualProtect(OriginalNtAllocateVirtualMemory, sizeof(original_NtAVM), oldProtect, &oldProtect);

    targetAddress = (PVOID)OriginalNtAllocateVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );
    if(status != 0){
        OutputDebugStringA("Failed to restore memory protections after NtAllocate hook installation\n");
    }
}

// Installing the hook initially
void HookNtProtectVirtualMemory() {
    // Get a handle to ntdll.dll
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == NULL) {
        OutputDebugStringA("Failed to load ntdll.dll\n");
        return;
    }

    // Resolve the address of the function to be hooked 
    OriginalNtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    if (OriginalNtProtectVirtualMemory == NULL) {
        OutputDebugStringA("Failed to get address of NtProtectVirtualMemory\n");
        return;
    }
    
    // Print the address and check if it is near ntdll.dll
    char ntdll_buf[128];
    char ntprotect_buf[128];
    sprintf_s(ntdll_buf, "ntdll address: %p\n", (void*)hNtdll);
    sprintf_s(ntprotect_buf, "original ntProtect address: %p\n", (void*)OriginalNtProtectVirtualMemory);
    OutputDebugStringA(ntdll_buf);
    OutputDebugStringA(ntprotect_buf);

    // Save 14 bytes of clean function
    // Print them before doing anything else related to hooking
    //pointer to bytes -> dereference address of NtProtect and index 
    memcpy(original_NtPVM, (void*)OriginalNtProtectVirtualMemory, 14);
    BYTE* prologue_ptr = (BYTE*)OriginalNtProtectVirtualMemory;
    char prologue_buf[128];
    sprintf_s(prologue_buf, "Prologue of OriginalNtProtect: %02X %02X %02X %02X %02X\n", prologue_ptr[0], prologue_ptr[1], prologue_ptr[2], prologue_ptr[3], prologue_ptr[4]);
    OutputDebugStringA(prologue_buf);

    // Update protections with write permissions to prepare to write hook with syscall stub to avoid using NtProtect directly
    // Very important to use a copy of the base address here. The kernel can modify targetAddress if it is misaligned, which will change all future references to the address of OriginalNtProtect
    SIZE_T regionSize = 14;
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READWRITE, 
        &oldProtect
    );

    if(status != 0){
        OutputDebugStringA("Failed to change memory protection using syscall stub\n");
    } else {
        OutputDebugStringA("Memory protection updated for hook installation\n");
    }
    

    // Apply the hook: write the jump to the hook function
    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedNtProtectVirtualMemory
    *(void**)(jmp + 2) = (void*)HookedNtProtectVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0; // jmp rax
    memcpy((void*)OriginalNtProtectVirtualMemory, jmp, sizeof(jmp));
    OutputDebugStringA("Hook installed\n");

    // Prologue after hook has been written
    // Get the address too to make sure it hasnt changed
    BYTE* prologue_new_ptr = (BYTE *)OriginalNtProtectVirtualMemory;
    char prologue_new_buf[128];
    char ntprotect_buf_new[128];
    sprintf_s(ntprotect_buf_new, "ntProtect address: %p\n", (void*)OriginalNtProtectVirtualMemory);
    sprintf_s(prologue_new_buf, "Prologue of OriginalNtProtect after hook: %02X %02X %02X %02X %02X\n", prologue_new_ptr[0], prologue_new_ptr[1], prologue_new_ptr[2], prologue_new_ptr[3], prologue_new_ptr[4]);
    OutputDebugStringA(ntprotect_buf_new);
    OutputDebugStringA(prologue_new_buf);

    // Restore memory protection using the custom low-level NtProtectVirtualMemory
    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READ, 
        &oldProtect
    );
    if(status != 0){
        OutputDebugStringA("Failed to restore memory protection\n");
    }
    OutputDebugStringA("Memory protection restored\n");

}

typedef int (WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
MessageBoxW_t OriginalMessageBoxW = nullptr;
BYTE originalBytes_MBW[14] = { 0 };

/* 
int WINAPI HookedMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    OutputDebugStringA("Hooked MessageBoxW called\n");

    //Temporarily restore the original bytes to call the original function to prevent infinite recursion
    DWORD oldProtect;
    VirtualProtect(OriginalMessageBoxW, sizeof(originalBytes_MBW), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(OriginalMessageBoxW, originalBytes_MBW, sizeof(originalBytes_MBW));
    VirtualProtect(OriginalMessageBoxW, sizeof(originalBytes_MBW), oldProtect, &oldProtect);

    // Call unhooked MBW
    int mbw = OriginalMessageBoxW(hWnd, L"Hooked MBW", L"Hooked MBW", uType);

    // Reapply the hook after calling the original function
    VirtualProtect(OriginalMessageBoxW, sizeof(originalBytes_MBW), PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedMessageBoxW
    *(void**)(jmp + 2) = (void*)HookedMessageBoxW;
    jmp[10] = 0xFF; jmp[11] = 0xE0; // jmp rax
    memcpy(OriginalMessageBoxW, jmp, sizeof(jmp));
    VirtualProtect(OriginalMessageBoxW, sizeof(originalBytes_MBW), oldProtect, &oldProtect);

    return mbw;
}

void HookMessageBoxW() {
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32 == NULL) {
        OutputDebugStringA("Failed to load user32.dll\n");
        return;
    }

    OriginalMessageBoxW = (MessageBoxW_t)GetProcAddress(hUser32, "MessageBoxW");
    if (OriginalMessageBoxW == NULL) {
        OutputDebugStringA("Failed to get address of MessageBoxW\n");
        return;
    }

    // Save the original bytes
    memcpy(originalBytes_MBW, OriginalMessageBoxW, sizeof(originalBytes_MBW));

    // Apply the hook
    DWORD oldProtect;
    VirtualProtect(OriginalMessageBoxW, sizeof(originalBytes_MBW), PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedMessageBoxW
    *(void**)(jmp + 2) = (void*)HookedMessageBoxW;
    jmp[10] = 0xFF; jmp[11] = 0xE0; // jmp rax
    memcpy(OriginalMessageBoxW, jmp, sizeof(jmp));
    VirtualProtect(OriginalMessageBoxW, sizeof(originalBytes_MBW), oldProtect, &oldProtect);
}
*/

// entry
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("dllmain\n");
        MessageBoxW(NULL, L"DLL Injected", L"Status", MB_OK); // For confirmation
        //HookMessageBoxW();
        HookNtAllocateVirtualMemory();
        //HookNtProtectVirtualMemory();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
