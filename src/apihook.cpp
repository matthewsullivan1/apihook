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
/**/

// Resolved Function Pointer
NtAllocateVirtualMemory_t OriginalNtAllocateVirtualMemory = nullptr;
NtProtectVirtualMemory_t OriginalNtProtectVirtualMemory = nullptr;
NtCreateThreadEx_t OriginalNtCreateThreadEx = nullptr;
NtWaitForSingleObject_t OriginalWaitForSingleObject = nullptr;
NtClose_t OriginalNtClose = nullptr;
NtFreeVirtualMemory_t OriginalNtFreeVirtualMemory = nullptr;
/**/

BYTE original_NtAVM[14] = { 0 };
BYTE original_NtPVM[14] = { 0 };
BYTE original_NtCTE[14] = { 0 };
BYTE original_NtWFSO[14] = { 0 };
BYTE original_NtC[14] = { 0 };
BYTE original_NtFVM[14] = { 0 }; 

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
    char debugMsg[256];
    sprintf_s(debugMsg, 
        "HookedNtAllocateVirtualMemory called: BaseAddress=%p, RegionSize=%llu\n",
        *BaseAddress, 
        *RegionSize
    );
    OutputDebugStringA(debugMsg);
    

    // Temporarily uninstall hook by writing the clean function prologue back to the function
    // Use syscall stubs instead of VirtualProtect
    DWORD oldProtect;
    SIZE_T regionSize = sizeof(original_NtAVM);
    PVOID targetAddress = (PVOID)OriginalNtAllocateVirtualMemory;

    NTSTATUS status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if(status != 0){
        OutputDebugStringA("Failed to change memory protections for NtAllocate hook installation\n");
    }

    memcpy(OriginalNtAllocateVirtualMemory, original_NtAVM, sizeof(original_NtAVM));
    
    targetAddress = (PVOID)OriginalNtAllocateVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);
    if(status != 0){
        OutputDebugStringA("Failed to restore memory protections after NtAllocate hook installation\n");
    }
    
    // Call clean function with intercepted arguments
    NTSTATUS cleanStatus = OriginalNtAllocateVirtualMemory(
        ProcessHandle, 
        BaseAddress, 
        ZeroBits, 
        RegionSize, 
        AllocationType, 
        Protect
    );

    // Reinstall hook to intercept future calls
    targetAddress = (PVOID)OriginalNtAllocateVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtAllocateVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy(OriginalNtAllocateVirtualMemory, jmp, sizeof(jmp));
    targetAddress = (PVOID)OriginalNtAllocateVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);
    if(status != 0){
        OutputDebugStringA("Failed to restore memory protections after NtAllocate hook installation\n");
    }

    // Return clean function return to callee
    return cleanStatus;
}


NTSTATUS NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    char debugMsg[256];
    sprintf_s(debugMsg, 
        "HookedNtProtectVirtualMemory called: BaseAddress=%p, RegionSize=%llu, NewProtect=0x%x\n",
        *BaseAddress, 
        *RegionSize, 
        NewProtect
    );
    OutputDebugStringA(debugMsg);
    

    // Temporarily uninstall hook by writing the clean function prologue back to the function
    SIZE_T regionSize = sizeof(original_NtPVM);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtProtectVirtualMemory;

    NTSTATUS status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    memcpy((void*)OriginalNtProtectVirtualMemory, original_NtPVM, sizeof(original_NtPVM));

    // Update target address in case the kernel changed it
    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    regionSize = sizeof(original_NtPVM);
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);

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
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect); 

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtProtectVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy((void*)OriginalNtProtectVirtualMemory, jmp, sizeof(jmp));

    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);

    // Return clean function return to callee 
    return cleanStatus;
}

NTSTATUS NTAPI HookedNtCreateThreadEx(
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
) {
    OutputDebugStringA("HookedNtCreateThreadEx called\n");
    // Temporarily uninstall hook by writing the clean function prologue back to the function
    SIZE_T regionSize = sizeof(original_NtCTE);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtCreateThreadEx;

    NTSTATUS status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    memcpy((void*)OriginalNtCreateThreadEx, original_NtCTE, sizeof(original_NtCTE));

    // Update target address in case the kernel realigned it
    targetAddress = (PVOID)OriginalNtCreateThreadEx;
    regionSize = 14;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);

    // Call clean function with intercepted arguments
    NTSTATUS cleanStatus = OriginalNtCreateThreadEx(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        StartRoutine,
        Argument,
        CreateFlags,
        ZeroBits,
        StackSize,
        MaximumStackSize,
        AttributeList
    );

    // Reinstall hook to intercept future calls
    targetAddress = (PVOID)OriginalNtCreateThreadEx;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect); 

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtCreateThreadEx;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy((void*)OriginalNtCreateThreadEx, jmp, sizeof(jmp));

    targetAddress = (PVOID)OriginalNtCreateThreadEx;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);

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

    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedNtAllocateVirtualMemory
    *(void**)(jmp + 2) = (void*)HookedNtAllocateVirtualMemory;
    jmp[10] = 0xFF; 
    jmp[11] = 0xE0; // jmp rax
    memcpy(OriginalNtAllocateVirtualMemory, jmp, sizeof(jmp));

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

    // Save 14 bytes of clean function
    memcpy(original_NtPVM, (void*)OriginalNtProtectVirtualMemory, sizeof(original_NtPVM));

    // Update protections with write permissions to prepare to write hook with syscall stub to avoid using NtProtect directly
    // Very important to use a copy of the base address here. The kernel can modify targetAddress if it is misaligned, which will change all future references to the address of OriginalNtProtect
    SIZE_T regionSize = sizeof(original_NtPVM);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READWRITE, 
        &oldProtect
    );
    
    // Apply the hook: write the jump to the hook function
    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedNtProtectVirtualMemory
    *(void**)(jmp + 2) = (void*)HookedNtProtectVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0; // jmp rax
    memcpy((void*)OriginalNtProtectVirtualMemory, jmp, sizeof(jmp));
    OutputDebugStringA("Hook installed\n");

    // Restore memory protection using syscall stub
    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        oldProtect, 
        &oldProtect
    );
    if(status != 0){
        OutputDebugStringA("Failed to restore memory protection\n");
    }
    OutputDebugStringA("Memory protection restored\n");

}

void HookNtCreateThreadEx(){
    // Get handle to ntdll.dll
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if(!ntdll){
        OutputDebugStringA("Failed to get handle to ntdll.dll\n");
        return;
    }
    // Resolve address of NtCreateThreadEx
    OriginalNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");
    // Save original prologue
    memcpy(original_NtCTE, (void*)OriginalNtCreateThreadEx, sizeof(original_NtCTE));
    // Update mem protections
    SIZE_T regionSize = sizeof(original_NtCTE);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtCreateThreadEx;
    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        PAGE_EXECUTE_READWRITE, 
        &oldProtect
    );

    // Apply the hook: write the jump to the hook function
    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedNtProtectVirtualMemory
    *(void**)(jmp + 2) = (void*)HookedNtCreateThreadEx;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0; // jmp rax
    memcpy((void*)OriginalNtCreateThreadEx, jmp, sizeof(jmp));

    // Restore memory protection using syscall stub
    targetAddress = (PVOID)OriginalNtCreateThreadEx;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        oldProtect, 
        &oldProtect
    );


    OutputDebugStringA("NtCreateThreadEx hook installed\n");

}




// entry
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("dllmain\n");
        MessageBoxW(NULL, L"DLL Injected", L"Status", MB_OK); // For confirmation
        HookNtAllocateVirtualMemory();
        HookNtProtectVirtualMemory();
        HookNtCreateThreadEx();

        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
