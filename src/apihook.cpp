#include <windows.h>
#include <iostream>


/*

todo : check if EXECUTE_READWRITE is needed when writing to the function prologue
systematically install hooks? Not sure if this is possible or necessary since each hook handler is unique ? 
systematically build jmp array
jump table
size of prologue and jmp array - might only need to be 12 bytes 
global handle to ntdll so that hook handlers can just call the hook install 




*/

CRITICAL_SECTION cs;
void HookNtFreeVirtualMemory();

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
NtWaitForSingleObject_t OriginalNtWaitForSingleObject = nullptr;
NtClose_t OriginalNtClose = nullptr;
NtFreeVirtualMemory_t OriginalNtFreeVirtualMemory = nullptr;
/**/

BYTE prologue_NtAllocateVirtualMemory[14] = { 0 };
BYTE prologue_NtProtectVirtualMemory[14] = { 0 };
BYTE prologue_NtCreateThreadEx[14] = { 0 };
BYTE prologue_NtWaitForSingleObject[14] = { 0 };
BYTE prologue_NtClose[14] = { 0 };
BYTE prologue_NtFreeVirtualMemory[14] = { 0 }; 

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
    SIZE_T regionSize = sizeof(prologue_NtAllocateVirtualMemory);
    PVOID targetAddress = (PVOID)OriginalNtAllocateVirtualMemory;

    EnterCriticalSection(&cs);

    NTSTATUS status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if(status != 0){
        OutputDebugStringA("Failed to change memory protections for NtAllocate hook installation\n");
    }

    memcpy(OriginalNtAllocateVirtualMemory, prologue_NtAllocateVirtualMemory, sizeof(prologue_NtAllocateVirtualMemory));
    
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
    LeaveCriticalSection(&cs);
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
    SIZE_T regionSize = sizeof(prologue_NtProtectVirtualMemory);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtProtectVirtualMemory;

    EnterCriticalSection(&cs);

    NTSTATUS status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    memcpy((void*)OriginalNtProtectVirtualMemory, prologue_NtProtectVirtualMemory, sizeof(prologue_NtProtectVirtualMemory));

    // Update target address in case the kernel changed it
    targetAddress = (PVOID)OriginalNtProtectVirtualMemory;
    regionSize = sizeof(prologue_NtProtectVirtualMemory);
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

    LeaveCriticalSection(&cs);

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
    SIZE_T regionSize = sizeof(prologue_NtCreateThreadEx);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtCreateThreadEx;

    EnterCriticalSection(&cs);

    NTSTATUS status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    memcpy((void*)OriginalNtCreateThreadEx, prologue_NtCreateThreadEx, sizeof(prologue_NtCreateThreadEx));

    // Update target address in case the kernel realigned it
    targetAddress = (PVOID)OriginalNtCreateThreadEx;
    regionSize = sizeof(prologue_NtCreateThreadEx);
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

    LeaveCriticalSection(&cs);


    // Return clean function return to callee 
    return cleanStatus;
}


NTSTATUS NTAPI HookedNtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
){
    OutputDebugStringA("HookedNtWaitForSingleObject called\n");
    
    PVOID targetAddress = (PVOID)OriginalNtWaitForSingleObject;
    SIZE_T regionSize = sizeof(prologue_NtWaitForSingleObject);
    DWORD oldProtect;
    
    EnterCriticalSection(&cs);

    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    memcpy((void *)OriginalNtWaitForSingleObject, prologue_NtWaitForSingleObject, sizeof(prologue_NtWaitForSingleObject));

    targetAddress = (PVOID)OriginalNtWaitForSingleObject;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );

    NTSTATUS cleanStatus = OriginalNtWaitForSingleObject(
        Handle,
        Alertable,
        Timeout
    );

    targetAddress = (PVOID)OriginalNtWaitForSingleObject;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtWaitForSingleObject;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy((void*)OriginalNtWaitForSingleObject, jmp, sizeof(jmp));

    targetAddress = (PVOID)OriginalNtWaitForSingleObject;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);

    LeaveCriticalSection(&cs);

    return cleanStatus;
}


NTSTATUS NTAPI HookedNtClose(
    HANDLE Handle
){
    OutputDebugStringA("HookedNtClose called\n");
    
    PVOID targetAddress = (PVOID)OriginalNtClose;
    SIZE_T regionSize = sizeof(prologue_NtClose);
    DWORD oldProtect;
    
    EnterCriticalSection(&cs);

    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    memcpy((void *)OriginalNtClose, prologue_NtClose, sizeof(OriginalNtClose));

    targetAddress = (PVOID)OriginalNtClose;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );

    NTSTATUS cleanStatus = OriginalNtClose(
        Handle
    );

    targetAddress = (PVOID)OriginalNtClose;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtClose;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy((void*)OriginalNtClose, jmp, sizeof(jmp));

    targetAddress = (PVOID)OriginalNtClose;
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);


    LeaveCriticalSection(&cs);

    return cleanStatus;

}


NTSTATUS NTAPI HookedNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType    
){

    OutputDebugStringA("HookedNtFreeVirtualMemory called\n");
    
    PVOID targetAddress = (PVOID)OriginalNtFreeVirtualMemory;
    SIZE_T regionSize = sizeof(prologue_NtFreeVirtualMemory);
    DWORD oldProtect;
    
    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    memcpy((void *)OriginalNtFreeVirtualMemory, prologue_NtFreeVirtualMemory, sizeof(prologue_NtFreeVirtualMemory));

    targetAddress = (PVOID)OriginalNtFreeVirtualMemory;
    regionSize = sizeof(prologue_NtFreeVirtualMemory);
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );

    NTSTATUS cleanStatus = OriginalNtFreeVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType
    );

    HookNtFreeVirtualMemory();

    /*
    targetAddress = (PVOID)OriginalNtFreeVirtualMemory;
    regionSize = sizeof(prologue_NtFreeVirtualMemory);
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void*)HookedNtFreeVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy((void*)OriginalNtFreeVirtualMemory, jmp, sizeof(jmp));

    targetAddress = (PVOID)OriginalNtFreeVirtualMemory;
    regionSize = sizeof(prologue_NtFreeVirtualMemory);
    status = Syscall_NtProtectVirtualMemory(GetCurrentProcess(), &targetAddress, &regionSize, oldProtect, &oldProtect);
    */

    return cleanStatus;
}

void HookNtAllocateVirtualMemory(HMODULE ntdll) {

    // Resolve the address of the function to be hooked 
    OriginalNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    if (OriginalNtAllocateVirtualMemory == NULL) {
        OutputDebugStringA("Failed to get address of NtAllocateVirtualMemory\n");
        return;
    }

    // Save the original bytes of the clean function into a global buffer
    memcpy(prologue_NtAllocateVirtualMemory, OriginalNtAllocateVirtualMemory, sizeof(prologue_NtAllocateVirtualMemory));

    // Apply the hook
    // Write a jump to the hook function to the clean function prologue\
    // Need to use NtProtect syscall stub
    DWORD oldProtect;
    SIZE_T regionSize = sizeof(prologue_NtAllocateVirtualMemory);
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
    memcpy((void *)OriginalNtAllocateVirtualMemory, jmp, sizeof(jmp));

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
    } else {
        OutputDebugStringA("NtAllocateVirtualMemory hook installed\n");
    }
}

void HookNtProtectVirtualMemory(HMODULE ntdll) {

    // Resolve the address of the function to be hooked 
    OriginalNtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    if (OriginalNtProtectVirtualMemory == NULL) {
        OutputDebugStringA("Failed to get address of NtProtectVirtualMemory\n");
        return;
    }

    // Save 14 bytes of clean function
    memcpy(prologue_NtProtectVirtualMemory, (void*)OriginalNtProtectVirtualMemory, sizeof(prologue_NtProtectVirtualMemory));

    // Update protections with write permissions to prepare to write hook with syscall stub to avoid using NtProtect directly
    // Very important to use a copy of the base address here. The kernel can modify targetAddress if it is misaligned, which will change all future references to the address of OriginalNtProtect
    SIZE_T regionSize = sizeof(prologue_NtProtectVirtualMemory);
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

void HookNtCreateThreadEx(HMODULE ntdll){
    // Resolve address of NtCreateThreadEx
    OriginalNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");
    if(!OriginalNtCreateThreadEx){
        OutputDebugStringA("Failed to resolve address of NtCreateThreadEx\n");
        return;
    }
    // Save original prologue
    memcpy(prologue_NtCreateThreadEx, (void*)OriginalNtCreateThreadEx, sizeof(prologue_NtCreateThreadEx));
    // Update mem protections
    SIZE_T regionSize = sizeof(prologue_NtCreateThreadEx);
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

void HookNtWaitForSingleObject(HMODULE ntdll){
    OriginalNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(ntdll, "NtWaitForSingleObject");
    if(!OriginalNtWaitForSingleObject){
        OutputDebugStringA("Failed to resolve address of NtWaitForSingleObject\n");
        return;
    }

    memcpy(prologue_NtWaitForSingleObject, (void *)OriginalNtWaitForSingleObject, sizeof(prologue_NtWaitForSingleObject));

    SIZE_T regionSize = sizeof(prologue_NtWaitForSingleObject);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtWaitForSingleObject;
    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );

    // Apply the hook: write the jump to the hook function
    BYTE jmp[14] = { 0x48, 0xB8 }; // mov rax, HookedNtProtectVirtualMemory
    *(void**)(jmp + 2) = (void*)HookedNtWaitForSingleObject;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0; // jmp rax
    memcpy((void*)OriginalNtWaitForSingleObject, jmp, sizeof(jmp));

    // Restore memory protection using syscall stub
    targetAddress = (PVOID)OriginalNtWaitForSingleObject;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize, 
        oldProtect, 
        &oldProtect
    );


    OutputDebugStringA("NtWaitForSingleObject hook installed\n");


}

void HookNtClose(HMODULE ntdll){
    OriginalNtClose = (NtClose_t)GetProcAddress(ntdll, "NtClose");

    if(!OriginalNtClose){
        OutputDebugStringA("Failed to resolve address of NtClose\n");
        return;
    }

    memcpy(prologue_NtClose, (void*)OriginalNtClose, sizeof(prologue_NtClose));

    SIZE_T regionSize = sizeof(prologue_NtClose);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtClose;

    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    if(status != 0){
        OutputDebugStringA("Failed to update memory protections in NtClose hook installation\n");
        return;
    }

    // movabs rax, addr
    // Cannot direct jump to a 8 byte address, need to load it into rax first
    BYTE jmp[14] = { 0x48, 0xB8 };

    // target address
    *(void**)(jmp + 2) = (void*)HookedNtClose;

    // jmp rax 
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;

    memcpy((void*)OriginalNtClose, jmp, sizeof(jmp));

    // update regionSize and targetAddress in case they were realigned before restoring protection
    regionSize = sizeof(prologue_NtClose);
    targetAddress = (PVOID)OriginalNtClose;

    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );
    if(status != 0){
        OutputDebugStringA("Failed to restore memory protections in NtClose hook installation\n");
        return;
    }

    OutputDebugStringA("NtClose hook installed\n");
}

void HookNtFreeVirtualMemory(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if(!ntdll){
        OutputDebugStringA("Failed to get handle to ntdll.dll\n");
        return;
    }

    OriginalNtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetProcAddress(ntdll, "NtFreeVirtualMemory");
    if(!OriginalNtFreeVirtualMemory){
        OutputDebugStringA("Failed to resolve address of NtFreeVirtualMemory\n");
        return;
    }

    memcpy(prologue_NtFreeVirtualMemory, (void *)OriginalNtFreeVirtualMemory, sizeof(prologue_NtFreeVirtualMemory));

    SIZE_T regionSize = sizeof(prologue_NtFreeVirtualMemory);
    DWORD oldProtect;
    PVOID targetAddress = (PVOID)OriginalNtFreeVirtualMemory;
    
    NTSTATUS status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    if(status != 0){
        OutputDebugStringA("Failed to update memory protections in NtFreeVirtualMemory hook installation\n");
        return;
    }

    BYTE jmp[14] = { 0x48, 0xB8 };
    *(void**)(jmp + 2) = (void *)HookedNtFreeVirtualMemory;
    jmp[10] = 0xFF;
    jmp[11] = 0xE0;
    memcpy((void *)OriginalNtFreeVirtualMemory, jmp, sizeof(jmp));

    targetAddress = (PVOID)OriginalNtFreeVirtualMemory;
    status = Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );

    if(status != 0){
        OutputDebugStringA("Failed to restore memory protections in NtFreeVirtualMemory hook install\n");
        return;
    } else {
        OutputDebugStringA("NtFreeVirtualMemory hook installed\n");
    }
    
}

void LogFunctionPrologue(BYTE prologue[], int size){
    char dbgString[256];

    char *ptr = dbgString;
    for(int i = 0; i < size; i++){
        ptr += sprintf_s(ptr, sizeof(dbgString) - (ptr - dbgString), "%02X ", prologue[i]);
    }

    OutputDebugStringA("Prologue:\n");
    OutputDebugStringA(dbgString);
    OutputDebugStringA("\n");
}

void LogFunctionBytes(void *function, int size){
    char dbgString[256];
    BYTE buffer[14];

    DWORD oldProtect;
    PVOID targetAddress = (PVOID)function;
    SIZE_T regionSize = size;

    Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(), 
        &targetAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    memcpy(buffer, function, size);

    targetAddress = (PVOID)function;
    regionSize = size;

    Syscall_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &targetAddress,
        &regionSize,
        oldProtect,
        &oldProtect
    );

    char *ptr = dbgString;
    for(int i = 0; i < size; i++){
        ptr += sprintf_s(ptr, sizeof(dbgString) - (ptr - dbgString), "%02X", buffer[i]);
    }

    OutputDebugStringA("Bytes at hooked prologue:\n");
    OutputDebugStringA(dbgString);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    

    InitializeCriticalSection(&cs);
    // Handle to ntdll.dll for hook installations to resolve function address
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if(!ntdll){
        OutputDebugStringA("Failed to get handle to ntdll.dll\n");
        return FALSE;
    }
    
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        MessageBoxW(NULL, L"dllmain", L"Status", MB_OK); // For confirmation

        HookNtAllocateVirtualMemory(ntdll);
        HookNtProtectVirtualMemory(ntdll);
        HookNtCreateThreadEx(ntdll);
        //HookNtWaitForSingleObject(ntdll);
        //HookNtClose(ntdll);
        HookNtFreeVirtualMemory();

        DeleteCriticalSection(&cs);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
