; syscall_stub.asm
; implements syscall stub for NtProtectVirtualMemory, so it can be called in the hook function to unhook/rehook itself

PUBLIC Syscall_NtProtectVirtualMemory

.CODE
Syscall_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, 50h
    syscall
    ret
Syscall_NtProtectVirtualMemory ENDP
END
