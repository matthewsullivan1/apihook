# Windows NT API Hooking

This project demonstrates API hooking by modifying the function prologues of key NT API calls (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtWaitForSingleObject`, `NtClose`, and `NtFreeVirtualMemory`). It includes a DLL injector, the source for a DLL to install the hooks, and a detection mechanism to (not yet) bypass hooks

## Project Structure
- **`resource`**: Contains hooking DLL source (apihook.cpp), and the syscall stub used to replicate functionality of NtProtectVirtualMemory (syscall_stub.asm)
- **`src`**: Contains source code for DLL injector (injector.cpp), and hook detection test program

## Build Scripts

- **`build_dll`**: Script used by the Makefile to compile the DLL and injector

## Debugging

- **`injector_log`**: Log file written by the DLL injector for debugging

## Features

1. **API Hooking**: 
   - Currently hooks functions from ntdll.dll by modifying their prologues to redirect execution to the corresponding hook handler

2. **DLL Injection**: 
   - Injector.exe loads the hooking DLL into the target process

3. **Hook Detection**:
   - A detection mechanism identifies when a function is hooked by checking the prologue 

---

## Usage

1. Compile the project:
   - Compile injector.cpp, apihook.cpp, and test program that uses hooked calls

2. Inject the DLL:
   - Use the provided injector to load the hooking DLL into the test program

3. Test:
   - Run the hook detection program and test stub to validate hook functionality

---

## License

This project is for educational purposes only. Ensure you comply with applicable laws and ethical guidelines when using this code
