# Windows NT API Hooking

This project demonstrates API hooking by modifying the function prologues of key NT API calls (`NtAllocateVirtualMemory` and `NtProtectVirtualMemory`). It includes a DLL injector, a hooking DLL, and a detection mechanism to (not yet) bypass hooks.

## Project Structure


## Build Scripts

- **`build_dll`**: Script used by the Makefile to compile the DLL using the cl

## Debugging

- **`injector_log`**: Log file written by the DLL injector for debugging

## Features

1. **API Hooking**: 
   - Currently hooks `NtAllocateVirtualMemory` and `NtProtectVirtualMemory` by modifying their prologues to redirect execution

2. **DLL Injection**: 
   - Injector.exe loads the hooking DLL into the target process

3. **Hook Detection**:
   - A detection mechanism identifies when a function is hooked by checking the prologue 

---

## Usage

1. Compile the project:
   - Build injector.exe, apihook.dll, and test program that uses hooked calls

2. Inject the DLL:
   - Use the provided injector to load the hooking DLL into a target process

3. Test:
   - Run the hook detection program and test stub to validate hook functionality

---

## License

This project is for educational purposes only. Ensure you comply with applicable laws and ethical guidelines when using this code.
