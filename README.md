# API Hooking Project

This project demonstrates API hooking by modifying the function prologues of key NT API calls (`NtAllocateVirtualMemory` and `NtProtectVirtualMemory`). It includes a DLL injector, a hooking DLL, and a detection mechanism to bypass hooks.

## Project Structure


## Build Scripts

- **`build_dll`**: Script used by the Makefile to compile the DLL using the `cl` compiler.

## Debugging

- **`injector_log`**: Log file written by the DLL injector for debugging and tracking injection behavior.

## Features

1. **API Hooking**: 
   - Hooks `NtAllocateVirtualMemory` and `NtProtectVirtualMemory` by modifying their prologues to redirect execution.
   - Uses a syscall stub for low-level functionality.

2. **DLL Injection**: 
   - A custom injector loads the hooking DLL into the target process.

3. **Hook Detection**:
   - A detection mechanism identifies and bypasses the installed hooks.

---

## Usage

1. Compile the project:
   - Use the provided Makefile or build scripts to compile the DLL and other components.

2. Inject the DLL:
   - Use the provided injector to load the hooking DLL into a target process.

3. Test:
   - Run the hook detection program and test stub to validate hook functionality.

---

## License

This project is for educational purposes only. Ensure you comply with applicable laws and ethical guidelines when using this code.
