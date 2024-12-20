#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>

// Function to get the process ID by process name
DWORD GetProcessIdByName(const char* processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD processId = 0;

    // Take a snapshot of all processes in the system
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed." << std::endl;
        return 0;
    }

    // Set the size of the structure before using it
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and check if it matches the process name
    // Iterate through all processes 
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    } else {
        std::cerr << "Process32First failed." << std::endl;
    }

    // Clean up
    CloseHandle(hProcessSnap);
    return processId;
}

// Function to inject the DLL
/*
1. Allocate memory within target process
2. Write path to DLL in allocated memory
3. Create thread that calls LoadLibraryA to load the DLL into memory
*/
bool InjectDLL(DWORD processId, const char* dllPath) {
    std::ofstream logFile("injector_log.txt", std::ios_base::app);
    logFile << "Starting DLL injection" << std::endl;

    // Open target process with full access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        logFile << "Failed to open process." << std::endl;
        logFile.close();
        return false;
    }
    logFile << "Opened process successfully." << std::endl;

    // Allocate memory for DLL path string 
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf == NULL) {
        logFile << "Failed to allocate memory in remote process." << std::endl;
        CloseHandle(hProcess);
        logFile.close();
        return false;
    }
    logFile << "Allocated memory in remote process." << std::endl;

    // Write DLL path in process memory
    if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        logFile << "Failed to write DLL path to remote process memory." << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        logFile.close();
        return false;
    }
    logFile << "Wrote DLL path to remote process memory." << std::endl;

    // Remote thread within target process
    HANDLE hThread = CreateRemoteThread(
        hProcess,                               // Target process handle
        NULL,                                   //Default sec attributes
        0,                                      //Stack size
        (LPTHREAD_START_ROUTINE)LoadLibraryA,   // Start address
        pRemoteBuf,                             //Argument for LoadLibraryA, path to DLL
        0,                                      // Creation flags
        NULL                                    // TID
        );
    if (hThread == NULL) {
        logFile << "Failed to create remote thread." << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        logFile.close();
        return false;
    }
    logFile << "Created remote thread." << std::endl;

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    logFile << "DLL injection completed successfully." << std::endl;
    logFile.close();
    return true;
}

int main(int argc, char * argv[]) {
    if(argc < 2){
        std::cerr << "Usage: injector.exe <target_process> [path_to_dll]\n";
        return 1;
    }
    // "C:\\Users\\18163\\Desktop\\dllinject\\dll\\apihook.dll"
    const char* processName = argv[1];
    const char* dllPath;

    // Use hardcoded full path if none is given
    if(argc < 3){
        dllPath = "C:\\Users\\18163\\Desktop\\dllinject\\dll\\apihook.dll";
    } else {
        dllPath = argv[2];
    }


    DWORD processId = GetProcessIdByName(processName);
    if (processId == 0) {
        std::cerr << "Process not found." << std::endl;
        return 1;
    }

    if (InjectDLL(processId, dllPath)) {
        std::cout << "DLL injected successfully." << std::endl;
    } else {
        std::cerr << "DLL injection failed." << std::endl;
    }

    return 0;
}
