#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <cstring> // 用于 _stricmp

DWORD GetExplorerPID() {
    // 获取当前进程的会话 ID
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentSessionId;
    if (!ProcessIdToSessionId(currentPid, &currentSessionId)) {
        std::cout << "Failed to get current session ID" << std::endl;
        return 0;
    }

    // 创建进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 枚举进程
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // 检查进程名是否为 explorer.exe
            if (_stricmp(pe32.szExeFile, "explorer.exe") == 0) {
                DWORD sessionId = 0;
                // 获取进程的会话 ID
                if (ProcessIdToSessionId(pe32.th32ProcessID, &sessionId)) {
                    // 如果会话 ID 匹配当前进程的会话 ID，则返回该进程 ID
                    if (sessionId == currentSessionId) {
                        CloseHandle(hSnapshot);
                        return pe32.th32ProcessID;
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

void InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return;

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pDllPath, 0, NULL);

    CloseHandle(hThread);
    CloseHandle(hProcess);
}

int main() {
    DWORD explorerPID = GetExplorerPID();
    if (!explorerPID) {
        std::cout << "Cannot find current user's explorer.exe" << std::endl;
        return 1;
    }

    char dllPath[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, dllPath);
    strcat_s(dllPath, "\\mainWindow.dll");
    InjectDLL(explorerPID, dllPath);
    
    std::cout << "DLL Inject Success!" << std::endl;
    return 0;
}