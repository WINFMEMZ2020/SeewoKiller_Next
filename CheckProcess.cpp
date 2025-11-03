// check_launcher.cpp
// 检查 KillerService.exe 是否在运行，若没有则启动当前目录下的 launcher.exe

#include <windows.h>
#include <tlhelp32.h>
#include <cwchar>
#include <string>
#include <iostream>

bool IsProcessRunning(const std::wstring& exeName) {
    bool found = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            // 比较进程名（不区分大小写）
            if (_wcsicmp(pe.szExeFile, exeName.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

std::wstring GetCurrentExeDirectory() {
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (len == 0 || len == MAX_PATH) return L"";
    // 去掉可执行文件名，保留目录（包含最后的反斜杠）
    wchar_t* p = wcsrchr(path, L'\\');
    if (p) {
        *(p + 1) = L'\0';
        return std::wstring(path);
    }
    return L"";
}

bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES);
}

int wmain() {
    const std::wstring targetProcess = L"KillerService.exe";
    const std::wstring launcherName = L"launcher.exe";

    if (IsProcessRunning(targetProcess)) {
        std::wcout << L"检测到 " << targetProcess << L" 正在运行，退出。\n";
        return 0;
    }

    std::wstring dir = GetCurrentExeDirectory();
    if (dir.empty()) {
        std::wcerr << L"无法获取当前可执行文件目录。\n";
        return 1;
    }

    std::wstring launcherPath = dir + launcherName;
    if (!FileExists(launcherPath)) {
        std::wcerr << L"未找到 " << launcherPath << L"\n";
        return 2;
    }

    // 启动 launcher.exe
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // CreateProcess 的第一个参数可以是 NULL，第二个参数为可写命令行字符串
    // 所以复制一个可写的缓冲区
    wchar_t cmdline[MAX_PATH];
    wcsncpy_s(cmdline, launcherPath.c_str(), _TRUNCATE);

    BOOL ok = CreateProcessW(
        NULL,           // lpApplicationName
        cmdline,        // lpCommandLine (可被修改)
        NULL,           // lpProcessAttributes
        NULL,           // lpThreadAttributes
        FALSE,          // bInheritHandles
        0,              // dwCreationFlags
        NULL,           // lpEnvironment
        dir.c_str(),    // lpCurrentDirectory
        &si,
        &pi
    );

    if (!ok) {
        DWORD err = GetLastError();
        std::wcerr << L"启动 " << launcherPath << L" 失败，错误码: " << err << L"\n";
        return 3;
    }

    // 启动成功：关闭句柄，主程序可以直接退出（若想等待 launcher 结束，可 WaitForSingleObject）
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::wcout << L"已启动 " << launcherPath << L"\n";
    return 0;
}
