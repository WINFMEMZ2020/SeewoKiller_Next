#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <thread>
#include <shlobj.h>
#include <shellapi.h>
#include <sddl.h>
#include <accctrl.h>

BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return result;
}

DWORD FindSystemProcessPID(const std::wstring& target = L"winlogon.exe") {
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, target.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

bool LaunchAsSystem(const wchar_t* exePath) {
    if (!EnableDebugPrivilege()) return false;

    DWORD pid = FindSystemProcessPID();
    if (!pid) return false;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return false;
    }

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDup)) {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    BOOL result = CreateProcessWithTokenW(
        hDup, 0, exePath, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    CloseHandle(hDup);
    CloseHandle(hToken);
    CloseHandle(hProc);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);

    return result;
}

bool LaunchSystemCopyAndExit() {
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    if (LaunchAsSystem(path)) {
        ExitProcess(0); // ✅ SYSTEM 启动成功，退出当前进程
    }

    return false;
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup);
    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);
    return isAdmin;
}

bool IsRunningAsSystem() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;

    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) return false;

    PSID pSid = ((TOKEN_USER*)buffer.data())->User.Sid;
    LPWSTR sidStr = NULL;
    ConvertSidToStringSidW(pSid, &sidStr);
    std::wstring sid(sidStr);
    LocalFree(sidStr);
    return sid == L"S-1-5-18"; // SID for SYSTEM
}

void ElevateToAdmin() {
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    ShellExecuteW(NULL, L"runas", path, NULL, NULL, SW_SHOW);
    ExitProcess(0);
}

std::wstring GetCurrentUser() {
    HANDLE hToken;
    DWORD dwSize = 0;
    PTOKEN_USER ptu = nullptr;
    wchar_t username[256] = {0};
    wchar_t domain[256] = {0};
    DWORD userSize = 256;
    DWORD domainSize = 256;
    SID_NAME_USE sidType;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return L"Unknown";

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    ptu = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
    
    if (!GetTokenInformation(hToken, TokenUser, ptu, dwSize, &dwSize)) {
        LocalFree(ptu);
        CloseHandle(hToken);
        return L"Unknown";
    }

    LookupAccountSidW(NULL, ptu->User.Sid, username, &userSize, domain, &domainSize, &sidType);
    
    LocalFree(ptu);
    CloseHandle(hToken);
    return std::wstring(domain) + L"\\" + username;
}

std::vector<std::pair<DWORD, std::wstring>> FindTargetProcesses(const std::vector<std::wstring>& targets, bool& accessDeniedFound) {
    std::vector<std::pair<DWORD, std::wstring>> result;
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;

    if (Process32FirstW(snap, &pe)) {
        do {
            for (auto& target : targets) {
                if (_wcsicmp(pe.szExeFile, target.c_str()) == 0) {
                    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                    if (!h) {
                        DWORD err = GetLastError();
                        if (err == ERROR_ACCESS_DENIED) {
                            accessDeniedFound = true;
                        }
                    } else {
                        CloseHandle(h);
                        result.emplace_back(pe.th32ProcessID, pe.szExeFile);
                    }
                }
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return result;
}

bool SuspendProcess(DWORD pid) {
    typedef NTSTATUS(WINAPI* PNtSuspendProcess)(HANDLE);
    PNtSuspendProcess NtSuspend = (PNtSuspendProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
    if (!NtSuspend) return false;

    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) return false;

    NTSTATUS status = NtSuspend(h);
    CloseHandle(h);
    return status == 0;
}

HANDLE GetExplorerProcessToken() {
    if (!EnableDebugPrivilege()) {
        std::wcerr << L"[!] Failed to enable debug privilege" << std::endl;
        return NULL;
    }

    DWORD currentSessionId;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId)) {
        std::wcerr << L"[!] Failed to get current session ID" << std::endl;
        return NULL;
    }

    HANDLE hToken = NULL;
    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] CreateToolhelp32Snapshot failed" << std::endl;
        return NULL;
    }

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                DWORD explorerSessionId;
                if (!ProcessIdToSessionId(pe.th32ProcessID, &explorerSessionId)) {
                    continue;
                }

                if (explorerSessionId != currentSessionId) {
                    continue;
                }

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (!hProcess) {
                    continue;
                }

                HANDLE hProcToken = NULL;
                if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hProcToken)) {
                    CloseHandle(hProcess);
                    continue;
                }

                HANDLE hDupToken = NULL;
                if (DuplicateTokenEx(hProcToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
                    CloseHandle(hProcToken);
                    CloseHandle(hProcess);
                    CloseHandle(hSnap);
                    return hDupToken;
                }

                CloseHandle(hProcToken);
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return NULL;
}


int wmain() {
    std::wcout << L"Now running as: " << GetCurrentUser() << std::endl;
    if (!IsRunningAsAdmin()) {
        std::wcout << L"\nWhy not run as Administrator?\nbakabakabakabakabaka\n" <<std::endl;
        ElevateToAdmin();
    }

    //if (!IsRunningAsSystem()) {
    //    std::wcout << L"[*] SYSTEM access needed. Attempting elevation...\n";
    //    LaunchSystemCopyAndExit();
    //}

    //process started here
    WCHAR dir[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, dir, MAX_PATH);
    WCHAR* lastSlash = wcsrchr(dir, L'\\');
    if (lastSlash) *lastSlash = 0;

    WCHAR injectorPath[MAX_PATH] = {0};
    WCHAR killerPath[MAX_PATH] = {0};
    wsprintfW(injectorPath, L"%s\\injector.exe", dir);
    wsprintfW(killerPath, L"%s\\KillerService.exe", dir);

    // 使用Explorer令牌启动injector.exe
    HANDLE hExplorerToken = GetExplorerProcessToken();
    if (!hExplorerToken) {
        std::wcout << L"[ERROR] Failed to get Explorer token" << std::endl;
        return 1;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    BOOL bInjectorStarted = CreateProcessWithTokenW(
        hExplorerToken,
        0,
        injectorPath,
        NULL,
        CREATE_NO_WINDOW,  // 静默启动
        NULL,
        dir,
        &si,
        &pi
    );
    CloseHandle(hExplorerToken);

    if (!bInjectorStarted) {
        std::wcout << L"[ERROR] Failed to launch injector.exe (Error: " 
                  << GetLastError() << L")" << std::endl;
        return 1;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::wcout << L"[+] injector.exe launched successfully" << std::endl;

    // 等待100ms
    Sleep(100);

    // 以管理员权限启动KillerService.exe
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = killerPath;
    sei.nShow = SW_HIDE;  // 隐藏窗口
    sei.lpVerb = L"runas"; // 管理员权限
    
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        std::wcout << L"[ERROR] Failed to launch KillerService.exe" << std::endl;
        return 1;
    }
    CloseHandle(sei.hProcess);
    std::wcout << L"[+] KillerService.exe launched successfully" << std::endl;

    // 启动器退出
    return 0;
}
