#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <shlobj.h>
#include <shellapi.h>
#include <sddl.h>
#include <accctrl.h>
#include <Aclapi.h>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <strsafe.h>
#include <commctrl.h>
#include <deque>

#include <wtsapi32.h>   // for WTSQueryUserToken, WTSGetActiveConsoleSessionId
#include <userenv.h>    // for CreateEnvironmentBlock, DestroyEnvironmentBlock

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_SHOWLOG 1001
#define ID_TRAY_EXIT 1002
#define WM_UPDATE_LOG (WM_USER + 100)

std::atomic<bool> killSeewoStarted{false}; // 全局声明，放在所有函数前

std::mutex g_logMutex;
std::deque<std::wstring> g_logLines;
constexpr size_t MAX_LOG_LINES = 1000;

HWND g_hLogWnd = NULL; // 全局保存Log窗口句柄

void AppendLog(const std::wstring& line) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logLines.push_back(line);
    if (g_logLines.size() > MAX_LOG_LINES) g_logLines.pop_front();
    if (g_hLogWnd && IsWindow(g_hLogWnd)) {
        PostMessageW(g_hLogWnd, WM_UPDATE_LOG, 0, 0);
    }
}

std::wstring GetAllLog() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::wstring all;
    for (const auto& l : g_logLines) {
        all += l + L"\r\n";
    }
    return all;
}

void LogOut(const std::wstring& msg) {
    AppendLog(msg);
}

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
    if (!EnableDebugPrivilege()) {
        //std::wcerr << L"[ERROR] EnableDebugPrivilege failed: " << GetLastError() << std::endl;
        {
            std::wstring logMsg = L"[ERROR] EnableDebugPrivilege failed: " + std::to_wstring(GetLastError());
            AppendLog(logMsg);
        }
        return false;
    }

    DWORD pid = FindSystemProcessPID();
    if (!pid) {
        //std::wcerr << L"[ERROR] FindSystemProcessPID failed." << std::endl;
        {
            std::wstring logMsg = L"[ERROR] FindSystemProcessPID failed.";
            AppendLog(logMsg);
        }
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        //std::wcerr << L"[ERROR] OpenProcess failed: " << GetLastError() << std::endl;
        {
            std::wstring logMsg = L"[ERROR] OpenProcess failed: " + std::to_wstring(GetLastError());
            AppendLog(logMsg);
        }
        return false;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        //std::wcerr << L"[ERROR] OpenProcessToken failed: " << GetLastError() << std::endl;
        {
            std::wstring logMsg = L"[ERROR] OpenProcessToken failed: " + std::to_wstring(GetLastError());
            AppendLog(logMsg);
        }
        CloseHandle(hProc);
        return false;
    }

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDup)) {
        //std::wcerr << L"[ERROR] DuplicateTokenEx failed: " << GetLastError() << std::endl;
        {
            std::wstring logMsg = L"[ERROR] DuplicateTokenEx failed: " + std::to_wstring(GetLastError());
            AppendLog(logMsg);
        }
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    BOOL result = CreateProcessWithTokenW(
        hDup, 0, exePath, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (!result) {
        //std::wcerr << L"[ERROR] CreateProcessWithTokenW failed: " << GetLastError() << std::endl;
        {
            std::wstring logMsg = L"[ERROR] CreateProcessWithTokenW failed: " + std::to_wstring(GetLastError());
            AppendLog(logMsg);
        }
    }

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

volatile bool RunTopMost = true; // 控制是否启用去除最前端功能

void DisableSeewoTopMost() {
    while (true) {
        std::vector<DWORD> pids;
        PROCESSENTRY32W pe = { sizeof(pe) };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"SeewoServiceAssistant.exe") == 0) {
                        pids.push_back(pe.th32ProcessID);
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        for (DWORD pid : pids) {
            struct EnumWindowsParam {
                std::vector<HWND>* windows;
                DWORD pid;
            } param = { new std::vector<HWND>(), pid };
            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                EnumWindowsParam* param = (EnumWindowsParam*)lParam;
                DWORD windowPid;
                GetWindowThreadProcessId(hwnd, &windowPid);
                if (windowPid == param->pid) {
                    param->windows->push_back(hwnd);
                }
                return TRUE;
            }, (LPARAM)&param);
            for (HWND hwnd : *param.windows) {
                if(RunTopMost){
                    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                    //std::wcout << L"[DisableTopMost] Disabled topmost for window: " << hwnd << std::endl;
                    //{
                    //    std::wstring logMsg = L"[DisableTopMost] Disabled topmost for window: " + std::to_wstring(reinterpret_cast<UINT_PTR>(hwnd));
                    //    AppendLog(logMsg);
                    //}
                    
                }else{
                    //std::wcout << L"[DisableTopMost] Found window hwnd:" << hwnd << " ,skipped."<< std::endl;
                    //{
                    //    std::wstring logMsg = L"[DisableTopMost] Found window hwnd: " + std::to_wstring(reinterpret_cast<UINT_PTR>(hwnd)) + L" ,skipped.";
                    //    AppendLog(logMsg);
                    //}
                }
                
            }
            delete param.windows;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}

// SeewoKiller核心查杀任务，每1000ms查杀一次指定进程
void KillSeewoTask() {
    static const wchar_t* targets[] = {
        L"SeewoServiceAssistant.exe",
        L"SeewoCore.exe",
        L"media_capture.exe",
        L"rtcRemoteDesktop.exe",
        L"screenCapture.exe",
        L"SeewoAbility.exe"
    };
    while (killSeewoStarted) { // 只要killSeewoStarted为true才循环
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    for (const auto& name : targets) {
                        if (_wcsicmp(pe.szExeFile, name) == 0) {
                            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (hProc) {
                                TerminateProcess(hProc, 0);
                                CloseHandle(hProc);
                                //std::wcout << L"[SeewoKiller] Terminated: " << name << std::endl;
                                {
                                    std::wstring logMsg = L"[SeewoKiller] Terminated: " + std::wstring(name);
                                    AppendLog(logMsg);
                                }
                            }
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    AppendLog(L"[KillSeewoTask] Thread exited.");
}

// SeewoFreezer核心冻结任务，挂起所有目标进程，完成后线程自动退出
void PerfectFreezeTask() {
    std::vector<std::wstring> targets = {
        L"SeewoCore.exe", L"SeewoServiceAssistant.exe", L"SeewoAbility.exe",
        L"media_capture.exe", L"screenCapture.exe", L"rtcRemoteDesktop.exe"
    };
    std::unordered_map<DWORD, bool> suspended;
    bool allSuspended = false;
    while (!allSuspended) {
        bool dummy = false;
        allSuspended = true;
        PROCESSENTRY32W pe = { sizeof(pe) };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            if (Process32FirstW(snap, &pe)) {
                do {
                    for (const auto& target : targets) {
                        if (_wcsicmp(pe.szExeFile, target.c_str()) == 0) {
                            DWORD pid = pe.th32ProcessID;
                            if (!suspended.count(pid)) {
                                typedef NTSTATUS(WINAPI* PNtSuspendProcess)(HANDLE);
                                PNtSuspendProcess NtSuspend = (PNtSuspendProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");
                                if (NtSuspend) {
                                    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
                                    if (h) {
                                        NTSTATUS status = NtSuspend(h);
                                        CloseHandle(h);
                                        if (status == 0) {
                                            //std::wcout << L"[PerfectFreeze] Suspended PID: " << pid << L" (" << pe.szExeFile << L")\n";
                                            {
                                                std::wstring logMsg = L"[PerfectFreeze] Suspended PID: " + std::to_wstring(pid) + L" (" + pe.szExeFile + L")";
                                                AppendLog(logMsg);
                                            }
                                            suspended[pid] = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        // 检查是否全部挂起
        for (const auto& target : targets) {
            bool found = false;
            PROCESSENTRY32W pe2 = { sizeof(pe2) };
            HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap2 != INVALID_HANDLE_VALUE) {
                if (Process32FirstW(snap2, &pe2)) {
                    do {
                        if (_wcsicmp(pe2.szExeFile, target.c_str()) == 0) {
                            DWORD pid = pe2.th32ProcessID;
                            if (!suspended.count(pid)) {
                                found = true;
                                break;
                            }
                        }
                    } while (Process32NextW(snap2, &pe2));
                }
                CloseHandle(snap2);
            }
            if (found) {
                allSuspended = false;
                break;
            }
        }
        if (!allSuspended) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    //std::wcout << L"[PerfectFreeze] All target processes suspended.\n";
    //std::wcout << L"[PerfectFreeze] Task thread exiting.\n";
    {
        std::wstring logMsg = L"[PerfectFreeze] All target processes suspended.";
        AppendLog(logMsg);
        logMsg = L"[PerfectFreeze] Task thread exiting.";
        AppendLog(logMsg);
    }
}

// 解冻SeewoServiceAssistant.exe进程的任务
void UndoFreezeTask() {
    typedef NTSTATUS(WINAPI* PNtResumeProcess)(HANDLE);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        AppendLog(L"[UndoFreeze] GetModuleHandleW(ntdll.dll) failed.");
        return;
    }
    auto NtResumeProcess = (PNtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    if (!NtResumeProcess) {
        AppendLog(L"[UndoFreeze] NtResumeProcess not found in ntdll.dll.");
        return;
    }

    std::vector<std::wstring> targets = {
        L"SeewoCore.exe", L"SeewoServiceAssistant.exe", L"SeewoAbility.exe",
        L"media_capture.exe", L"screenCapture.exe", L"rtcRemoteDesktop.exe"
    };

    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        AppendLog(L"[UndoFreeze] CreateToolhelp32Snapshot failed.");
        return;
    }

    std::unordered_set<DWORD> resumedPids;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (const auto& target : targets) {
                if (_wcsicmp(pe.szExeFile, target.c_str()) == 0) {
                    DWORD pid = pe.th32ProcessID;
                    if (resumedPids.count(pid)) break; // 已处理过该 PID
                    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
                    if (!hProc) {
                        DWORD err = GetLastError();
                        std::wstring logMsg = L"[UndoFreeze] OpenProcess failed for PID: " + std::to_wstring(pid) + L" (" + pe.szExeFile + L") Error: " + std::to_wstring(err);
                        AppendLog(logMsg);
                    } else {
                        NTSTATUS status = NtResumeProcess(hProc);
                        CloseHandle(hProc);
                        if (status == 0) {
                            resumedPids.insert(pid);
                            std::wstring logMsg = L"[UndoFreeze] Resumed PID: " + std::to_wstring(pid) + L" (" + pe.szExeFile + L")";
                            AppendLog(logMsg);
                        } else {
                            std::wstring logMsg = L"[UndoFreeze] Failed to resume PID: " + std::to_wstring(pid) + L" (" + pe.szExeFile + L") NTSTATUS: " + std::to_wstring((long long)status);
                            AppendLog(logMsg);
                        }
                    }
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (!resumedPids.empty()) {
        std::wstring logMsg = L"[UndoFreeze] Total processes resumed: " + std::to_wstring(resumedPids.size());
        AppendLog(logMsg);
    } else {
        AppendLog(L"[UndoFreeze] No target processes found or none resumed.");
    }
    {
        std::wstring logMsg = L"[UndoFreeze] Task thread exiting.";
        AppendLog(logMsg);
    }
}

void PipeWorker(HANDLE hPipe) {
    wchar_t buffer[512] = {0};
    DWORD bytesRead = 0;
    static std::atomic<bool> perfectFreezeStarted{false};
    static std::atomic<bool> undoFreezeStarted{false};
    while (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead / sizeof(wchar_t)] = 0;
        std::wstring msg(buffer);
        //std::wcout << L"[PIPE] Received: " << msg << std::endl;
        {
            std::wstring logMsg = L"[PIPE] Received: " + msg;
            AppendLog(logMsg);
        }
        if (msg == L"KillSeewo") {
            //std::wcout << L"[ACTION] KillSeewo triggered." << std::endl;
            {
                std::wstring logMsg = L"[ACTION] KillSeewo triggered.";
                AppendLog(logMsg);
            }
            if (!killSeewoStarted.exchange(true)) {
                //std::wcout << L"[Info] KillSeewoTask thread started!" << std::endl;
                {
                    std::wstring logMsg = L"[Info] KillSeewoTask thread started!";
                    AppendLog(logMsg);
                }
                std::thread(KillSeewoTask).detach();
            }else{
                //std::wcout << L"[Info] KillSeewoTask thread already running!" << std::endl;
                {
                    std::wstring logMsg = L"[Info] KillSeewoTask thread already running!";
                    AppendLog(logMsg);
                }
            }
        } else if (msg == L"RestartSeewo"){
            //add code here to restart seewo
            {
                std::wstring logmsg = L"[Info] RestartSeewo Started";
                AppendLog(logmsg);
            }
            // 0. 检查并终止KillSeewoTask线程
            if (killSeewoStarted) {
                AppendLog(L"[RestartSeewo] KillSeewoTask is running, stopping it...");
                killSeewoStarted = false;
                // 等待KillSeewoTask线程退出
                Sleep(1200); // 稍微多等一点，确保线程退出
            }
            // 1. 结束所有Seewo相关进程
            static const wchar_t* targets[] = {
                L"SeewoServiceAssistant.exe",
                L"SeewoCore.exe",
                L"media_capture.exe",
                L"rtcRemoteDesktop.exe",
                L"screenCapture.exe",
                L"SeewoAbility.exe"
            };
            {
                std::wstring logmsg = L"[RestartSeewo] Killing Seewo processes...";
                AppendLog(logmsg);
            }
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = { sizeof(pe) };
                if (Process32FirstW(hSnap, &pe)) {
                    do {
                        for (const auto& name : targets) {
                            if (_wcsicmp(pe.szExeFile, name) == 0) {
                                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                                if (hProc) {
                                    TerminateProcess(hProc, 0);
                                    CloseHandle(hProc);
                                    std::wstring logMsg = L"[RestartSeewo] Terminated: ";
                                    logMsg += name;
                                    AppendLog(logMsg);
                                }
                            }
                        }
                    } while (Process32NextW(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            // 2. 启动Seewo相关进程
            std::vector<std::wstring> exeList = {
                L"C:\\Program Files (x86)\\Seewo\\SeewoService\\SeewoService_1.5.5.3862\\SeewoServiceAssistant\\SeewoServiceAssistant.exe",
                L"C:\\Program Files (x86)\\Seewo\\SeewoService\\SeewoService_1.5.5.3862\\SeewoAbility\\SeewoAbility.exe"
                //L"C:\\Program Files (x86)\\Seewo\\SeewoService\\SeewoService_1.5.4.3822\\screenCapture.exe",
                //L"C:\\Program Files (x86)\\Seewo\\SeewoService\\SeewoService_1.5.4.3822\\media_capture.exe",
                //L"C:\\Program Files (x86)\\Seewo\\SeewoService\\SeewoService_1.5.4.3822\\rtcRemoteDesktop.exe"
            };
            for (size_t i = 0; i < exeList.size(); ++i) {
                std::wstring exe = exeList[i];
                std::wstring logMsg = L"[RestartSeewo] Starting: ";
                logMsg += exe;
                AppendLog(logMsg);
                // 检查文件是否存在
                DWORD attr = GetFileAttributesW(exe.c_str());
                if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    AppendLog(L"[RestartSeewo] File not found: " + exe);
                    continue;
                }
                // 构造带引号的命令行
                std::wstring cmdLine = L"\"" + exe + L"\"";
                STARTUPINFOW si = { sizeof(si) };
                PROCESS_INFORMATION pi = {};
                BOOL ok = CreateProcessW(exe.c_str(), (LPWSTR)cmdLine.c_str(), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
                if (ok) {
                    AppendLog(L"[RestartSeewo] Started successfully.");
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                } else {
                    DWORD err = GetLastError();
                    if (err == ERROR_ELEVATION_REQUIRED || err == 740) {
                        AppendLog(L"[RestartSeewo] CreateProcessW elevation required, retrying with ShellExecuteW runas...");
                        HINSTANCE hRes = ShellExecuteW(NULL, L"runas", exe.c_str(), NULL, NULL, SW_SHOWNORMAL);
                        if ((INT_PTR)hRes > 32) {
                            AppendLog(L"[RestartSeewo] ShellExecuteW(runas) started successfully.");
                        } else {
                            AppendLog(L"[RestartSeewo] ShellExecuteW(runas) failed: " + std::to_wstring((INT_PTR)hRes));
                        }
                    } else {
                        AppendLog(L"[RestartSeewo] Failed to start: " + exe + L" Error: " + std::to_wstring(err));
                    }
                }
                Sleep(1000); // 等待1秒
            }
            // 3. 启动核心服务
            {
                AppendLog(L"[RestartSeewo] Starting SeewoCoreService via SC...");
                SHELLEXECUTEINFOW sei = { sizeof(sei) };
                sei.fMask = SEE_MASK_NOCLOSEPROCESS;
                sei.lpVerb = L"open";
                sei.lpFile = L"sc";
                sei.lpParameters = L"start SeewoCoreService";
                sei.nShow = SW_HIDE;
                if (ShellExecuteExW(&sei)) {
                    AppendLog(L"[RestartSeewo] SC command launched.");
                    if (sei.hProcess) CloseHandle(sei.hProcess);
                } else {
                    AppendLog(L"[RestartSeewo] Failed to launch SC. Error: " + std::to_wstring(GetLastError()));
                }
            }
            AppendLog(L"[RestartSeewo] All done.");
        } else if (msg == L"PerfectFreeze") {
            //std::wcout << L"[ACTION] PerfectFreeze triggered." << std::endl;
            {
                std::wstring logMsg = L"[ACTION] PerfectFreeze triggered.";
                AppendLog(logMsg);
            }
            if (!perfectFreezeStarted.exchange(true)) {
                //std::wcout << L"[Info] PerfectFreezeTask thread started!" << std::endl;
                {
                    std::wstring logMsg = L"[Info] PerfectFreezeTask thread started!";
                    AppendLog(logMsg);
                }
                std::thread([](){ PerfectFreezeTask(); perfectFreezeStarted = false; }).detach();
            }else{
                //std::wcout << L"[Info] PerfectFreezeTask thread already running!" << std::endl;
                {
                    std::wstring logMsg = L"[Info] PerfectFreezeTask thread already running!";
                    AppendLog(logMsg);
                }
            }
        } else if (msg == L"UndoFreeze") {
            //std::wcout << L"[ACTION] UndoFreeze triggered." << std::endl;
            {
                std::wstring logMsg = L"[ACTION] UndoFreeze triggered.";
                AppendLog(logMsg);
            }
            if (!undoFreezeStarted.exchange(true)) {
                //std::wcout << L"[Info] UndoFreezeTask thread started!" << std::endl;
                {
                    std::wstring logMsg = L"[Info] UndoFreezeTask thread started!";
                    AppendLog(logMsg);
                }
                std::thread([](){ UndoFreezeTask(); undoFreezeStarted = false; }).detach();
            } else {
                //std::wcout << L"[Info] UndoFreezeTask thread already running!" << std::endl;
                {
                    std::wstring logMsg = L"[Info] UndoFreezeTask thread already running!";
                    AppendLog(logMsg);
                }
            }
        } else if (msg == L"CheckBox:0"){
            //std::wcout << L"[ACTION] DisableTopMost triggered." << std::endl;
            {
                std::wstring logMsg = L"[ACTION] DisableTopMost triggered.";
                AppendLog(logMsg);
            }
            RunTopMost = false; // 停止去除最前端功能
        } else if (msg == L"CheckBox:1") {
            //std::wcout << L"[ACTION] EnableTopMost triggered." << std::endl;
            {
                std::wstring logMsg = L"[ACTION] EnableTopMost triggered.";
                AppendLog(logMsg);
            }
            RunTopMost = true; // 启用去除最前端功能
        } else if(msg == L"WindowsVerified"){
            AppendLog(L"[log] WindowsVerified.");

        }
        else {
            //std::wcout << L"[UNKNOWN ACTION] Received unknown command: " << msg << std::endl;
            //{
            //    std::wstring logMsg = L"[PIPE] Received unknown command: " + msg;
            //    AppendLog(logMsg);
            //}
        }
        ZeroMemory(buffer, sizeof(buffer));
    }
    //std::wcout << L"[SYSTEM] Client disconnected." << std::endl;
    {
        std::wstring logMsg = L"[SYSTEM] Client disconnected.";
        AppendLog(logMsg);
    }
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}


bool RestartExplorerAsActiveUser()
{
    DWORD activeSessionId = WTSGetActiveConsoleSessionId();
    if (activeSessionId == 0xFFFFFFFF)
        return false;

    HANDLE hUserToken = NULL;
    if (!WTSQueryUserToken(activeSessionId, &hUserToken))
        return false;

    HANDLE hPrimaryToken = NULL;
    if (!DuplicateTokenEx(hUserToken, TOKEN_ALL_ACCESS, NULL,
        SecurityIdentification, TokenPrimary, &hPrimaryToken))
    {
        CloseHandle(hUserToken);
        return false;
    }

    // 杀掉当前 Session 下的所有 explorer.exe
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnap, &pe))
        {
            do {
                if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0)
                {
                    DWORD pidSession = 0;
                    if (ProcessIdToSessionId(pe.th32ProcessID, &pidSession) && pidSession == activeSessionId)
                    {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hProc)
                        {
                            TerminateProcess(hProc, 0);
                            CloseHandle(hProc);
                        }
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    // 设置启动信息（桌面环境非常关键）
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION pi = {};
    WCHAR explorerPath[MAX_PATH] = L"C:\\Windows\\explorer.exe";

    // 继承用户环境变量，避免空白桌面或路径错误
    LPVOID pEnv = NULL;
    CreateEnvironmentBlock(&pEnv, hPrimaryToken, FALSE);

    BOOL bRes = CreateProcessAsUserW(
        hPrimaryToken,
        explorerPath,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
        pEnv,
        NULL,
        &si,
        &pi
    );

    if (pEnv)
        DestroyEnvironmentBlock(pEnv);

    if (bRes)
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    CloseHandle(hPrimaryToken);
    CloseHandle(hUserToken);

    return bRes == TRUE;
}


LRESULT CALLBACK LogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HWND hEdit;
    switch (msg) {
    case WM_CREATE:
        hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 0, 0, hwnd, NULL, GetModuleHandleW(NULL), NULL);
        {
            std::wstring log = GetAllLog();
            SetWindowTextW(hEdit, log.c_str());
            SendMessageW(hEdit, EM_SETSEL, -1, -1);
            SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
            SendMessageW(hEdit, WM_VSCROLL, SB_BOTTOM, 0);
            // 设置窗口标题
            int remain = (int)(MAX_LOG_LINES - g_logLines.size());
            wchar_t title[128];
            swprintf(title, 128, L"SeewoKiller Log   Remaining messages:%d", remain);
            SetWindowTextW(hwnd, title);
        }
        break;
    case WM_SIZE:
        MoveWindow(hEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
        break;
    case WM_UPDATE_LOG:
        {
            int firstLine = (int)SendMessageW(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
            int totalLines = (int)SendMessageW(hEdit, EM_GETLINECOUNT, 0, 0);
            RECT rc; GetClientRect(hEdit, &rc);
            TEXTMETRICW tm; HDC hdc = GetDC(hEdit);
            HFONT hFont = (HFONT)SendMessageW(hEdit, WM_GETFONT, 0, 0);
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            GetTextMetricsW(hdc, &tm);
            SelectObject(hdc, hOldFont);
            ReleaseDC(hEdit, hdc);
            int linesPerPage = (rc.bottom - rc.top) / tm.tmHeight;
            bool atBottom = (firstLine + linesPerPage + 1 >= totalLines);
            std::wstring log = GetAllLog();
            SetWindowTextW(hEdit, log.c_str());
            if (atBottom) {
                SendMessageW(hEdit, EM_SETSEL, -1, -1);
                SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
                SendMessageW(hEdit, WM_VSCROLL, SB_BOTTOM, 0);
            } else {
                SendMessageW(hEdit, EM_LINESCROLL, 0, firstLine);
            }
            // 设置窗口标题
            int remain = (int)(MAX_LOG_LINES - g_logLines.size());
            wchar_t title[128];
            swprintf(title, 128, L"SeewoKiller Log   Remaining messages:%d", remain);
            SetWindowTextW(hwnd, title);
        }
        break;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        g_hLogWnd = NULL;
        return 0;
    case WM_DESTROY:
        g_hLogWnd = NULL;
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void ShowLogWindow(HINSTANCE hInst, HWND hParent) {
    if (g_hLogWnd && IsWindow(g_hLogWnd)) {
        ShowWindow(g_hLogWnd, SW_SHOWNORMAL);
        SetForegroundWindow(g_hLogWnd);
        return;
    }
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = LogWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SeewoKillerLogWnd";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&wc);
    g_hLogWnd = CreateWindowW(L"SeewoKillerLogWnd", L"SeewoKiller Log", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 400, hParent, NULL, hInst, NULL);
    ShowWindow(g_hLogWnd, SW_SHOWNORMAL);
    UpdateWindow(g_hLogWnd);
}

// 托盘图标相关
NOTIFYICONDATAW g_nid = {0};
HMENU g_hTrayMenu = NULL;

void AddTrayIcon(HWND hwnd, HINSTANCE hInst) {
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"SeewoKiller");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

void RemoveTrayIcon() {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

void ShowTrayMenu(HWND hwnd) {
    if (!g_hTrayMenu) {
        g_hTrayMenu = CreatePopupMenu();
        AppendMenuW(g_hTrayMenu, MF_STRING, ID_TRAY_SHOWLOG, L"ShowLog");
        AppendMenuW(g_hTrayMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");
    }
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(g_hTrayMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP) {
            ShowTrayMenu(hwnd);
        } else if (lParam == WM_LBUTTONDBLCLK) {
            ShowLogWindow((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE), hwnd);
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_TRAY_SHOWLOG) {
            ShowLogWindow((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE), hwnd);
        } else if (LOWORD(wParam) == ID_TRAY_EXIT) {
            // // 杀死当前用户下所有explorer.exe进程
            // DWORD currentSessionId = 0;
            // ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId);
            // HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            // if (hSnap != INVALID_HANDLE_VALUE) {
            //     PROCESSENTRY32W pe = { sizeof(pe) };
            //     if (Process32FirstW(hSnap, &pe)) {
            //         do {
            //             if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
            //                 HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            //                 if (hProc) {
            //                     DWORD sessionId = 0;
            //                     if (ProcessIdToSessionId(pe.th32ProcessID, &sessionId) && sessionId == currentSessionId) {
            //                         TerminateProcess(hProc, 0);
            //                     }
            //                     CloseHandle(hProc);
            //                 }
            //             }
            //         } while (Process32NextW(hSnap, &pe));
            //     }
            //     CloseHandle(hSnap);
            // }
            // // 重启explorer.exe（当前用户权限）
            // ShellExecuteW(NULL, NULL, L"explorer.exe", NULL, NULL, SW_SHOW);
            //使用当前活动用户权限重启explorer.exe
            RestartExplorerAsActiveUser();
            // 退出程序
            PostQuitMessage(0);
        }
        break;
    case WM_DESTROY:
        RemoveTrayIcon();
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    // 日志：当前用户
    AppendLog(L"Now running as: " + GetCurrentUser());
    if (!IsRunningAsSystem()) {
        if (!IsRunningAsAdmin()) {
            AppendLog(L"Why not run as Administrator? bakabakabakabakabaka");
            ElevateToAdmin();
        }
        AppendLog(L"SYSTEM access needed. Attempting elevation...");
        bool launchResult = LaunchSystemCopyAndExit();
        if (!launchResult) {
            AppendLog(L"[ERROR] SYSTEM elevation failed!");
            Sleep(5000);
        }
    }
    AppendLog(L"[SYSTEM] Entered SYSTEM main loop!");
    // 启动后台线程
    std::thread(DisableSeewoTopMost).detach();

    // 注册主窗口类
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"SeewoKillerMainWnd";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(L"SeewoKillerMainWnd", L"SeewoKiller", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 200, NULL, NULL, hInstance, NULL);
    // 隐藏主窗口
    ShowWindow(hwnd, SW_HIDE);
    // 托盘图标
    AddTrayIcon(hwnd, hInstance);

    // 持续服务型主循环，每次都新建管道实例，断开后自动重建
    std::thread([hwnd]() {
        while (true) {
            SECURITY_ATTRIBUTES sa = {0};
            PSECURITY_DESCRIPTOR pSD = NULL;
            ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &pSD, NULL);
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = pSD;
            sa.bInheritHandle = FALSE;
            HANDLE hPipe = CreateNamedPipeW(
                L"\\\\.\\pipe\\SeewoKillerPipe",
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                5, 4096, 4096, 0, &sa);
            if (!hPipe || hPipe == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                AppendLog(L"Failed to create pipe. Error: " + std::to_wstring(err));
                if (pSD) LocalFree(pSD);
                Sleep(1000);
                continue;
            }
            if (pSD) LocalFree(pSD);
            AppendLog(L"[SYSTEM] Waiting for client connection...");
            BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
            if (connected) {
                AppendLog(L"[SYSTEM] Client connected.");
                std::thread(PipeWorker, hPipe).detach();
            } else {
                CloseHandle(hPipe);
            }
        }
    }).detach();

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

