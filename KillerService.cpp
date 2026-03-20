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
#include <sstream>
#include <iomanip>
#include <richedit.h>
#include <wincrypt.h>


#include <wtsapi32.h>   // for WTSQueryUserToken, WTSGetActiveConsoleSessionId
#include <userenv.h>    // for CreateEnvironmentBlock, DestroyEnvironmentBlock

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Advapi32.lib")

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_SHOWLOG 1001
#define ID_TRAY_EXIT 1002
#define ID_TRAY_PASSWORD 1003
#define WM_UPDATE_LOG (WM_USER + 100)

#define ID_PASSWORD_OK 2001
#define ID_PASSWORD_EDIT 2002
// Change password window IDs
#define ID_CHANGE_PWD_PWD_EDIT 3001
#define ID_CHANGE_PWD_CONFIRM_EDIT 3002
#define ID_CHANGE_PWD_BUTTON 3003


std::atomic<bool> killSeewoStarted{false}; // 全局声明，放在所有函数前

std::mutex g_logMutex;
std::deque<std::wstring> g_logLines;
constexpr size_t MAX_LOG_LINES = 1000;
size_t g_logShownIndex = 0;


HWND g_hLogWnd = NULL; // 全局保存Log窗口句柄
HWND g_hPasswordWnd = NULL; // 全局保存Password窗口句柄
HWND g_hChangePwdWnd = NULL; // 全局保存Change Password窗口句柄

void AppendLog(const std::wstring& line) {
    //Get now time
    SYSTEMTIME st;
    GetLocalTime(&st);
    //format time
    std::wstringstream ss;
    ss << L"["
       << std::setw(4) << std::setfill(L'0') << st.wYear << L"."
       << std::setw(2) << std::setfill(L'0') << st.wMonth << L"."
       << std::setw(2) << std::setfill(L'0') << st.wDay << L" "
       << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
       << std::setw(2) << std::setfill(L'0') << st.wSecond
       << L"]\u3000"
       << line;

    std::wstring finalLine = ss.str();
    
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logLines.push_back(finalLine);
    if (g_logLines.size() > MAX_LOG_LINES)
        g_logLines.pop_front();

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
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
            // 查找SeewoService的位置
            // 第一步：查找"C:\\Program Files (x86)\\Seewo\\SeewoService\\"目录下匹配"SeewoService_"开头的文件夹
            std::wstring seewoServiceRoot = L"C:\\Program Files (x86)\\Seewo\\SeewoService\\";
            std::wstring bestFolder; // 保存匹配到的最好（最新）的文件夹名（仅文件夹名，不含尾分隔符）
            const wchar_t* prefix = L"SeewoService_";
            size_t prefixLen = wcslen(prefix);

            WIN32_FIND_DATAW fd = {};
            std::wstring findPattern = seewoServiceRoot + L"*";
            HANDLE hFind = FindFirstFileW(findPattern.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        std::wstring name = fd.cFileName;
                        if (name.length() >= prefixLen && _wcsnicmp(name.c_str(), prefix, prefixLen) == 0) {
                            // 选取最大的目录名（简单按字典序），也可以按时间戳比较 fd.ftLastWriteTime
                            if (bestFolder.empty() || _wcsicmp(name.c_str(), bestFolder.c_str()) > 0) {
                                bestFolder = name;
                            }
                        }
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }

            std::wstring seewoServicePath; // 完整路径，含末尾反斜杠
            bool path_found = false;
            if (!bestFolder.empty()) {
                seewoServicePath = seewoServiceRoot + bestFolder + L"\\";
                path_found = true;
                AppendLog(L"[RestartSeewo] Found SeewoService folder: " + seewoServicePath);
            } else {
                AppendLog(L"[RestartSeewo] No SeewoService_* folder found under: " + seewoServiceRoot);
            }

            // 第二步：拼接完整路径
            std::wstring seewoServiceAssistantExe = seewoServicePath + L"SeewoServiceAssistant\\SeewoServiceAssistant.exe";
            DWORD attr = GetFileAttributesW(seewoServiceAssistantExe.c_str());
            std::wstring SeewoAbilityExe = seewoServicePath + L"SeewoAbility\\SeewoAbility.exe";
            DWORD attr2 = GetFileAttributesW(SeewoAbilityExe.c_str());
            
            if(path_found){
                // 2. 启动Seewo相关进程
                std::vector<std::wstring> exeList = {
                    seewoServiceAssistantExe,
                    SeewoAbilityExe
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
            }else{
                AppendLog(L"[RestartSeewo] Error:Cannot find SeewoService path, aborting restart...");
            }
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
            // std::wcout << L"[UNKNOWN ACTION] Received unknown command: " << msg << std::endl;
            // {
            //     std::wstring logMsg = L"[PIPE] Received unknown command: " + msg;
            //     AppendLog(logMsg);
            // }
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

// 判断最后一行是否可见
bool IsLastLineVisible(HWND hEdit)
{
    if (!IsWindow(hEdit)) return true;

    // 当前可见的第一行
    int firstVisible = (int)SendMessageW(hEdit, EM_GETFIRSTVISIBLELINE, 0, 0);
    // 总行数
    int totalLines = (int)SendMessageW(hEdit, EM_GETLINECOUNT, 0, 0);

    // 获取可视矩形（编辑控件内部客户区）
    RECT rc = {0};
    SendMessageW(hEdit, EM_GETRECT, 0, (LPARAM)&rc);

    // 获取行高（用当前字体的 TEXTMETRIC）
    TEXTMETRICW tm = {0};
    HDC hdc = GetDC(hEdit);
    if (hdc) {
        HFONT hFont = (HFONT)SendMessageW(hEdit, WM_GETFONT, 0, 0);
        HFONT old = (HFONT)SelectObject(hdc, hFont);
        GetTextMetricsW(hdc, &tm);
        SelectObject(hdc, old);
        ReleaseDC(hEdit, hdc);
    }
    int lineHeight = tm.tmHeight;
    if (lineHeight <= 0) lineHeight = 16; // 保底

    int viewHeight = rc.bottom - rc.top;
    int linesPerPage = viewHeight / lineHeight;
    if (linesPerPage < 1) linesPerPage = 1;

    // 如果第一可见行 + 一页行数 >= 总行数，则最后一行可见
    return (firstVisible + linesPerPage >= totalLines);
}


void ScrollEditToBottom(HWND hEdit)
{
    if (!IsWindow(hEdit)) return;
    SendMessageW(hEdit, EM_SCROLL, SB_BOTTOM, 0);
}

LRESULT CALLBACK LogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND hEdit = NULL;
    static bool s_needInitialScroll = false;

    switch (msg)
    {
    case WM_CREATE:
    {
        hEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            MSFTEDIT_CLASS,
            L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL |
            ES_MULTILINE | ES_READONLY,
            0, 0, 0, 0,
            hwnd,
            NULL,
            GetModuleHandleW(NULL),
            NULL
        );

        // 字体
        LOGFONTW lf = {};
        lf.lfHeight = -14;
        wcscpy_s(lf.lfFaceName, L"Consolas");
        HFONT hFont = CreateFontIndirectW(&lf);
        SendMessageW(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        // 初始填充已有日志
        {
            std::wstring log = GetAllLog();
            {
                std::lock_guard<std::mutex> lock(g_logMutex);
                g_logShownIndex = g_logLines.size();
            }
            // 直接插入并滚到底（初始时我们总是滚到底）
            SendMessageW(hEdit, EM_SETSEL, -1, -1);
            SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)log.c_str());
            // 这一步：ScrollEditToBottom 保证视图到底
            ScrollEditToBottom(hEdit);
        }
        // 更新窗口标题
        {
            int remain = (int)(MAX_LOG_LINES - g_logLines.size());
            wchar_t title[128];
            swprintf_s(title, sizeof(title)/sizeof(title[0]), L"SeewoKiller Log   Remaining messages: %d", remain);
            SetWindowTextW(hwnd, title);
        }
        // 标记窗口刚创建时滚动到底
        if(hEdit){
            s_needInitialScroll = true;
        }
        break;
    }

    case WM_SIZE:
        if (hEdit)
        {
            MoveWindow(hEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
            if(s_needInitialScroll){//需要滚动到最底部
                ScrollEditToBottom(hEdit);
                s_needInitialScroll = false;
            }
        }
        break;

    case WM_UPDATE_LOG:
    {
        if (!hEdit) break;

        // 在追加前判断视图是否在底部
        bool wasAtBottom = IsLastLineVisible(hEdit);

        std::wstring toAppend;
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            while (g_logShownIndex < g_logLines.size())
            {
                toAppend += g_logLines[g_logShownIndex++];
                toAppend += L"\r\n";
            }
        }

        if (!toAppend.empty())
        {
            // 插入新文本
            SendMessageW(hEdit, EM_SETSEL, -1, -1);
            SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)toAppend.c_str());
        }

        // 只有之前就在底部，才执行滚动到底
        if (wasAtBottom)
        {
            ScrollEditToBottom(hEdit);
        }

        // 更新窗口标题
        {
            int remain = (int)(MAX_LOG_LINES - g_logLines.size());
            wchar_t title[128];
            swprintf_s(title, sizeof(title)/sizeof(title[0]), L"SeewoKiller Log   Remaining messages: %d", remain);
            SetWindowTextW(hwnd, title);
        }
        break;
    }

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        g_hLogWnd = NULL;
        return 0;

    case WM_DESTROY:
        g_hLogWnd = NULL;
        break;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
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
    g_hLogWnd = CreateWindowW(L"SeewoKillerLogWnd", L"SeewoKiller Log   Remaining messages: ", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 600, hParent, NULL, hInst, NULL);
    ShowWindow(g_hLogWnd, SW_SHOWNORMAL);
    UpdateWindow(g_hLogWnd);
}

// 将 UTF-16 转为 UTF-8
static std::string Utf16ToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    if (sz <= 0) return {};
    std::string out(sz, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], sz, NULL, NULL);
    return out;
}

// 计算输入数据的 MD5（返回小写 32 字符十六进制）
static std::string Md5HexLower(const std::string& input)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[16];
    DWORD cbHash = sizeof(rgbHash);
    std::string result;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return result;
    }
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return result;
    }
    if (!input.empty()) {
        if (!CryptHashData(hHash, (BYTE*)input.data(), (DWORD)input.size(), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return result;
        }
    }
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        static const char hex[] = "0123456789abcdef";
        result.reserve(cbHash * 2);
        for (DWORD i = 0; i < cbHash; ++i) {
            result.push_back(hex[(rgbHash[i] >> 4) & 0xF]);
            result.push_back(hex[rgbHash[i] & 0xF]);
        }
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

// 从注册表读取配置的 md5（优先检查活动用户的 HKEY_USERS\<SID>，然后回退到 HKEY_CURRENT_USER），找不到返回空串
static std::wstring GetConfiguredMd5()
{
    DWORD activeSessionId = WTSGetActiveConsoleSessionId();
    AppendLog(std::wstring(L"[Password] GetConfiguredMd5 ActiveSessionId=") + std::to_wstring(activeSessionId));
    if (activeSessionId != 0xFFFFFFFF) {
        HANDLE hUserToken = NULL;
        if (WTSQueryUserToken(activeSessionId, &hUserToken)) {
            DWORD bufSize = 0;
            GetTokenInformation(hUserToken, TokenUser, NULL, 0, &bufSize);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufSize > 0) {
                std::vector<BYTE> buffer(bufSize);
                if (GetTokenInformation(hUserToken, TokenUser, buffer.data(), bufSize, &bufSize)) {
                    TOKEN_USER* ptu = (TOKEN_USER*)buffer.data();
                    LPWSTR sidStr = NULL;
                    if (ConvertSidToStringSidW(ptu->User.Sid, &sidStr)) {
                        std::wstring sid(sidStr);
                        LocalFree(sidStr);
                        std::wstring regPath = sid + L"\\SOFTWARE\\SeewoKiller\\pwd_config";
                        AppendLog(L"[Password] Checking registry path.");
                        HKEY hKey = NULL;
                        LONG res = RegOpenKeyExW(HKEY_USERS, regPath.c_str(), 0, KEY_READ, &hKey);
                        if (res == ERROR_SUCCESS) {
                            DWORD type = 0;
                            DWORD cb = 0;
                            res = RegQueryValueExW(hKey, L"md5", NULL, &type, NULL, &cb);
                            if (res == ERROR_SUCCESS && type == REG_SZ && cb > 0) {
                                std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 1);
                                res = RegQueryValueExW(hKey, L"md5", NULL, &type, (LPBYTE)buf.data(), &cb);
                                RegCloseKey(hKey);
                                if (res == ERROR_SUCCESS) {
                                    std::wstring val(buf.data());
                                    AppendLog(L"[Password] Found configured value in user hive.");
                                    CloseHandle(hUserToken);
                                    return val;
                                }
                            } else {
                                if (hKey) RegCloseKey(hKey);
                                AppendLog(L"[Password] Value not present in user hive.");
                            }
                        } else {
                            AppendLog(L"[Password] RegOpenKeyExW failed for user hive. Error: " + std::to_wstring(res));
                        }
                    }
                }
            }
            CloseHandle(hUserToken);
        }
    }

    // fallback to HKEY_CURRENT_USER
    AppendLog(L"[Password] Falling back to current user check.");
    HKEY hKey = NULL;
    LONG res = RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\SeewoKiller\\pwd_config", 0, KEY_READ, &hKey);
    if (res != ERROR_SUCCESS) {
        AppendLog(L"[Password] RegOpenKeyExW(current user hive) failed. Error: " + std::to_wstring(res));
        return L"";
    }
    DWORD type = 0;
    DWORD cb = 0;
    res = RegQueryValueExW(hKey, L"md5", NULL, &type, NULL, &cb);
    if (res != ERROR_SUCCESS || type != REG_SZ || cb == 0) {
        if (hKey) RegCloseKey(hKey);
        AppendLog(L"[Password] Value not present or invalid in current user hive.");
        return L"";
    }
    std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 1);
    res = RegQueryValueExW(hKey, L"md5", NULL, &type, (LPBYTE)buf.data(), &cb);
    RegCloseKey(hKey);
    if (res == ERROR_SUCCESS) {
        std::wstring val(buf.data());
        AppendLog(L"[Password] Found configured value in current user hive.");
        return val;
    }
    return L"";
}

// 尝试将 md5 写入注册表（优先写入活动用户的 HKEY_USERS\<SID>，回退到 HKEY_CURRENT_USER）
bool SetConfiguredMd5(const std::wstring& md5)
{
    AppendLog(L"[Password] SetConfiguredMd5 invoked.");
    DWORD activeSessionId = WTSGetActiveConsoleSessionId();
    if (activeSessionId != 0xFFFFFFFF) {
        HANDLE hUserToken = NULL;
        if (WTSQueryUserToken(activeSessionId, &hUserToken)) {
            DWORD bufSize = 0;
            GetTokenInformation(hUserToken, TokenUser, NULL, 0, &bufSize);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufSize > 0) {
                std::vector<BYTE> buffer(bufSize);
                if (GetTokenInformation(hUserToken, TokenUser, buffer.data(), bufSize, &bufSize)) {
                    TOKEN_USER* ptu = (TOKEN_USER*)buffer.data();
                    LPWSTR sidStr = NULL;
                    if (ConvertSidToStringSidW(ptu->User.Sid, &sidStr)) {
                        std::wstring sid(sidStr);
                        LocalFree(sidStr);
                        std::wstring regPath = sid + L"\\SOFTWARE\\SeewoKiller\\pwd_config";
                        AppendLog(L"[Password] Attempting to write to user hive.");
                        HKEY hKey = NULL;
                        DWORD disp = 0;
                        LONG res = RegCreateKeyExW(HKEY_USERS, regPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
                        if (res == ERROR_SUCCESS) {
                            if (md5.empty()) {
                                // delete value
                                LONG del = RegDeleteValueW(hKey, L"md5");
                                RegCloseKey(hKey);
                                if (del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND) {
                                    AppendLog(L"[Password] Deleted configured value from user hive (or it did not exist)." );
                                    CloseHandle(hUserToken);
                                    return true;
                                } else {
                                    AppendLog(L"[Password] RegDeleteValueW failed for user hive. Error: " + std::to_wstring(del));
                                }
                            } else {
                                std::wstring md5w = md5;
                                LONG r2 = RegSetValueExW(hKey, L"md5", 0, REG_SZ, (const BYTE*)md5w.c_str(), (DWORD)((md5w.size()+1)*sizeof(wchar_t)));
                                RegCloseKey(hKey);
                                if (r2 == ERROR_SUCCESS) {
                                    AppendLog(L"[Password] Successfully wrote configured value to user hive.");
                                    CloseHandle(hUserToken);
                                    return true;
                                } else {
                                    AppendLog(L"[Password] RegSetValueExW failed for user hive. Error: " + std::to_wstring(r2));
                                }
                            }
                        } else {
                            AppendLog(L"[Password] RegCreateKeyExW failed for user hive. Error: " + std::to_wstring(res));
                        }
                    }
                }
            }
            CloseHandle(hUserToken);
        } else {
            AppendLog(L"[Password] WTSQueryUserToken failed while setting configuration. Error: " + std::to_wstring(GetLastError()));
        }
    }

    // fallback to HKEY_CURRENT_USER
    AppendLog(L"[Password] Falling back to write current user hive.");
    HKEY hKey = NULL;
    DWORD disp = 0;
    LONG res2 = RegCreateKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\SeewoKiller\\pwd_config", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, &disp);
    if (res2 != ERROR_SUCCESS) {
        AppendLog(L"[Password] RegCreateKeyExW(current user hive) failed. Error: " + std::to_wstring(res2));
        return false;
    }
    if (md5.empty()) {
        LONG del = RegDeleteValueW(hKey, L"md5");
        RegCloseKey(hKey);
        if (del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND) {
            AppendLog(L"[Password] Deleted configured value from current user hive (or it did not exist)." );
            return true;
        } else {
            AppendLog(L"[Password] RegDeleteValueW failed for current user hive. Error: " + std::to_wstring(del));
            return false;
        }
    } else {
        std::wstring md5w = md5;
        LONG r3 = RegSetValueExW(hKey, L"md5", 0, REG_SZ, (const BYTE*)md5w.c_str(), (DWORD)((md5w.size()+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
        if (r3 == ERROR_SUCCESS) {
            AppendLog(L"[Password] Successfully wrote configured value to current user hive.");
            return true;
        } else {
            AppendLog(L"[Password] RegSetValueExW failed for current user hive. Error: " + std::to_wstring(r3));
            return false;
        }
    }
}

    void ShowChangePasswordWindow(HINSTANCE hInst, HWND hParent);

LRESULT CALLBACK PasswordWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND hLabel = NULL;
    static HWND hEdit = NULL;
    static HWND hButton = NULL;

    switch (msg) {
    case WM_CREATE:
    {
        hLabel = CreateWindowExW(0, L"STATIC", L"Enter Password:",
            WS_CHILD | WS_VISIBLE,
            10, 10, 110, 24,
            hwnd, NULL, GetModuleHandleW(NULL), NULL);

        hEdit = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_PASSWORD,
            130, 10, 200, 24,
            hwnd, (HMENU)ID_PASSWORD_EDIT, GetModuleHandleW(NULL), NULL);

        hButton = CreateWindowExW(0, L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 44, 80, 26,
            hwnd, (HMENU)ID_PASSWORD_OK, GetModuleHandleW(NULL), NULL);

        // 设置默认字体
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        SendMessageW(hLabel, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hButton, WM_SETFONT, (WPARAM)hFont, TRUE);
        break;
    }
    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right - rc.left;
        // label fixed width 110, spacing, edit fills rest
        MoveWindow(hLabel, 10, 10, 110, 24, TRUE);
        MoveWindow(hEdit, 130, 10, ((w - 150) > 80 ? (w - 150) : 80), 24, TRUE);
        MoveWindow(hButton, (w - 80) / 2, 44, 80, 26, TRUE);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_PASSWORD_OK) {
            // 读取输入密码
            wchar_t wbuf[512] = {0};
            if (hEdit) GetWindowTextW(hEdit, wbuf, (int)_countof(wbuf));
            std::wstring pwd(wbuf);
            AppendLog(L"[Password] OK clicked. Input length: " + std::to_wstring(pwd.size()));

            // 计算 md5（对 UTF-8 编码内容计算）
            std::string utf8 = Utf16ToUtf8(pwd);
            std::string md5 = Md5HexLower(utf8);
            std::wstring md5w(md5.begin(), md5.end());
            AppendLog(L"[Password] Computed password hash.");

            // 获取配置的 md5
            std::wstring cfg = GetConfiguredMd5();
            std::string cfg_n = Utf16ToUtf8(cfg);
            AppendLog(L"[Password] Loaded configured hash.");

            bool ok = false;
            if (!cfg_n.empty()) {
                ok = (md5 == cfg_n);
            } else {
                AppendLog(L"[Password] No configured value to compare.");
            }

            if (ok) {
                AppendLog(L"[Password] Password match: TRUE. Showing change password window.");
                // 打开修改密码窗口：不要使用验证窗口作为父窗口（父窗口随后会被销毁），使用 NULL 作为顶层窗口
                ShowChangePasswordWindow((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE), NULL);
            } else {
                AppendLog(L"[Password] Password match: FALSE");
                MessageBoxW(hwnd, L"Password incorrect", L"Password", MB_OK | MB_ICONERROR);
            }

            // 关闭当前验证窗口
            ShowWindow(hwnd, SW_HIDE);
            g_hPasswordWnd = NULL;
            DestroyWindow(hwnd);
        }
        break;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        g_hPasswordWnd = NULL;
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        g_hPasswordWnd = NULL;
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void ShowPasswordWindow(HINSTANCE hInst, HWND hParent) {
    if (g_hPasswordWnd && IsWindow(g_hPasswordWnd)) {
        ShowWindow(g_hPasswordWnd, SW_SHOWNORMAL);
        SetForegroundWindow(g_hPasswordWnd);
        return;
    }
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = PasswordWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SeewoKillerPasswordWnd";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&wc);
    g_hPasswordWnd = CreateWindowW(L"SeewoKillerPasswordWnd", L"Password",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 360, 120, hParent, NULL, hInst, NULL);
    ShowWindow(g_hPasswordWnd, SW_SHOWNORMAL);
    UpdateWindow(g_hPasswordWnd);
}

LRESULT CALLBACK ChangePwdWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND hLabel1 = NULL;
    static HWND hEdit1 = NULL;
    static HWND hLabel2 = NULL;
    static HWND hEdit2 = NULL;
    static HWND hButton = NULL;

    switch (msg) {
    case WM_CREATE:
    {
        hLabel1 = CreateWindowExW(0, L"STATIC", L"Password:",
            WS_CHILD | WS_VISIBLE,
            10, 10, 80, 24,
            hwnd, NULL, GetModuleHandleW(NULL), NULL);

        hEdit1 = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_PASSWORD,
            100, 10, 220, 24,
            hwnd, (HMENU)ID_CHANGE_PWD_PWD_EDIT, GetModuleHandleW(NULL), NULL);

        hLabel2 = CreateWindowExW(0, L"STATIC", L"Confirm:",
            WS_CHILD | WS_VISIBLE,
            10, 44, 80, 24,
            hwnd, NULL, GetModuleHandleW(NULL), NULL);

        hEdit2 = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_PASSWORD,
            100, 44, 220, 24,
            hwnd, (HMENU)ID_CHANGE_PWD_CONFIRM_EDIT, GetModuleHandleW(NULL), NULL);

        hButton = CreateWindowExW(0, L"BUTTON", L"Change Password",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            120, 80, 120, 28,
            hwnd, (HMENU)ID_CHANGE_PWD_BUTTON, GetModuleHandleW(NULL), NULL);

        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        SendMessageW(hLabel1, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hEdit1, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hLabel2, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hEdit2, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hButton, WM_SETFONT, (WPARAM)hFont, TRUE);
        break;
    }
    case WM_SIZE:
    {
        RECT rc;
        GetClientRect(hwnd, &rc);
        int w = rc.right - rc.left;
        MoveWindow(hLabel1, 10, 10, 80, 24, TRUE);
        MoveWindow(hEdit1, 100, 10, w - 120, 24, TRUE);
        MoveWindow(hLabel2, 10, 44, 80, 24, TRUE);
        MoveWindow(hEdit2, 100, 44, w - 120, 24, TRUE);
        MoveWindow(hButton, (w - 120) / 2, 80, 120, 28, TRUE);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_CHANGE_PWD_BUTTON) {
            wchar_t p1[256] = {0};
            wchar_t p2[256] = {0};
            if (hEdit1) GetWindowTextW(hEdit1, p1, (int)_countof(p1));
            if (hEdit2) GetWindowTextW(hEdit2, p2, (int)_countof(p2));
            std::wstring ws1(p1), ws2(p2);
            if (ws1 == ws2) {
                AppendLog(L"[ChangePwd] New passwords match. Persisting configuration...");
                bool wrote = false;
                if (ws1.empty()) {
                    // empty means clear password
                    AppendLog(L"[ChangePwd] New password is empty: clearing configured password.");
                    wrote = SetConfiguredMd5(L"");
                } else {
                    // 计算 md5 并写入注册表
                    std::string utf8 = Utf16ToUtf8(ws1);
                    std::string md5 = Md5HexLower(utf8);
                    std::wstring md5w(md5.begin(), md5.end());
                    wrote = SetConfiguredMd5(md5w);
                }
                if (wrote) {
                    AppendLog(L"[ChangePwd] Configuration persisted successfully.");
                    MessageBoxW(hwnd, L"Password changed successfully", L"Change Password", MB_OK | MB_ICONINFORMATION);
                    ShowWindow(hwnd, SW_HIDE);
                    g_hChangePwdWnd = NULL;
                    DestroyWindow(hwnd);
                } else {
                    AppendLog(L"[ChangePwd] Failed to persist configuration.");
                    MessageBoxW(hwnd, L"Failed to persist new password", L"Change Password", MB_OK | MB_ICONERROR);
                }
            } else {
                AppendLog(L"[ChangePwd] New passwords do not match or empty.");
                MessageBoxW(hwnd, L"Passwords do not match or empty", L"Change Password", MB_OK | MB_ICONERROR);
            }
        }
        break;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        g_hChangePwdWnd = NULL;
        DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        g_hChangePwdWnd = NULL;
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

void ShowChangePasswordWindow(HINSTANCE hInst, HWND hParent) {
    if (g_hChangePwdWnd && IsWindow(g_hChangePwdWnd)) {
        ShowWindow(g_hChangePwdWnd, SW_SHOWNORMAL);
        SetForegroundWindow(g_hChangePwdWnd);
        return;
    }
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = ChangePwdWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SeewoKillerChangePwdWnd";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    RegisterClassW(&wc);
    g_hChangePwdWnd = CreateWindowW(L"SeewoKillerChangePwdWnd", L"Change Password",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 420, 160, hParent, NULL, hInst, NULL);
    ShowWindow(g_hChangePwdWnd, SW_SHOWNORMAL);
    UpdateWindow(g_hChangePwdWnd);
}

// 检查注册表中是否配置了密码（HKEY_CURRENT_USER\SOFTWARE\SeewoKiller\pwd_config, 值名: md5）
bool IsPasswordConfigured()
{
    // Treat configured md5 as present only when GetConfiguredMd5() returns a non-empty string
    std::wstring cfg = GetConfiguredMd5();
    bool present = !cfg.empty();
    AppendLog(std::wstring(L"[Password] IsPasswordConfigured -> ") + (present ? L"true" : L"false"));
    return present;
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
        AppendMenuW(g_hTrayMenu, MF_STRING, ID_TRAY_PASSWORD, L"Password");
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
        } else if (LOWORD(wParam) == ID_TRAY_PASSWORD) {
            AppendLog(L"[Password] Tray menu clicked. Checking configuration...");
            bool cfg = IsPasswordConfigured();
            if (cfg) {
                AppendLog(L"[Password] Configuration present. Showing password window.");
                ShowPasswordWindow((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE), hwnd);
            } else {
                AppendLog(L"[Password] No configuration found. Opening change-password window to allow setting a password.");
                // No existing password: open change-password window so user can set one
                ShowChangePasswordWindow((HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE), NULL);
            }
        } else if (LOWORD(wParam) == ID_TRAY_EXIT) {
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

    //RichEdit初始化
    LoadLibraryW(L"Msftedit.dll");  // RichEdit 4.1+


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