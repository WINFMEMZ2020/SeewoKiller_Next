#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>

// 管道通信相关
HANDLE g_hPipe = NULL;
std::atomic<bool> g_exit(false);
std::atomic<bool> RunTopMost(true);

void PipeClientThread() {
    int loopCount = 0;
    DWORD tid = GetCurrentThreadId();
    while (!g_exit) {
        std::wcout << L"[PipeClient][TID:" << tid << L"] Try connect..." << std::endl;
        g_hPipe = CreateFileW(
            L"\\\\.\\pipe\\DisableTopMostPipe",
            GENERIC_READ, // 只读即可，避免权限拒绝
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[PipeClient][TID:" << tid << L"] Failed to connect pipe. Error: " << GetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        std::wcout << L"[PipeClient][TID:" << tid << L"] Connected to pipe." << std::endl;
        wchar_t buffer[512];
        DWORD bytesRead = 0;
        int msgCount = 0;
        while (!g_exit) {
            ++loopCount;
            auto t1 = std::chrono::system_clock::now();
            std::time_t t1t = std::chrono::system_clock::to_time_t(t1);
            std::wcout << L"[PipeClient][TID:" << tid << L"][Loop:" << loopCount << L"] Waiting for message... (" << std::put_time(std::localtime(&t1t), L"%F %T") << L")" << std::endl;
            BOOL ok = ReadFile(g_hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL);
            auto t2 = std::chrono::system_clock::now();
            std::time_t t2t = std::chrono::system_clock::to_time_t(t2);
            std::wcout << L"[PipeClient][TID:" << tid << L"][Loop:" << loopCount << L"] ReadFile returned: " << ok << L", bytesRead: " << bytesRead << L" (" << std::put_time(std::localtime(&t2t), L"%F %T") << L")" << std::endl;
            if (!ok || bytesRead == 0) {
                DWORD err = GetLastError();
                std::wcerr << L"[PipeClient][TID:" << tid << L"][Loop:" << loopCount << L"] ReadFile failed or pipe closed. Error: " << err << std::endl;
                break;
            }
            size_t wcharCount = bytesRead / sizeof(wchar_t);
            buffer[wcharCount] = 0;
            std::wstring msg(buffer);
            ++msgCount;
            std::wcout << L"[PipeClient][TID:" << tid << L"][Loop:" << loopCount << L"] [PipeMsg] (len=" << msg.length() << L") " << msg << std::endl;
            const std::wstring prefix = L"[Target:DisableTopMost]";
            if (msg.find(prefix) == 0) {
                size_t pos = msg.find(L"CheckBox:");
                if (pos != std::wstring::npos) {
                    wchar_t val = msg[pos + 9];
                    std::wcout << L"[PipeClient][TID:" << tid << L"][Loop:" << loopCount << L"] CheckBox value: " << val << std::endl;
                    if (val == L'1') {
                        if (!RunTopMost) std::wcout << L"[状态切换] RunTopMost = true" << std::endl;
                        RunTopMost = true;
                    } else if (val == L'0') {
                        if (RunTopMost) std::wcout << L"[状态切换] RunTopMost = false" << std::endl;
                        RunTopMost = false;
                    }
                }
            }
            ZeroMemory(buffer, sizeof(buffer));
        }
        std::wcout << L"[PipeClient][TID:" << tid << L"] Disconnected from pipe." << std::endl;
        CloseHandle(g_hPipe);
        g_hPipe = NULL;
    }
}

// 获取指定进程名的进程 ID 列表
std::vector<DWORD> getProcessIdsByName(const std::wstring& name) {
    std::vector<DWORD> pids;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (std::wstring(pe.szExeFile) == name) {
                    pids.push_back(pe.th32ProcessID);
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return pids;
}

// 用于枚举窗口的结构体
struct EnumWindowsParam {
    std::vector<HWND>* windows;
    DWORD pid;
};

// 枚举窗口的回调函数
static BOOL CALLBACK enumWindowsCallback(HWND hwnd, LPARAM lParam) {
    EnumWindowsParam* param = (EnumWindowsParam*)lParam;
    DWORD windowPid;
    GetWindowThreadProcessId(hwnd, &windowPid);
    if (windowPid == param->pid) {
        param->windows->push_back(hwnd);
    }
    return TRUE;
}

// 根据进程 ID 获取窗口句柄列表
std::vector<HWND> getWindowsByProcessId(DWORD pid) {
    std::vector<HWND> windows;
    EnumWindowsParam param = { &windows, pid };
    EnumWindows(enumWindowsCallback, (LPARAM)&param);  // 修正为 &param
    return windows;
}

// 检查程序是否以管理员权限运行
bool isRunningAsAdmin() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }
    TOKEN_ELEVATION elevation;
    DWORD dwSize;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        CloseHandle(hToken);
        return elevation.TokenIsElevated != 0;
    }
    CloseHandle(hToken);
    return false;
}

// 以管理员权限提升程序
void elevateProgram() {
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    sei.lpFile = exePath;
    sei.lpParameters = L"elevated";
    sei.nShow = SW_HIDE;
    if (ShellExecuteExW(&sei)) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
        ExitProcess(0);
    } else {
        std::wcerr << L"Elevation failed." << std::endl;
    }
}

// 主函数
int wmain(int argc, WCHAR* argv[]) {
    bool isElevated = false;
    if (argc > 1 && std::wstring(argv[1]) == L"elevated") {
        isElevated = true;
    }
    if (!isRunningAsAdmin() && !isElevated) {
        elevateProgram();
        return 0;
    }

    // 设置程序优先级为高优先级
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    int counter = 0;
    std::vector<DWORD> pids;
    // 启动管道连接线程，等待连接成功后再启动监听线程
    std::thread pipeClientThread(PipeClientThread);
    while (true) {
        // 每 0.5 秒更新一次 PID 列表（10 * 50ms = 500ms）
        if (counter % 10 == 0) {
            pids = getProcessIdsByName(L"SeewoServiceAssistant.exe");
        }

        bool success = true;
        if (RunTopMost) { // 新增：仅当RunTopMost为true时执行
            for (DWORD pid : pids) {
                std::vector<HWND> windows = getWindowsByProcessId(pid);
                for (HWND hwnd : windows) {
                    if (!SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)) {
                        std::wcerr << L"Failed to set window position for window " << hwnd << L". Error: " << GetLastError() << std::endl;
                        success = false;
                    }
                }
            }
            if (success) {
                //std::wcout << L"Successfully disabled topmost for all windows." << std::endl;
            }
        } else {
            std::wcout << L"TopMost功能已暂停。" << std::endl;
        }
        counter++;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));  // 每 50ms 检查一次
    }
    // 退出前清理
    g_exit = true;
    if (pipeClientThread.joinable()) pipeClientThread.join();
    if (g_hPipe) CloseHandle(g_hPipe);
    return 0;
}