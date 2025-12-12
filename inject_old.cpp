#include <windows.h>
#include <iostream>
#include <thread>
#include <string>
#include <tchar.h> 
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")
#include <algorithm>
#include <vector>
#include <tlhelp32.h> 
#include <atomic>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

// 管道通信相关
HANDLE g_hPipe = NULL;
std::atomic<bool> g_pipeConnected(false);
wchar_t g_password_md5[64] = {0}; // 全局定义，供所有函数直接访问

// Global definition of CreateWindowInBand
typedef HWND(WINAPI* CreateWindowInBand_t)(
    DWORD dwExStyle,
    LPCWSTR lpClassName,
    LPCWSTR lpWindowName,
    DWORD dwStyle,
    int x,
    int y,
    int nWidth,
    int nHeight,
    HWND hWndParent,
    HMENU hMenu,
    HINSTANCE hInstance,
    LPVOID lpParam,
    DWORD dwBand
);

CreateWindowInBand_t CreateWindowInBand = nullptr;

void ConnectToPipe() {
    while (true) {
        g_hPipe = CreateFileW(
            L"\\\\.\\pipe\\SeewoKillerPipe",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            g_pipeConnected = true;
            break;
        }
        Sleep(1000);
    }
}

void SendPipeCommand(const wchar_t* cmd) {
    if (!g_pipeConnected) return;
    DWORD bytesWritten = 0;
    WriteFile(g_hPipe, cmd, (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)), &bytesWritten, NULL);
}

// 日志输出到管道
void SendPipeLog(const wchar_t* msg) {
    wchar_t buf[512];
    swprintf_s(buf, L"[LOG] %s", msg);
    SendPipeCommand(buf);
}

#define NTSTATUS LONG
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

enum ZBID
{
    ZBID_DEFAULT = 0,
    ZBID_DESKTOP = 1,
    ZBID_UIACCESS = 2,
    ZBID_IMMERSIVE_IHM = 3,
    ZBID_IMMERSIVE_NOTIFICATION = 4,
    ZBID_IMMERSIVE_APPCHROME = 5,
    ZBID_IMMERSIVE_MOGO = 6,
    ZBID_IMMERSIVE_EDGY = 7,
    ZBID_IMMERSIVE_INACTIVEMOBODY = 8,
    ZBID_IMMERSIVE_INACTIVEDOCK = 9,
    ZBID_IMMERSIVE_ACTIVEMOBODY = 10,
    ZBID_IMMERSIVE_ACTIVEDOCK = 11,
    ZBID_IMMERSIVE_BACKGROUND = 12,
    ZBID_IMMERSIVE_SEARCH = 13,
    ZBID_GENUINE_WINDOWS = 14,
    ZBID_IMMERSIVE_RESTRICTED = 15,
    ZBID_SYSTEM_TOOLS = 16,
    //Windows 10+
    ZBID_LOCK = 17,
    ZBID_ABOVELOCK_UX = 18,
};

int screenWidth = GetSystemMetrics(SM_CXSCREEN);
int screenHeight = GetSystemMetrics(SM_CYSCREEN);

HWND g_mainWindow = NULL;
HWND g_buttonWindow = NULL;

bool isMenuVisible = false; // 菜单是否可见

void ToggleMenuVisibility()
{
    if (g_mainWindow && g_buttonWindow)
    {
        int mainWindowWidth = 160;
        int mainWindowHeight = 270; // 与CreateSuperTopWindow保持一致
        int buttonWidth = 40;
        int buttonHeight = 60;
        int menuY = screenHeight - mainWindowHeight; // 菜单展开时的 y 坐标

        if (isMenuVisible)
        {
            // 隐藏菜单，将主窗口移到屏幕外
            SetWindowPos(g_mainWindow, NULL, screenWidth, screenHeight, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_HIDEWINDOW);
            // 确保展开按钮保持在屏幕边缘且Y坐标与主窗口一致
            SetWindowPos(g_buttonWindow, NULL, screenWidth - buttonWidth, menuY, buttonWidth, buttonHeight, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        else
        {
            // 显示菜单，将主窗口移回屏幕内
            SetWindowPos(g_mainWindow, NULL, screenWidth - mainWindowWidth, menuY, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_SHOWWINDOW);
            // 同步展开按钮位置到主窗口左侧
            SetWindowPos(g_buttonWindow, NULL, screenWidth - mainWindowWidth - buttonWidth, menuY, buttonWidth, buttonHeight, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        isMenuVisible = !isMenuVisible;
    }
}

ULONG_PTR g_gdiplusToken;

void InitGDIPlus()
{
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);
}

void ShutdownGDIPlus()
{
    Gdiplus::GdiplusShutdown(g_gdiplusToken);
}

void DrawPngIcon(HWND hwnd, HDC hdc)
{
    WCHAR path[MAX_PATH] = {0};
    // 获取DLL所在目录
    HMODULE hModule = NULL;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)DrawPngIcon, &hModule);
    GetModuleFileNameW(hModule, path, MAX_PATH);
    WCHAR* lastSlash = wcsrchr(path, L'\\');
    if (lastSlash) *(lastSlash + 1) = 0;
    wcscat_s(path, MAX_PATH, L"toolbox.png");
    // 输出调试信息到管道
    //SendPipeLog(L"[DrawPngIcon] PNG Path:");
    //SendPipeLog(path);
    Gdiplus::Image image(path);
    if (image.GetLastStatus() == Gdiplus::Ok)
    {
        int wndWidth = 40;
        int wndHeight = 60;
        int iconW = image.GetWidth();
        int iconH = image.GetHeight();
        float scale = std::min((float)wndWidth / iconW, (float)wndHeight / iconH);
        int drawW = (int)(iconW * scale);
        int drawH = (int)(iconH * scale);
        int x = (wndWidth - drawW) / 2;
        int y = (wndHeight - drawH) / 2;
        Gdiplus::Graphics graphics(hdc);
        graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
        Gdiplus::Status drawStatus = graphics.DrawImage(&image, x, y, drawW, drawH);
        // 输出绘制状态到管道
        WCHAR dbg[128];
        swprintf_s(dbg, L"[DrawPngIcon] DrawImage status: %d", (int)drawStatus);
        //SendPipeLog(dbg);
    }
    else {
        WCHAR dbg[128];
        swprintf_s(dbg, L"[DrawPngIcon] Image load failed, status: %d", (int)image.GetLastStatus());
        SendPipeLog(dbg);
    }
}

LRESULT CALLBACK ButtonWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        DrawPngIcon(hwnd, hdc);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN:
    {
        if (!isMenuVisible) {
            // 检查password文件是否存在
            WCHAR path[MAX_PATH] = {0};
            HMODULE hModule = NULL;
            GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)DrawPngIcon, &hModule);
            GetModuleFileNameW(hModule, path, MAX_PATH);
            WCHAR* lastSlash = wcsrchr(path, L'\\');
            if (lastSlash) *(lastSlash + 1) = 0;
            wcscat_s(path, MAX_PATH, L"password");
            DWORD attr = GetFileAttributesW(path);
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                // 存在password文件，读取内容并弹窗显示MD5
                HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    char buf[64] = {0};
                    DWORD bytesRead = 0;
                    ReadFile(hFile, buf, 32, &bytesRead, NULL);
                    CloseHandle(hFile);
                    // 转换为宽字节
                    MultiByteToWideChar(CP_UTF8, 0, buf, -1, g_password_md5, 64);
                    //MessageBoxW(hwnd, g_password_md5, L"Password MD5", MB_OK);
                }
                // 注册密码窗口类
                static bool pwClassRegistered = false;
                if (!pwClassRegistered) {
                    WNDCLASS pwc = {0};
                    pwc.style = CS_HREDRAW | CS_VREDRAW;
                    pwc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
                        static HWND hEdit = NULL;
                        switch (msg) {
                        case WM_CREATE:
                        {
                            // BY ChatGPT 
                            // 使用现代 Windows UI 字体：Segoe UI
                            HFONT hFont = CreateFontW(
                                20, 0, 0, 0,
                                FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET,
                                OUT_DEFAULT_PRECIS,
                                CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY,   // 抗锯齿
                                DEFAULT_PITCH | FF_DONTCARE,
                                L"Segoe UI"
                            );

                            // 创建标题
                            HWND hTitle = CreateWindowEx(0, L"STATIC", L"Password Required.",
                                WS_CHILD | WS_VISIBLE | SS_LEFT,
                                30, 10, 420, 25,
                                hwnd, NULL, GetModuleHandle(NULL), NULL);
                            SendMessage(hTitle, WM_SETFONT, (WPARAM)hFont, TRUE);

                            // 静态文本控件（无边框更美观）
                            HWND hText1 = CreateWindowEx(0, L"STATIC", L"Make sure this is you.",
                                WS_CHILD | WS_VISIBLE | SS_LEFT,
                                30, 45, 420, 25,
                                hwnd, NULL, GetModuleHandle(NULL), NULL);
                            SendMessage(hText1, WM_SETFONT, (WPARAM)hFont, TRUE);

                            HWND hText2 = CreateWindowEx(0, L"STATIC", L"Since a password is enabled, you will need to verify",
                                WS_CHILD | WS_VISIBLE | SS_LEFT,
                                30, 70, 420, 25,
                                hwnd, NULL, GetModuleHandle(NULL), NULL);
                            SendMessage(hText2, WM_SETFONT, (WPARAM)hFont, TRUE);

                            HWND hText3 = CreateWindowEx(0, L"STATIC", L"your identity before proceeding further.",
                                WS_CHILD | WS_VISIBLE | SS_LEFT,
                                30, 95, 420, 25,
                                hwnd, NULL, GetModuleHandle(NULL), NULL);
                            SendMessage(hText3, WM_SETFONT, (WPARAM)hFont, TRUE);

                            HWND hText4 = CreateWindowEx(0, L"STATIC", L"I use Arch btw.",
                                WS_CHILD | WS_VISIBLE | SS_LEFT,
                                30, 220, 420, 25,
                                hwnd, NULL, GetModuleHandle(NULL), NULL);
                            SendMessage(hText4, WM_SETFONT, (WPARAM)hFont, TRUE);

                            // 密码输入框
                            hEdit = CreateWindowEx(0, L"EDIT", NULL,
                                WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                                30, 130, 420, 28,
                                hwnd, NULL, GetModuleHandle(NULL), NULL);
                            SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

                            // 按钮
                            HWND hButton = CreateWindow(L"BUTTON", L"OK",
                                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                200, 180, 100, 32,
                                hwnd, (HMENU)1, GetModuleHandle(NULL), NULL);
                            SendMessage(hButton, WM_SETFONT, (WPARAM)hFont, TRUE);

                            return 0;
                        }

                        case WM_COMMAND:
                            if (LOWORD(wParam) == 1 && HIWORD(wParam) == BN_CLICKED) {
                                wchar_t pw[64] = {0};
                                GetWindowText(hEdit, pw, 63);
                                // 计算输入内容的MD5
                                char inputUtf8[64] = {0};
                                WideCharToMultiByte(CP_UTF8, 0, pw, -1, inputUtf8, 64, NULL, NULL);
                                BYTE md5[16] = {0};
                                DWORD cbHash = 16;
                                HCRYPTPROV hProv = 0;
                                HCRYPTHASH hHash = 0;
                                if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
                                    if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                                        CryptHashData(hHash, (BYTE*)inputUtf8, (DWORD)strlen(inputUtf8), 0);
                                        CryptGetHashParam(hHash, HP_HASHVAL, md5, &cbHash, 0);
                                        CryptDestroyHash(hHash);
                                    }
                                    CryptReleaseContext(hProv, 0);
                                }
                                // 转换为32位小写字符串
                                char md5str[33] = {0};
                                for (int i = 0; i < 16; ++i) {
                                    sprintf(md5str + i * 2, "%02x", md5[i]);
                                }
                                wchar_t md5w[64] = {0};
                                MultiByteToWideChar(CP_UTF8, 0, md5str, -1, md5w, 64);
                                if (wcscmp(md5w, g_password_md5) == 0) {
                                    //MessageBoxW(hwnd, L"true", L"验证结果", MB_OK);
                                    ToggleMenuVisibility();
                                    SendPipeCommand(L"WindowsVerified");
                                }else{
                                    MessageBoxW(hwnd, L"Wrong password.", L"", MB_OK | MB_ICONERROR);
                                    SetWindowText(hEdit, L""); // 清空输入框
                                }
                                DestroyWindow(hwnd);
                            }
                            break;
                        case WM_CLOSE:
                            DestroyWindow(hwnd);
                            return 0;
                        case WM_DESTROY:
                            return 0;
                        }
                        return DefWindowProc(hwnd, msg, wParam, lParam);
                    };
                    pwc.hInstance = GetModuleHandle(NULL);
                    pwc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
                    pwc.lpszClassName = L"PasswordWindowClass";
                    RegisterClass(&pwc);
                    pwClassRegistered = true;
                }
                int pwWidth = 600;
                int pwHeight = 300;
                int pwX = (screenWidth - pwWidth) / 2;
                int pwY = (screenHeight - pwHeight) / 2;
                HWND pwWnd = CreateWindowInBand(
                    WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                    L"PasswordWindowClass",
                    L"Verify your identity.",
                    WS_CAPTION | WS_BORDER | WS_SYSMENU | WS_VISIBLE,
                    pwX, pwY, pwWidth, pwHeight,
                    NULL, NULL, GetModuleHandle(NULL), NULL,
                    ZBID_UIACCESS
                );
                ShowWindow(pwWnd, SW_SHOW);
                UpdateWindow(pwWnd);
                return 0;
            }
        }
        // 不存在password文件或菜单已展开，直接切换菜单可见性
        ToggleMenuVisibility();
        return 0;
    }
    case WM_SETCURSOR:
        SetCursor(LoadCursor(NULL, IDC_ARROW)); // 设置为默认箭头光标
        return TRUE;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void UpdateButtonPosition()
{
    if (g_mainWindow && g_buttonWindow)
    {
        RECT mainRect;
        GetWindowRect(g_mainWindow, &mainRect);
        SetWindowPos(g_buttonWindow, NULL, mainRect.left - 40, mainRect.top, 40, 60, SWP_NOZORDER | SWP_SHOWWINDOW);
    }
}

#define IDC_CHECKBOX 1001
#define IDC_BUTTON1 2001
#define IDC_BUTTON2 2002
#define IDC_BUTTON3 2003
#define IDC_BUTTON4 2004 // RestartSeewo 按钮ID
void AddControlsToMainWindow(HWND hwnd)
{
    CreateWindow(
        L"BUTTON",
        L"KillSeewo",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 10, 140, 30,
        hwnd, (HMENU)IDC_BUTTON1, GetModuleHandle(NULL), NULL
    );

    CreateWindow(
        L"BUTTON",
        L"RestartSeewo",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 50, 140, 30,
        hwnd, (HMENU)IDC_BUTTON4, GetModuleHandle(NULL), NULL
    );

    CreateWindow(
        L"BUTTON",
        L"PerfectFreeze",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 90, 140, 30,
        hwnd, (HMENU)IDC_BUTTON2, GetModuleHandle(NULL), NULL
    );

    CreateWindow(
        L"BUTTON",
        L"UndoFreeze",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 130, 140, 30,
        hwnd, (HMENU)IDC_BUTTON3, GetModuleHandle(NULL), NULL
    );

    HWND hCheck = CreateWindow(
        L"BUTTON",
        L"Disable Seewo Topmost",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | BS_MULTILINE,
        10, 170, 140, 50, // 向下移动以适应新增按钮
        hwnd, (HMENU)IDC_CHECKBOX, GetModuleHandle(NULL), NULL
    );
    if (hCheck) {
        SendMessage(hCheck, BM_SETCHECK, BST_CHECKED, 0); // 默认勾选
    }
}

LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
        AddControlsToMainWindow(hwnd); // 添加控件
        // 启动管道连接线程
        std::thread(ConnectToPipe).detach();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CHECKBOX && HIWORD(wParam) == BN_CLICKED) {
            HWND hCheck = (HWND)lParam;
            LRESULT checked = SendMessage(hCheck, BM_GETCHECK, 0, 0);
            wchar_t msg[64];
            swprintf_s(msg, L"CheckBox:%d", checked == BST_CHECKED ? 1 : 0);
            SendPipeCommand(msg);
        } else if (LOWORD(wParam) == IDC_BUTTON1 && HIWORD(wParam) == BN_CLICKED) {
            SendPipeCommand(L"KillSeewo");
        } else if (LOWORD(wParam) == IDC_BUTTON4 && HIWORD(wParam) == BN_CLICKED) {
            // RestartSeewo 按钮事件
            SendPipeCommand(L"RestartSeewo");
        } else if (LOWORD(wParam) == IDC_BUTTON2 && HIWORD(wParam) == BN_CLICKED) {
            SendPipeCommand(L"PerfectFreeze");
        } else if (LOWORD(wParam) == IDC_BUTTON3 && HIWORD(wParam) == BN_CLICKED) {
            SendPipeCommand(L"UndoFreeze");
        }
        break;
    case WM_SETCURSOR:
        SetCursor(LoadCursor(NULL, IDC_ARROW)); // 设置为默认箭头光标
        return TRUE;
    case WM_MOVE:
        UpdateButtonPosition();
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void CreateSuperTopWindow()
{
    InitGDIPlus(); // 在窗口线程初始化GDI+
    // 获取屏幕工作区（不包含任务栏）
    RECT workArea = {0};
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0);
    int taskbarHeight = screenHeight - (workArea.bottom - workArea.top);

    WNDCLASS wc = {0};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"MainWindowClass";
    RegisterClass(&wc);

    WNDCLASS buttonWc = {0};
    buttonWc.style = CS_HREDRAW | CS_VREDRAW;
    buttonWc.lpfnWndProc = ButtonWindowProc;
    buttonWc.hInstance = GetModuleHandle(NULL);
    buttonWc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    buttonWc.lpszClassName = L"ButtonWindowClass";
    RegisterClass(&buttonWc);

    int mainWindowWidth = 160; // 扩大两倍
    int mainWindowHeight = 270; // 增加高度以容纳新按钮
    int buttonWidth = 40;
    int buttonHeight = 60;
    // 计算主窗口实际高度，避免遮挡任务栏
    int visibleMainWindowHeight = mainWindowHeight;
    if (taskbarHeight > 0 && mainWindowHeight > taskbarHeight) {
        visibleMainWindowHeight = mainWindowHeight - taskbarHeight;
    }
    int menuY = screenHeight - mainWindowHeight; // 保持原有y坐标

    g_mainWindow = CreateWindowInBand(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"MainWindowClass",
        NULL,
        WS_VISIBLE | WS_POPUP,
        screenWidth, menuY, mainWindowWidth, visibleMainWindowHeight, // 高度裁剪
        NULL, NULL, GetModuleHandle(NULL), NULL,
        ZBID_UIACCESS
    );

    g_buttonWindow = CreateWindowInBand(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"ButtonWindowClass",
        NULL,
        WS_VISIBLE | WS_POPUP,
        screenWidth - buttonWidth, menuY, buttonWidth, buttonHeight, // 展开按钮位置正确
        NULL, NULL, GetModuleHandle(NULL), NULL,
        ZBID_UIACCESS
    );

    if (g_mainWindow && g_buttonWindow)
    {
        // 强制重绘，确保首次显示时就绘制
        InvalidateRect(g_buttonWindow, NULL, TRUE);
        UpdateWindow(g_buttonWindow);
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    ShutdownGDIPlus(); // 在窗口线程销毁GDI+
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        HMODULE hUser32 = LoadLibraryW(L"user32.dll");
        if (!hUser32) return FALSE;

        CreateWindowInBand = (CreateWindowInBand_t)GetProcAddress(hUser32, "CreateWindowInBand");
        if (!CreateWindowInBand) return FALSE;

        std::thread windowThread(CreateSuperTopWindow);
        windowThread.detach();
    }
    return TRUE;
}