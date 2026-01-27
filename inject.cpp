#include <windows.h>
#include <iostream>
#include <thread>
#include <string>
#include <tchar.h> 
#include <gdiplus.h>
#include <algorithm>
#include <vector>
#include <tlhelp32.h> 
#include <atomic>
#include <wincrypt.h>
#include <commctrl.h>
#include <winternl.h>
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")


#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_opengl3.h"


#include <gl/GL.h>

LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam
);


extern "C" NTSTATUS NTAPI RtlGetVersion(
    PRTL_OSVERSIONINFOW lpVersionInformation
);


// 新增：前向声明 Edit 子类过程（使用传统 SetWindowLongPtr / CallWindowProc 方式）
LRESULT CALLBACK EditSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

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


bool IsWindows10OrGreater()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
        return false;

    typedef NTSTATUS (NTAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);

    auto pRtlGetVersion =
        (RtlGetVersion_t)GetProcAddress(hNtdll, "RtlGetVersion");

    if (!pRtlGetVersion)
        return false;

    RTL_OSVERSIONINFOW osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    if (pRtlGetVersion(&osvi) != 0)
        return false;

    return osvi.dwMajorVersion >= 10;
}


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

int windowWidth  = 180;
int windowHeight = 250;

static HWND passwordWindowHWND = NULL;// 防止多次打开密码窗口

void ToggleMenuVisibility()
{
    if (g_mainWindow && g_buttonWindow)
    {
        RECT workArea{};
        SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0);

        int screenWidth  = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);
        
        int mainWindowWidth = windowWidth;
        int mainWindowHeight = windowHeight;
        int buttonWidth = 40;
        int buttonHeight = 60;
        int menuY = workArea.bottom - windowHeight; // 菜单展开时的 y 坐标

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
    case WM_ERASEBKGND:
    {
        HDC hdc = (HDC)wParam;

        RECT rc;
        GetClientRect(hwnd, &rc);

        HBRUSH hBrush = CreateSolidBrush(RGB(240, 240, 240));
        FillRect(hdc, &rc, hBrush);
        DeleteObject(hBrush);

        return 1; 
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
                if((passwordWindowHWND != NULL) && IsWindow(passwordWindowHWND)) {
                    SetForegroundWindow(passwordWindowHWND);
                    SetActiveWindow(passwordWindowHWND);
                    return 0;
                }
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

                            // 注册 Edit 子类：按 Enter 会触发父窗口的 OK 按钮处理
                            // 使用 SetWindowLongPtr + SetProp 保存原始 WndProc（避免对 comctl32 的链接依赖）
                            WNDPROC origProc = (WNDPROC)SetWindowLongPtr(hEdit, GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);
                            SetPropW(hEdit, L"OrigEditProc", (HANDLE)origProc);

                            // 将输入焦点设置到编辑控件
                            // 为了兼容性那就几种方法都试一次吧w
                            SetFocus(hEdit);
                            SetActiveWindow(hwnd);
                            SetForegroundWindow(hwnd);

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
                                    passwordWindowHWND = NULL;
                                    SendPipeCommand(L"WindowsVerified");
                                    DestroyWindow(hwnd);
                                }else{
                                    MessageBoxW(hwnd, L"Wrong password.", L"", MB_OK | MB_ICONERROR);
                                    SetWindowText(hEdit, L""); // 清空输入框
                                    // 重新设置焦点
                                    SetFocus(hEdit);
                                    SetActiveWindow(hwnd);
                                    SetForegroundWindow(hwnd);
                                }
                                // 虽然不太清楚，反正加个retuen 0又不吃亏w
                                return 0;
                            }
                            break;
                        case WM_CLOSE:
                            passwordWindowHWND = NULL;
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
                passwordWindowHWND = pwWnd;

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

LRESULT CALLBACK MainWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SETCURSOR:
        SetCursor(LoadCursor(NULL, IDC_ARROW));
        return TRUE;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}



void CreateSuperTopWindow()
{
    InitGDIPlus(); // 在窗口线程初始化GDI+

    WNDCLASS wc = {};
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.lpfnWndProc = MainWindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"MainWindowClass";
    RegisterClass(&wc);

    // 计算位置
    RECT workArea{};
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0);

    int screenWidth  = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);


    int posX = screenWidth - windowWidth;
    int posY = workArea.bottom - windowHeight;

    DWORD WindowBand = ZBID_UIACCESS;
    if (IsWindows10OrGreater())
        WindowBand = ZBID_ABOVELOCK_UX;

    g_mainWindow = CreateWindowInBand(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"MainWindowClass",
        L"",
        WS_POPUP | WS_VISIBLE,
        posX, posY,
        windowWidth, windowHeight,
        nullptr, nullptr,
        GetModuleHandle(nullptr),
        nullptr,
        WindowBand
    );

    if (!g_mainWindow)
        return;

        
    //窗口小窗
    WNDCLASS buttonWc = {0};
    buttonWc.style = CS_HREDRAW | CS_VREDRAW;
    buttonWc.lpfnWndProc = ButtonWindowProc;  
    buttonWc.hInstance = GetModuleHandle(NULL);
    buttonWc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    buttonWc.lpszClassName = L"ButtonWindowClass";
    RegisterClass(&buttonWc);

    int buttonWidth = 40;
    int buttonHeight = 60;
    int menuY = screenHeight - windowHeight;  // 和主窗口对齐

    g_buttonWindow = CreateWindowInBand(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"ButtonWindowClass",
        NULL,
        WS_VISIBLE | WS_POPUP,
        screenWidth - buttonWidth, menuY,
        buttonWidth, buttonHeight,
        NULL, NULL, GetModuleHandle(NULL), NULL,
        WindowBand
    );

    // 初始状态：菜单隐藏，只显示按钮
    isMenuVisible = false;

    //重置窗口状态，确保窗口与按钮位置正确
    ToggleMenuVisibility();
    ToggleMenuVisibility();
    
    
    //OpenGL Context 初始化
    HDC hdc = GetDC(g_mainWindow);

    PIXELFORMATDESCRIPTOR pfd = {};
    pfd.nSize      = sizeof(pfd);
    pfd.nVersion   = 1;
    pfd.dwFlags    = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cDepthBits = 24;
    pfd.iLayerType = PFD_MAIN_PLANE;

    int pf = ChoosePixelFormat(hdc, &pfd);
    SetPixelFormat(hdc, pf, &pfd);

    HGLRC glrc = wglCreateContext(hdc);
    wglMakeCurrent(hdc, glrc);

    //imgui初始化
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr; //禁止imgui.ini文件生成
    io.Fonts->Clear();
    io.Fonts->AddFontFromFileTTF(
        "C:\\Windows\\Fonts\\msyh.ttc",
        22.0f
    );

    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;

    ImGui::StyleColorsLight();

    ImGui_ImplWin32_Init(g_mainWindow);
    ImGui_ImplOpenGL3_Init("#version 130");

    //启动管道
    std::thread(ConnectToPipe).detach();

    // 消息与渲染循环
    MSG msg{};
    bool running = true;

    while (running)
    {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT)
            {
                running = false;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();


        //UI渲染

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);



        ImGui::Begin(
            "##MainPanel",
            nullptr,
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse
        );

        int MainButtonHeight = 40;
        // KillSeewo
        if (ImGui::Button("KillSeewo", ImVec2(-1, MainButtonHeight)))
            SendPipeCommand(L"KillSeewo");

        // RestartSeewo
        if (ImGui::Button("RestartSeewo", ImVec2(-1, MainButtonHeight)))
            SendPipeCommand(L"RestartSeewo");

        // PerfectFreeze
        if (ImGui::Button("PerfectFreeze", ImVec2(-1, MainButtonHeight)))
            SendPipeCommand(L"PerfectFreeze");

        // UndoFreeze
        if (ImGui::Button("UndoFreeze", ImVec2(-1, MainButtonHeight)))
            SendPipeCommand(L"UndoFreeze");

        // Checkbox（保持原语义）
        static bool disableTop = true;

        // 复选框
        if (ImGui::Checkbox("##disableTopmost", &disableTop))
        {
            wchar_t buf[64];
            swprintf_s(buf, L"CheckBox:%d", disableTop ? 1 : 0);
            SendPipeCommand(buf);
        }

        // 让文字紧挨着复选框右边
        ImGui::SameLine(0.0f, 10.0f);  
        ImGui::TextWrapped("Disable Seewo Topmost");
        ImGui::End();

        // 渲染
        ImGui::Render();

        glViewport(
            0, 0,
            (int)io.DisplaySize.x,
            (int)io.DisplaySize.y
        );

        glClearColor(0.08f, 0.08f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SwapBuffers(hdc);
    }

    // 资源清理
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    wglMakeCurrent(nullptr, nullptr);
    wglDeleteContext(glrc);
    ReleaseDC(g_mainWindow, hdc);

    ShutdownGDIPlus();
    
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

// 新增：Edit 子类过程，按 Enter 时向父窗口发送 OK 按钮点击消息（ID = 1）
LRESULT CALLBACK EditSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_KEYDOWN && wParam == VK_RETURN)
    {
        HWND hParent = GetParent(hWnd);
        if (hParent)
        {
            // 模拟按钮 ID=1 被点击：发送 WM_COMMAND (低字 = 控件ID, 高字 = BN_CLICKED)
            SendMessage(hParent, WM_COMMAND, MAKEWPARAM(1, BN_CLICKED), (LPARAM)hWnd);
        }
        return 0; 
    }

    // 在控件销毁时恢复原始过程并移除属性
    if (uMsg == WM_NCDESTROY)
    {
        WNDPROC orig = (WNDPROC)(ULONG_PTR)GetPropW(hWnd, L"OrigEditProc");
        if (orig) {
            SetWindowLongPtr(hWnd, GWLP_WNDPROC, (LONG_PTR)orig);
            RemovePropW(hWnd, L"OrigEditProc");
        }
        // 继续向原始过程传递 WM_NCDESTROY（如果 orig 存在）
        if (orig) return CallWindowProc(orig, hWnd, uMsg, wParam, lParam);
        return 0;
    }

    // 其它消息转发到原始过程
    WNDPROC orig = (WNDPROC)(ULONG_PTR)GetPropW(hWnd, L"OrigEditProc");
    if (orig) {
        return CallWindowProc(orig, hWnd, uMsg, wParam, lParam);
    }
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}