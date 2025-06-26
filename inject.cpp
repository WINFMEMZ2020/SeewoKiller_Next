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

// 管道通信相关
HANDLE g_hPipe = NULL;
std::atomic<bool> g_pipeConnected(false);

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
        int mainWindowHeight = 240;
        int buttonWidth = 40;
        int buttonHeight = 60;
        int menuY = screenHeight - mainWindowHeight; // 菜单展开时的 y 坐标

        if (isMenuVisible)
        {
            // 隐藏菜单，将主窗口移到屏幕外
            SetWindowPos(g_mainWindow, NULL, screenWidth, screenHeight, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_HIDEWINDOW);
            // 确保展开按钮保持在屏幕边缘
            SetWindowPos(g_buttonWindow, NULL, screenWidth - buttonWidth, menuY, buttonWidth, buttonHeight, SWP_NOZORDER | SWP_SHOWWINDOW);
        }
        else
        {
            // 显示菜单，将主窗口移回屏幕内
            SetWindowPos(g_mainWindow, NULL, screenWidth - mainWindowWidth, menuY, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_SHOWWINDOW);
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
    SendPipeLog(L"[DrawPngIcon] PNG Path:");
    SendPipeLog(path);
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
        SendPipeLog(dbg);
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
        ToggleMenuVisibility(); // 切换菜单显示状态
        return 0;
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
        L"PerfectFreeze",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 50, 140, 30,
        hwnd, (HMENU)IDC_BUTTON2, GetModuleHandle(NULL), NULL
    );

    CreateWindow(
        L"BUTTON",
        L"UndoFreeze",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 90, 140, 30,
        hwnd, (HMENU)IDC_BUTTON3, GetModuleHandle(NULL), NULL
    );

    HWND hCheck = CreateWindow(
        L"BUTTON",
        L"Disable Seewo Topmost",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | BS_MULTILINE,
        10, 130, 140, 50, // 增加高度以显示多行文本
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

    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (!hUser32) return;

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

    auto CreateWindowInBand = (CreateWindowInBand_t)GetProcAddress(hUser32, "CreateWindowInBand");
    if (!CreateWindowInBand) return;

    int mainWindowWidth = 160; // 扩大两倍
    int mainWindowHeight = 240; // 扩大两倍
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
        std::thread windowThread(CreateSuperTopWindow);
        windowThread.detach();
    }
    return TRUE;
}