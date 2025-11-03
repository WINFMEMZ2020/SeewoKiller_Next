// SendCommand.cpp
#include <windows.h>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcout << L"Usage: SendCommand <command>" << std::endl;
        return 1;
    }

    const std::wstring command = argv[1];

    HANDLE hPipe = CreateFileW(
        L"\\\\.\\pipe\\SeewoKillerPipe",
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcout << L"Failed to connect to pipe. Error: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD bytesWritten;
    BOOL success = WriteFile(
        hPipe,
        command.c_str(),
        (command.size() + 1) * sizeof(wchar_t),
        &bytesWritten,
        NULL);

    if (!success) {
        std::wcout << L"WriteFile failed. Error: " << GetLastError() << std::endl;
    } else {
        std::wcout << L"Command sent: " << command << std::endl;
    }

    CloseHandle(hPipe);
    return 0;
}