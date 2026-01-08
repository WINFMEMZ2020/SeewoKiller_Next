chcp 65001
echo off
cls
echo Restarting explorer.exe...
taskkill /f /im explorer.exe
start explorer.exe

echo Killing KillerService.exe...
taskkill /f /im KillerService.exe
echo Killing DisableSeewoTopMost.exe...
taskkill /f /im DisableSeewoTopMost.exe


echo Compiling injector.exe...
g++ -o injector.exe injector.cpp -luser32 -lkernel32 -static
echo Compiling inject.dll...
REM g++ -shared -o mainWindow.dll inject.cpp -lgdiplus -static -municode -lgdi32
g++ -shared -o mainWindow.dll inject.cpp -Iimgui -Iimgui/backends imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp imgui/backends/imgui_impl_win32.cpp imgui/backends/imgui_impl_opengl3.cpp -lgdi32 -luser32 -lopengl32 -static -municode -lgdiplus -ldwmapi
echo Compiling KillerService.exe...
g++ -static -municode -mwindows -o KillerService.exe KillerService.cpp -lpsapi -lshell32 -ladvapi32 -lgdi32 -lwtsapi32 -luserenv
REM g++ -static -municode -mwindows -o KillerService.exe KillerService.cpp -lpsapi -lshell32 -ladvapi32 -lgdi32
REM g++ -static -static-libgcc -static-libstdc++ -o KillerService.exe KillerService.cpp -luser32 -ladvapi32 -lshell32 -lpsapi -municode
REM echo Compiling DisableSeewoTopMost.cpp...
REM g++ -o DisableSeewoTopMost DisableSeewoTopMost.cpp -luser32 -lkernel32 -lws2_32 -static -municode 
echo Compiling launcher.exe...
REM g++ -o launcher.exe launcher.cpp -static -municode -lshell32
g++ -o launcher.exe launcher.cpp -static -lpsapi -ladvapi32 -lshell32 -lole32 -lshlwapi -O2 -Wl,--subsystem,windows -municode
explorer .
REM start injector.exe
REM start KillerService.exe
REM start DisableSeewoTopMost.exe
REM pause