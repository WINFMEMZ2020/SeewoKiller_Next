# SeewoKiller_Next
基于C++的希沃软件对抗工具，包括杀进程，取消置顶，挂起进程等功能。
<br><br>

# AI生成代码说明
由于  <del>作者太懒</del>  技术力不够高，本项目约30%代码使用AI编写。<br>
如launcher，CheckProcess等简单的程序使用AI生成并经过超过6个月的稳定性测试，表现为各个组件稳定性良好。

# 编译方式
在编译前，请确保已安装gcc与g++并恰当地配置了环境变量。<br>
作者使用MSYS2安装gcc组件。
在g++安装完成后，请打开PowerShell或者命令提示符，若是有以下输出则为安装成功。
```powershell
PS C:\Users\udm> g++ --version
g++.exe (Rev8, Built by MSYS2 project) 15.2.0
Copyright (C) 2025 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```
请在开始菜单右键，选择"终端管理员"，使用管理员权限来运行终端。并且导航到源代码所在目录。<br>
![PowerShell示例](/pic/07.png)<br>
使用此命令来构建程序：
```powershell
 .\make.bat
 ```
警告：**此操作将会重启`explorer.exe`，请谨慎操作。**<br> 
如果顺利，编译操作将继续运行直至完成。若是未观察到有报错的输出则为编译成功，这是一个编译成功的示例输出：
```powershell
Restarting explorer.exe...
SUCCESS: The process "explorer.exe" with PID 16124 has been terminated.
Killing KillerService.exe...
SUCCESS: The process "KillerService.exe" with PID 15676 has been terminated.
Killing DisableSeewoTopMost.exe...
ERROR: The process "DisableSeewoTopMost.exe" not found.
Compiling injector.exe...
Compiling inject.dll...
Compiling KillerService.exe...
Compiling launcher.exe...
PS D:\prj\SeewoKiller_Next>
```
构建脚本将自动打开编译后的可执行文件的目录，双击`launcher.exe`即可启动SeewoKiller。

# 如何使用？
![主界面](/pic/00.png)<br>
在编译完成后打开launcher.exe，右下角会出现工具箱图标，点击即可展开。<br>
此处包含该程序的全部功能。<br>
## 功能说明
**KillSeewo：** 点击即可启动，将会以每1000ms一次的速度杀死**希沃管家**的进程。
**RestartSeewo：** 点击后将终止KillSeewo的线程（如果存在），然后重新启动希沃管家。<br>
**PerfectFreeze：** 点击后将会挂起希沃管家的所有进程。由于Windows的进程挂起具有挂起计数，因此多次挂起希沃管家后，需要多次使用UndoFreeze。<br>
**UndoFreeze：** 点击后将恢复所有希沃管家的进程。<br>
Disable Seewo Topmost：默认勾选，启用后会将希沃管家的窗口按照每100ms一次的速度取消其置顶属性。如果存在希沃管家的锁屏，该功能将很有用。

## 托盘图标说明
KillerService.exe为常驻进程，为方便管理，它将创建托盘图标。<br>
![托盘图标](/pic/01.png)<br>
右键该托盘图标，将会显示两个选项。<br>
![托盘图标](/pic/02.png)<br>
**ShowLog：** 这将弹出日志窗口，在此处可以查看SeewoKiller的日志。
![托盘图标](/pic/03.png)<br>
**Exit：** 这将完全退出SeewoKiller，**此操作将会重启`explorer.exe`** ，谨慎操作。

## 密码功能说明
您可以为主窗口的弹出设置密码，但请注意，此密码原理和破解方式极其简单，因为设计的目的是为了防误触。<br>
要启用密码，只需要在程序同目录下创建`password`文件即可。<br>
``` powershell
PS D:\prj\SeewoKiller_Next> ls

    Directory: D:\prj\SeewoKiller_Next

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d----            2026/1/8     9:20                imgui
d----           2026/1/17    11:34                pic
-a---           2026/1/17    11:02             31 .gitignore
-a---           2025/9/14    22:27           3331 CheckProcess.cpp
-a---           2025/9/14    22:28        2915685 CheckProcess.exe
-a---           2025/6/26    10:44           8029 DisableSeewoTopMost.cpp
-a---           2025/6/26    10:44        3032332 DisableSeewoTopMost.exe
-a---           2025/6/26    10:44           6770 empty.cpp
-a---            2026/1/8     9:41            101 imgui.ini
-a---            2026/1/8    18:00          27261 inject.cpp
-a---           2025/6/26    10:44           2354 injector.cpp
-a---            2026/1/8    18:00        2955310 injector.exe
-a---            2026/1/8     9:16          45295 KillerService.cpp
-a---            2026/1/8    18:00        3404792 KillerService.exe
-a---           2025/6/26    10:44          10736 launcher.cpp
-a---            2026/1/8    18:00        2969813 launcher.exe
-a---           2026/1/17    11:02           1235 LICENSE
-a---            2026/1/8    18:00        4745850 mainWindow.dll
-a---            2026/1/7    13:55           1666 make.bat
-a---            2025/8/3    18:28             32 password
-a---           2026/1/17    11:38           1749 README.md
-a---           2025/9/12    21:02           1054 SendCommand.cpp
-a---           2025/9/12    21:03        2910530 SendCommand.exe
-a---            2026/1/8     9:24           1235 THIRD_PARTY_LICENSES.txt
-a---           2025/6/26    10:44           8060 toolbox.png
```
<br>

在`password`文件内，应该填入密码的MD5-32哈希值。如下图所示：<br>
![Notepad++窗口](/pic/04.png)<br>
请注意：**这个文件应该使用UTF-8编码且不能包含换行。**<br>
再次点击工具箱图标就能看到该界面：
![密码窗口](/pic/05.png)<br>
输入密码，并且按下"OK"按钮或回车键来确认。<br>
若要删除密码，只需要删除`password`文件，不需要重启SeewoKiller。<br>

# 原理
本程序使用DLL注入到`explorer.exe`，并且使用未公开函数`CreateWindowInBand()`来创建`ZBID_UIACCESS`或者`ZBID_ABOVELOCK_UX`层级的窗口。使用命名管道实现`mainWindow.dll`与`KillerService.exe`之间的通信。<br>
在PerfectFreeze和UndoFreeze功能上，使用未公开函数`NtSuspendProcess()`与`NtResumeProcess()`。<br>
`KillerService.exe`将会使用SYSTEM身份运行，来保证权限足够。

# Omake
本仓库还附带额外程序以满足不同需求：<br>
`launcher.cpp`：程序的启动器。<br>
`CheckProcess.cpp`：此程序将检查SeewoKiller的运行状态，如果没有，则启动`launcher.exe`。<br>
`DisableSeewoTopMost.cpp`：该功能已合并至KillerService.exe。但要编译也不是不行。<br>
`empty.cpp`：没有任何功能，附赠的SYSTEM权限提权模板（？）<br>
`SendCommand.cpp`：向SeewoKiller的通信管道发送字符串消息。如果希沃管家存在定时关机行为，或者需要定时让SeewoKiller执行某些操作而不通过GUI，此程序将很好用。配合计划任务程序实现的定时冻结希沃管家的使用例：<br>
![AutoPerfectFreeze计划任务程序](/pic/06.png)<br>

## SendCommand.exe 使用用法：
```batch
SendCommand.exe command
```
本程序只接受一个参数，这个参数可以是：
| 参数 | 对应功能 |
| :--- | :--- |
| `KillSeewo` | 启用 KillSeewo 线程 |
| `RestartSeewo` | 重启希沃管家 |
| `PerfectFreeze` | 挂起希沃管家的所有进程 |
| `UndoFreeze` | 恢复希沃管家的所有进程 |
| `CheckBox:0` | 禁用 Disable Seewo Topmost |
| `CheckBox:1` | 启用 Disable Seewo Topmost |
| `WindowsVerified` | 记录窗口已验证，没啥用的功能 |

实际上这就是在主窗口点击功能按钮后像管道内发送的字符串消息。

## 本程序定义的希沃管家进程
在代码中如下定义希沃管家的进程：
```cpp
static const wchar_t* targets[] = {
    L"SeewoServiceAssistant.exe",
    L"SeewoCore.exe",
    L"media_capture.exe",
    L"rtcRemoteDesktop.exe",
    L"screenCapture.exe",
    L"SeewoAbility.exe"
};
```
# 第三方开源代码使用声明
此项目使用了第三方代码。<br>
- `Dear ImGui`：主窗口UI库。<br>
本仓库的使用遵循该仓库的MIT协议。<br>

若要查看完整的开源协议声明，请查看`THIRD_PARTY_LICENSES.txt`<br>