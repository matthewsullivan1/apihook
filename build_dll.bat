@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

echo VSINSTALLDIR=%VSINSTALLDIR%
echo VCToolsInstallDir=%VCToolsInstallDir%
echo PATH=%PATH%
echo INCLUDE=%INCLUDE%
echo LIB=%LIB%

if not exist dll mkdir dll
cl /LD /W4 /std:c++17 /Fedll\apihook.dll src\apihook.cpp src\syscall_stub.obj User32.lib Kernel32.lib

echo Compilation complete
