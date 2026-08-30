@echo off
setlocal
cd /d "%~dp0"

echo KOTOR KPatch Adapter - Build
echo.

set "CSC="
if exist "%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if exist "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if not defined CSC (
  echo ERROR: Could not find the .NET Framework C# compiler csc.exe.
  echo Install/enable .NET Framework 4.x or build the project in Visual Studio.
  pause
  exit /b 1
)

echo Compiler: %CSC%
echo Building 32-bit Windows GUI executable...

"%CSC%" /nologo /target:winexe /platform:x86 /optimize+ /out:"KotorKPatchAdapter.exe" ^
 /reference:System.dll ^
 /reference:System.Core.dll ^
 /reference:System.Drawing.dll ^
 /reference:System.Windows.Forms.dll ^
 /reference:System.IO.Compression.dll ^
 /reference:System.IO.Compression.FileSystem.dll ^
 "src\Program.cs" "src\AdapterCore.cs" "src\SqliteNative.cs" "src\MainForm.cs"

if errorlevel 1 (
  echo.
  echo BUILD FAILED.
  pause
  exit /b 1
)

echo.
echo BUILD COMPLETE:
echo %CD%\KotorKPatchAdapter.exe
echo.
pause
