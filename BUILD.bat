@echo off
echo ============================================================
echo   FlagHunt C# ^| .NET 8 Builder
echo ============================================================
echo.

where dotnet >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] .NET SDK not found.
    echo.
    echo Download the .NET 8 SDK from:
    echo   https://dotnet.microsoft.com/download/dotnet/8.0
    echo.
    pause
    exit /b 1
)

echo .NET SDK found:
dotnet --version
echo.

cd /d "%~dp0"
echo Building FlagHunt (Release / win-x64 / self-contained)...
echo.

dotnet publish -c Release -r win-x64 --self-contained true ^
    -p:PublishSingleFile=true ^
    -p:IncludeNativeLibrariesForSelfExtract=true ^
    -o "%~dp0dist" --nologo

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Build failed. See output above.
    pause
    exit /b 1
)

copy /Y "%~dp0dist\FlagHunt.exe" "%~dp0..\FlagHunt_CS.exe" >nul

echo.
echo ============================================================
echo   Done!  FlagHunt_CS.exe saved to your Desktop.
echo ============================================================
pause
