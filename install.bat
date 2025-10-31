@echo off
REM Automated installation script for dextr on Windows
REM Version 1.0

setlocal EnableDelayedExpansion

echo.
echo ======================================================
echo        dextr Installation Script v1.0
echo    Secure Archiving and Encryption System
echo          Created by orpheus497
echo ======================================================
echo.

REM Check for Python
echo [*] Checking Python installation...

set PYTHON_CMD=
set PYTHON_VERSION=

REM Try python3
where python3 >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=python3
    for /f "tokens=2" %%i in ('python3 --version 2^>^&1') do set PYTHON_VERSION=%%i
    goto :python_found
)

REM Try python
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=python
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
    goto :python_found
)

REM Try py launcher
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=py -3
    for /f "tokens=2" %%i in ('py -3 --version 2^>^&1') do set PYTHON_VERSION=%%i
    goto :python_found
)

REM No Python found
echo [X] Python not found
echo.
echo Please install Python 3.7 or higher:
echo   Download from: https://www.python.org/downloads/
echo   Make sure to check "Add Python to PATH" during installation
echo.
pause
exit /b 1

:python_found
echo [+] Found Python %PYTHON_VERSION%

REM Check Python version (simplified check)
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

if %MAJOR% LSS 3 (
    echo [X] Python 3.7+ is required (found Python %MAJOR%.%MINOR%)
    pause
    exit /b 1
)

if %MAJOR% EQU 3 if %MINOR% LSS 7 (
    echo [X] Python 3.7+ is required (found Python %MAJOR%.%MINOR%)
    pause
    exit /b 1
)

echo.

REM Check pip
echo [*] Checking pip installation...
%PYTHON_CMD% -m pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] pip is not installed
    echo.
    echo Please install pip:
    echo   %PYTHON_CMD% -m ensurepip --upgrade
    echo.
    pause
    exit /b 1
)
echo [+] pip is installed
echo.

REM Install dependencies
echo [*] Installing dependencies...
%PYTHON_CMD% -m pip install --user -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [X] Failed to install dependencies
    pause
    exit /b 1
)
echo [+] Dependencies installed successfully
echo.

REM Choose installation method
echo Choose installation method:
echo   1. System-wide installation (may require administrator)
echo   2. User installation (recommended)
echo   3. Development mode (for developers)
echo   4. Skip installation (just dependencies)
echo.
set /p CHOICE="Enter choice [1-4]: "

if "%CHOICE%"=="1" (
    echo [*] Installing dextr system-wide...
    %PYTHON_CMD% -m pip install .
    if !ERRORLEVEL! NEQ 0 (
        echo [X] System-wide installation failed
        echo Try user installation instead
        pause
        exit /b 1
    )
    echo [+] dextr installed system-wide
    set INSTALL_METHOD=system
) else if "%CHOICE%"=="2" (
    echo [*] Installing dextr for current user...
    %PYTHON_CMD% -m pip install --user .
    if !ERRORLEVEL! NEQ 0 (
        echo [X] User installation failed
        pause
        exit /b 1
    )
    echo [+] dextr installed for user
    set INSTALL_METHOD=user
) else if "%CHOICE%"=="3" (
    echo [*] Installing dextr in development mode...
    %PYTHON_CMD% -m pip install --user -e .
    if !ERRORLEVEL! NEQ 0 (
        echo [X] Development installation failed
        pause
        exit /b 1
    )
    echo [+] dextr installed in development mode
    set INSTALL_METHOD=dev
) else if "%CHOICE%"=="4" (
    echo [*] Skipping dextr installation
    set INSTALL_METHOD=none
) else (
    echo [X] Invalid choice
    pause
    exit /b 1
)
echo.

REM Test installation
echo [*] Testing installation...
if "%INSTALL_METHOD%"=="none" (
    run.bat --version >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo [+] Direct execution works: run.bat --version
    ) else (
        echo [X] Installation test failed
        pause
        exit /b 1
    )
) else (
    where dextr >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo [+] Command 'dextr' is available
        dextr --version >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            echo [+] dextr is working correctly
        ) else (
            echo [X] dextr command failed
            pause
            exit /b 1
        )
    ) else (
        echo [!] dextr command not found in PATH
        echo.
        echo You may need to add Python Scripts directory to PATH:
        echo   %APPDATA%\Python\PythonXY\Scripts
        echo.
        echo Restart your terminal after adding to PATH
        echo.
        echo Alternatively, you can use: run.bat [command]
    )
)
echo.

REM Show usage
echo.
echo ======================================================
echo           Installation Complete!
echo ======================================================
echo.

if "%INSTALL_METHOD%"=="none" (
    echo Usage: run.bat [command]
) else (
    echo Usage: dextr [command]
    echo    or: run.bat [command]
)

echo.
echo Quick Start:
echo   1. Generate a key:    dextr generate
echo   2. Encrypt files:     dextr encrypt -k key.dxk -i file.txt -o backup.dxe
echo   3. Decrypt archive:   dextr decrypt -k key.dxk -i backup.dxe -o restored
echo   4. View key info:     dextr info -k key.dxk
echo.
echo Documentation:
echo   - Full guide:         type README.md
echo   - Quick reference:    type USAGE.md
echo   - Help:               dextr --help
echo.
echo For detailed help, run: dextr help
echo.
pause
