@echo off
REM Windows batch launcher for dextr
REM Automatically finds Python installation

REM Try python3 first
where python3 >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python3 "%~dp0dextr.py" %*
    exit /b %ERRORLEVEL%
)

REM Try python
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python "%~dp0dextr.py" %*
    exit /b %ERRORLEVEL%
)

REM Try py launcher
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3 "%~dp0dextr.py" %*
    exit /b %ERRORLEVEL%
)

REM No Python found
echo Error: Python 3.7+ is required but not found in PATH 1>&2
exit /b 1
