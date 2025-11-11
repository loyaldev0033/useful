@echo off
title Unified Browser Data Extractor
color 0A

echo.
echo ================================================================================
echo                    UNIFIED BROWSER DATA EXTRACTOR
echo ================================================================================
echo.
echo This tool combines logic from all analyzed password/cookie extraction projects
echo Supports: Chrome, Edge, Brave, Opera
echo Extracts: Passwords, Cookies, Autofill Data
echo.
echo ================================================================================
echo.

REM Check if Python is installed
REM Try python3 first
python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python3
    python3 --version
    echo Found Python3 - using python3 command
    goto :check_deps
)

REM Try python
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
    python --version
    echo Found Python - using python command
    goto :check_deps
)

REM Try py (Windows Python Launcher)
py --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    py --version
    echo Found Python Launcher - using py command
    goto :check_deps
)

REM No Python found
echo ERROR: Python is not installed or not in PATH
echo Please install Python 3.7+ and try again
echo Download from: https://www.python.org/downloads/
pause
exit /b 1

:check_deps
echo Python found. Checking dependencies...

REM Detect platform and use appropriate requirements file
echo Detecting platform...
%PYTHON_CMD% -c "import sys; print('win32' if sys.platform == 'win32' else 'linux' if sys.platform.startswith('linux') else 'darwin' if sys.platform == 'darwin' else 'unknown')" > platform.txt
set /p PLATFORM=<platform.txt
del platform.txt

if "%PLATFORM%"=="win32" (
    set REQ_FILE=requirements_windows.txt
    echo Platform detected: Windows
) else if "%PLATFORM%"=="linux" (
    set REQ_FILE=requirements_linux.txt
    echo Platform detected: Linux
) else if "%PLATFORM%"=="darwin" (
    set REQ_FILE=requirements_macos.txt
    echo Platform detected: macOS
) else (
    set REQ_FILE=requirements_windows.txt
    echo Platform unknown, using Windows requirements
)

REM Check if required packages are installed
if "%PLATFORM%"=="win32" (
    %PYTHON_CMD% -c "import Crypto, win32crypt, colorama, tqdm" >nul 2>&1
) else (
    %PYTHON_CMD% -c "import Crypto, colorama, tqdm" >nul 2>&1
)

if errorlevel 1 (
    echo Installing required dependencies...
    echo This may take a few minutes...
    echo.
    %PYTHON_CMD% -m pip install -r %REQ_FILE%
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        echo Please check your internet connection and try again
        pause
        exit /b 1
    )
    echo.
    echo Dependencies installed successfully!
    echo.
)

echo Starting extraction process...
echo.

REM Run the main extraction script automatically
%PYTHON_CMD% main.py

echo.
echo ================================================================================
echo Extraction process completed!
echo Check the generated files in this directory:
echo - extracted_passwords.txt
echo - extracted_passwords.csv  
echo - extracted_cookies.txt
echo - extracted_cookies.json
echo - extraction_summary.txt
echo - extraction.log
echo ================================================================================
echo.

REM Automatically open the output directory
explorer .
