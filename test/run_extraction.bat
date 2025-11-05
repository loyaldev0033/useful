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
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Python found. Checking dependencies...

REM Check if required packages are installed
python -c "import Crypto, win32crypt, colorama, tqdm" >nul 2>&1
if errorlevel 1 (
    echo Installing required dependencies...
    echo This may take a few minutes...
    echo.
    pip install -r requirements.txt
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
python main.py

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
