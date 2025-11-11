#!/bin/bash

# Unified Browser Data Extractor - Cross-Platform Launcher
# Supports: Windows, Linux, macOS

echo ""
echo "=================================================================================="
echo "                   UNIFIED BROWSER DATA EXTRACTOR"
echo "=================================================================================="
echo ""
echo "This tool combines logic from all analyzed password/cookie extraction projects"
echo "Supports: Chrome, Edge, Brave, Opera"
echo "Extracts: Passwords, Cookies, Autofill Data"
echo ""
echo "=================================================================================="
echo ""

# Detect platform
PLATFORM="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    echo "Platform detected: Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="darwin"
    echo "Platform detected: macOS"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    PLATFORM="win32"
    echo "Platform detected: Windows (Git Bash/Cygwin)"
else
    echo "Warning: Unknown platform, attempting to detect..."
    PLATFORM=$(python3 -c "import sys; print(sys.platform)" 2>/dev/null || echo "unknown")
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "ERROR: Python is not installed or not in PATH"
        echo "Please install Python 3.7+ and try again"
        echo "Download from: https://www.python.org/downloads/"
        exit 1
    else
        PYTHON_CMD=python
    fi
else
    PYTHON_CMD=python3
fi

echo "Python found: $($PYTHON_CMD --version)"
echo "Checking dependencies..."

# Determine requirements file based on platform
if [ "$PLATFORM" == "win32" ]; then
    REQ_FILE="requirements_windows.txt"
elif [ "$PLATFORM" == "darwin" ]; then
    REQ_FILE="requirements_macos.txt"
else
    REQ_FILE="requirements_linux.txt"
fi

# Check if required packages are installed
if [ "$PLATFORM" == "win32" ]; then
    $PYTHON_CMD -c "import Crypto, win32crypt, colorama, tqdm" 2>/dev/null
else
    $PYTHON_CMD -c "import Crypto, colorama, tqdm" 2>/dev/null
fi

if [ $? -ne 0 ]; then
    echo "Installing required dependencies..."
    echo "This may take a few minutes..."
    echo ""
    $PYTHON_CMD -m pip install -r "$REQ_FILE"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        echo "Please check your internet connection and try again"
        exit 1
    fi
    echo ""
    echo "Dependencies installed successfully!"
    echo ""
fi

echo "Starting extraction process..."
echo ""

# Run the main extraction script
$PYTHON_CMD main.py

echo ""
echo "=================================================================================="
echo "Extraction process completed!"
echo "Check the generated files in this directory:"
echo "- extracted_passwords.txt"
echo "- extracted_passwords.csv"
echo "- extracted_cookies.txt"
echo "- extracted_cookies.json"
echo "- extraction_summary.txt"
echo "- extraction.log"
echo "=================================================================================="
echo ""

# Open file manager (platform-specific)
if [ "$PLATFORM" == "darwin" ]; then
    open .
elif [ "$PLATFORM" == "linux" ]; then
    xdg-open . 2>/dev/null || nautilus . 2>/dev/null || dolphin . 2>/dev/null || echo "Please open the directory manually"
fi

