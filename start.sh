#!/bin/bash

# Cross-Platform Credential Extractor Launcher
# Supports: Windows (via WSL/Git Bash), Linux, macOS
# Equivalent to start.bat but for Unix-like systems

echo "========================================"
echo "CREDENTIAL EXTRACTOR AND REMOTE DESKTOP TOOL"
echo "========================================"
echo ""
echo "This will install dependencies and run ALL tools automatically"
echo ""

echo "WARNING: This tool extracts sensitive credentials from your system."
echo "Only use this tool on systems you own and have permission to access."
echo ""

echo "========================================"
echo "STEP 1: DETECTING PYTHON INSTALLATION"
echo "========================================"
echo ""

echo "Checking for Python installation..."

# Function to find best Python
find_python() {
    # Try Homebrew Python first (macOS, usually has SSL)
    if [ -f "/opt/homebrew/bin/python3" ]; then
        echo "/opt/homebrew/bin/python3"
        return 0
    elif [ -f "/usr/local/bin/python3" ]; then
        echo "/usr/local/bin/python3"
        return 0
    elif command -v python3 &> /dev/null; then
        echo "python3"
        return 0
    elif command -v python &> /dev/null; then
        echo "python"
        return 0
    fi
    return 1
}

PYTHON_CMD=$(find_python)

if [ -z "$PYTHON_CMD" ]; then
    echo "ERROR: No Python installation found!"
    echo "Please install Python 3.x from https://python.org"
    echo ""
    echo "Installation options:"
    echo "  macOS: brew install python3"
    echo "  Linux: sudo apt install python3 python3-pip  (Ubuntu/Debian)"
    echo "         sudo yum install python3 python3-pip    (CentOS/RHEL)"
    exit 1
fi

echo "Found Python: $($PYTHON_CMD --version)"
echo "Python path: $(which $PYTHON_CMD)"

echo ""
echo "========================================"
echo "STEP 2: DETECTING PLATFORM"
echo "========================================"
echo "Detecting platform..."

PLATFORM=$($PYTHON_CMD -c "import sys; print('win32' if sys.platform == 'win32' else 'linux' if sys.platform.startswith('linux') else 'darwin' if sys.platform == 'darwin' else 'unknown')" 2>/dev/null)

if [ "$PLATFORM" == "win32" ]; then
    echo "Platform detected: Windows"
    REQ_FILE="test/requirements_windows.txt"
elif [ "$PLATFORM" == "linux" ]; then
    echo "Platform detected: Linux"
    REQ_FILE="test/requirements_linux.txt"
elif [ "$PLATFORM" == "darwin" ]; then
    echo "Platform detected: macOS"
    REQ_FILE="test/requirements_macos.txt"
else
    echo "Platform unknown, using Linux requirements"
    REQ_FILE="test/requirements_linux.txt"
fi

echo ""
echo "========================================"
echo "STEP 3: INSTALLING DEPENDENCIES"
echo "========================================"
echo "Installing all required libraries..."
echo ""

# Function to install with fallbacks
install_with_fallback() {
    local package="$1"
    
    # Try standard install
    if $PYTHON_CMD -m pip install "$package" 2>/dev/null; then
        return 0
    fi
    
    # Try with trusted hosts
    if $PYTHON_CMD -m pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org "$package" 2>/dev/null; then
        return 0
    fi
    
    return 1
}

# Install platform-specific requirements
if [ -f "$REQ_FILE" ]; then
    echo "Installing platform-specific dependencies from $REQ_FILE..."
    if ! $PYTHON_CMD -m pip install -r "$REQ_FILE" 2>/dev/null; then
        echo "Trying with trusted hosts..."
        $PYTHON_CMD -m pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r "$REQ_FILE" 2>/dev/null || echo "Warning: Some dependencies may have failed"
    fi
else
    echo "Warning: Platform-specific requirements file not found, installing common dependencies..."
fi

echo ""
echo "Installing common cryptography libraries..."
install_with_fallback "pycryptodome" || echo "Warning: pycryptodome installation failed"
install_with_fallback "cryptography" || echo "Warning: cryptography installation failed"
install_with_fallback "pycryptodomex" || echo "Warning: pycryptodomex installation failed"

echo ""
echo "Installing system access libraries..."
if [ "$PLATFORM" == "win32" ]; then
    echo "Installing Windows-specific libraries..."
    install_with_fallback "pywin32" || echo "Warning: pywin32 installation failed"
    install_with_fallback "pywin32-ctypes" || echo "Warning: pywin32-ctypes installation failed"
else
    echo "Installing cross-platform libraries..."
    install_with_fallback "keyring" || echo "Warning: keyring installation failed"
    install_with_fallback "psutil" || echo "Warning: psutil installation failed"
fi

echo ""
echo "Installing network libraries..."
install_with_fallback "requests" || echo "Warning: requests installation failed"

echo ""
echo "Installing XML processing..."
install_with_fallback "lxml" || echo "Warning: lxml installation failed"

echo ""
echo "Installing additional utilities..."
install_with_fallback "colorama" || echo "Warning: colorama installation failed"
install_with_fallback "tqdm" || echo "Warning: tqdm installation failed"

if [ "$PLATFORM" == "win32" ]; then
    echo ""
    echo "Installing memory access libraries..."
    install_with_fallback "pymem" || echo "Warning: pymem installation failed"
fi

echo ""
echo "Installation complete!"
echo ""

echo "========================================"
echo "STEP 4: RUNNING ALL PYTHON TOOLS"
echo "========================================"
echo ""

# Check which scripts exist and run them
SCRIPTS=("ultimate.py" "aggressive.py" "remote.py" "run.py")
OUTPUT_FILES=("output1.txt" "output2.txt" "output3.txt" "output4.txt")
SCRIPT_NAMES=("Ultimate Credential Extractor" "Aggressive Credential Extractor" "Remote Desktop Configuration" "Advanced Credential Extractor")

SCRIPT_COUNT=0
for i in "${!SCRIPTS[@]}"; do
    SCRIPT="${SCRIPTS[$i]}"
    OUTPUT="${OUTPUT_FILES[$i]}"
    NAME="${SCRIPT_NAMES[$i]}"
    
    if [ -f "$SCRIPT" ]; then
        SCRIPT_COUNT=$((SCRIPT_COUNT + 1))
        echo "[$SCRIPT_COUNT] Running $NAME ($SCRIPT)..."
        echo "Output: $OUTPUT"
        $PYTHON_CMD "$SCRIPT" > "$OUTPUT" 2>&1
        if [ $? -eq 0 ]; then
            echo "$NAME completed successfully"
        else
            echo "$NAME completed with warnings (check $OUTPUT for details)"
        fi
        echo ""
    else
        echo "Skipping $SCRIPT (not found)"
        echo ""
    fi
done

echo "========================================"
echo "CREATING SUMMARY REPORT"
echo "========================================"
echo "Creating summary report..."

{
    echo "SUMMARY REPORT"
    echo "=============="
    echo "Generated: $(date)"
    echo "Python Command Used: $PYTHON_CMD"
    echo "Platform: $PLATFORM"
    echo ""
    echo "PYTHON TOOLS EXECUTED:"
    for i in "${!SCRIPTS[@]}"; do
        if [ -f "${SCRIPTS[$i]}" ]; then
            echo "- ${SCRIPTS[$i]} (${SCRIPT_NAMES[$i]})"
        fi
    done
    echo ""
    echo "OUTPUT FILES CREATED:"
    for i in "${!SCRIPTS[@]}"; do
        if [ -f "${SCRIPTS[$i]}" ] && [ -f "${OUTPUT_FILES[$i]}" ]; then
            echo "- ${OUTPUT_FILES[$i]} (${SCRIPT_NAMES[$i]} results)"
        fi
    done
    echo "- summary.txt (This summary report)"
    echo ""
    echo "IMPORTANT SECURITY NOTES:"
    echo "- All output files contain sensitive information"
    echo "- Store them securely and delete when no longer needed"
    echo "- Do not share these files with unauthorized parties"
    echo ""
} > summary.txt

echo "========================================"
echo "ALL TOOLS EXECUTION COMPLETED!"
echo "========================================"
echo ""
echo "PYTHON COMMAND USED: $PYTHON_CMD"
echo "PLATFORM: $PLATFORM"
echo ""
echo "OUTPUT FILES CREATED:"
for i in "${!SCRIPTS[@]}"; do
    if [ -f "${SCRIPTS[$i]}" ] && [ -f "${OUTPUT_FILES[$i]}" ]; then
        echo "- ${OUTPUT_FILES[$i]} (${SCRIPT_NAMES[$i]})"
    fi
done
echo "- summary.txt (Summary report)"
echo ""
echo "IMPORTANT SECURITY NOTES:"
echo "- All output files contain sensitive information"
echo "- Store them securely and delete when no longer needed"
echo "- Do not share these files with unauthorized parties"
echo ""

# Platform-specific remote desktop info (only for Windows)
if [ "$PLATFORM" == "win32" ]; then
    echo "========================================"
    echo "REMOTE DESKTOP CONNECTION INFO"
    echo "========================================"
    echo "To connect to this PC via Remote Desktop:"
    echo "1. Open Remote Desktop Connection (mstsc)"
    echo "2. Enter the IP address"
    echo "3. Enter your username and password"
    echo "4. Click Connect"
    echo ""
fi

echo "All tools have been executed successfully!"
echo ""
