#!/bin/bash

# Unified Browser Data Extractor - Cross-Platform Launcher
# Supports: Windows, Linux, macOS
# Robust version that handles various edge cases

# Don't use set -e, we handle errors gracefully

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

# Function to find best Python installation
find_best_python() {
    local python_cmd=""
    
    # Try Homebrew Python first (macOS, usually has SSL)
    if [ -f "/opt/homebrew/bin/python3" ]; then
        python_cmd="/opt/homebrew/bin/python3"
    elif [ -f "/usr/local/bin/python3" ]; then
        python_cmd="/usr/local/bin/python3"
    # Try system Python
    elif command -v python3 &> /dev/null; then
        python_cmd="python3"
    elif command -v python &> /dev/null; then
        python_cmd="python"
    fi
    
    # Verify Python has SSL support
    if [ -n "$python_cmd" ]; then
        if $python_cmd -c "import ssl" 2>/dev/null; then
            echo "$python_cmd"
            return 0
        fi
    fi
    
    # If no SSL, still return the Python we found (will try workarounds)
    if [ -n "$python_cmd" ]; then
        echo "$python_cmd"
        return 0
    fi
    
    return 1
}

# Function to check if SSL is available
check_ssl() {
    local python_cmd="$1"
    $python_cmd -c "import ssl" 2>/dev/null
    return $?
}

# Function to install with fallback methods
install_dependencies() {
    local python_cmd="$1"
    local req_file="$2"
    local platform="$3"
    
    echo "Attempting to install dependencies..."
    
    # Method 1: Standard pip install
    if $python_cmd -m pip install -r "$req_file" 2>/dev/null; then
        echo "✓ Dependencies installed successfully using standard pip"
        return 0
    fi
    
    # Method 2: Try with trusted hosts (if SSL issue)
    echo "Standard installation failed, trying with trusted hosts..."
    if $python_cmd -m pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r "$req_file" 2>/dev/null; then
        echo "✓ Dependencies installed using trusted hosts method"
        return 0
    fi
    
    # Method 3: Install packages individually (more resilient)
    echo "Trying individual package installation..."
    local packages=""
    if [ "$platform" == "win32" ]; then
        packages="pycryptodome pywin32 requests colorama tqdm"
    elif [ "$platform" == "darwin" ]; then
        packages="pycryptodome pyobjc-framework-Security requests colorama tqdm"
    else
        packages="pycryptodome keyring requests colorama tqdm"
    fi
    
    local success=true
    for pkg in $packages; do
        if ! $python_cmd -m pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org "$pkg" 2>/dev/null; then
            echo "Warning: Failed to install $pkg, continuing..."
            success=false
        fi
    done
    
    if [ "$success" = true ]; then
        echo "✓ Dependencies installed individually"
        return 0
    fi
    
    # Method 4: Try without version constraints
    echo "Trying installation without version constraints..."
    if [ -f "$req_file" ]; then
        # Remove version constraints
        local temp_req=$(mktemp)
        sed 's/==.*$//' "$req_file" > "$temp_req"
        if $python_cmd -m pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r "$temp_req" 2>/dev/null; then
            rm "$temp_req"
            echo "✓ Dependencies installed without version constraints"
            return 0
        fi
        rm "$temp_req"
    fi
    
    return 1
}

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

# Find best Python installation
echo "Searching for Python installation..."
PYTHON_CMD=$(find_best_python)

if [ -z "$PYTHON_CMD" ]; then
    echo "ERROR: Python is not installed or not in PATH"
    echo ""
    echo "Installation options:"
    echo "  macOS: brew install python3"
    echo "  Linux: sudo apt install python3 python3-pip  (Ubuntu/Debian)"
    echo "         sudo yum install python3 python3-pip    (CentOS/RHEL)"
    echo "  Or download from: https://www.python.org/downloads/"
    exit 1
fi

echo "Python found: $($PYTHON_CMD --version)"
echo "Python path: $(which $PYTHON_CMD)"

# Check SSL support
if check_ssl "$PYTHON_CMD"; then
    echo "✓ SSL support: Available"
    SSL_AVAILABLE=true
else
    echo "⚠ SSL support: Not available (will use workarounds)"
    SSL_AVAILABLE=false
fi

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
MISSING_DEPS=false
if [ "$PLATFORM" == "win32" ]; then
    $PYTHON_CMD -c "import Crypto, win32crypt, colorama, tqdm" 2>/dev/null || MISSING_DEPS=true
else
    $PYTHON_CMD -c "import Crypto, colorama, tqdm" 2>/dev/null || MISSING_DEPS=true
fi

if [ "$MISSING_DEPS" = true ]; then
    echo "Some dependencies are missing. Installing..."
    echo ""
    
    if ! install_dependencies "$PYTHON_CMD" "$REQ_FILE" "$PLATFORM"; then
        echo ""
        echo "⚠ WARNING: Failed to install some dependencies automatically"
        echo "The script will attempt to run anyway, but some features may not work."
        echo ""
        echo "Manual installation options:"
        echo "  1. Install Python with SSL support:"
        if [ "$PLATFORM" == "darwin" ]; then
            echo "     brew install python3"
        elif [ "$PLATFORM" == "linux" ]; then
            echo "     sudo apt install python3-venv python3-pip"
        fi
        echo ""
        echo "  2. Or install dependencies manually:"
        echo "     $PYTHON_CMD -m pip install --trusted-host pypi.org pycryptodome colorama tqdm requests"
        echo ""
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo ""
        echo "✓ Dependencies installed successfully!"
        echo ""
    fi
else
    echo "✓ All required dependencies are already installed"
    echo ""
fi

echo "Starting extraction process..."
echo ""

# Run the main extraction script (continue even if it fails partially)
set +e  # Don't exit on error
$PYTHON_CMD main.py
EXIT_CODE=$?
set -e

echo ""
echo "=================================================================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo "Extraction process completed!"
else
    echo "Extraction process completed with warnings (exit code: $EXIT_CODE)"
fi
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
    open . 2>/dev/null || true
elif [ "$PLATFORM" == "linux" ]; then
    xdg-open . 2>/dev/null || nautilus . 2>/dev/null || dolphin . 2>/dev/null || true
fi

exit $EXIT_CODE

