# Installation Guide - Universal Compatibility

This project is designed to run in **any situation**, even with limited Python installations or missing dependencies.

## Quick Start

### macOS/Linux:
```bash
cd test
chmod +x run_extraction.sh
./run_extraction.sh
```

### Windows:
```bash
cd test
run_extraction.bat
```

## Features for Maximum Compatibility

### 1. **Automatic Python Detection**
- Finds the best Python installation available
- Prefers Homebrew Python (macOS) which has SSL support
- Falls back to system Python if needed

### 2. **SSL Workarounds**
If your Python doesn't have SSL support, the script will:
- Try installing with `--trusted-host` flags
- Install packages individually
- Try without version constraints
- Continue even if some packages fail

### 3. **Graceful Degradation**
- Script continues even if optional dependencies are missing
- Core functionality works with minimal dependencies
- Clear error messages guide you to solutions

### 4. **Multiple Installation Methods**
The script tries 4 different methods:
1. Standard pip install
2. Trusted hosts method (for SSL issues)
3. Individual package installation
4. Installation without version constraints

## Troubleshooting

### SSL Module Not Available

**macOS:**
```bash
# Install Python with SSL via Homebrew
brew install python3

# Then run the script again
./run_extraction.sh
```

**Linux:**
```bash
# Install Python with SSL support
sudo apt install python3-venv python3-pip python3-dev libssl-dev

# Or for CentOS/RHEL
sudo yum install python3 python3-pip openssl-devel
```

### Missing Dependencies

If automatic installation fails, install manually:

```bash
# For macOS/Linux
python3 -m pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org pycryptodome colorama tqdm requests

# For Windows
python -m pip install pycryptodome pywin32 colorama tqdm requests
```

### Python Not Found

**macOS:**
```bash
brew install python3
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install python3 python3-pip
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install python3 python3-pip
```

**Windows:**
Download from https://www.python.org/downloads/

## Manual Installation (If Script Fails)

1. **Install Python 3.7+** (see above)

2. **Install dependencies:**
   ```bash
   # macOS
   pip3 install -r requirements_macos.txt
   
   # Linux
   pip3 install -r requirements_linux.txt
   
   # Windows
   pip install -r requirements_windows.txt
   ```

3. **Run the script:**
   ```bash
   python3 main.py  # macOS/Linux
   python main.py   # Windows
   ```

## What Works Without Full Dependencies

- **Core extraction logic** - Works with minimal dependencies
- **File operations** - No special dependencies needed
- **Logging** - Uses standard library
- **Basic output** - Works without colorama (just no colors)

## What Requires Dependencies

- **Password/Cookie decryption** - Requires `pycryptodome`
- **Colored output** - Requires `colorama` (optional)
- **Progress bars** - Requires `tqdm` (optional)
- **Windows encryption** - Requires `pywin32` (Windows only)
- **macOS Keychain** - Requires `pyobjc-framework-Security` (macOS only)
- **Linux keyring** - Requires `keyring` (Linux only)

## Running in Restricted Environments

If you're in a restricted environment (no internet, limited permissions):

1. **Download wheels manually:**
   - Visit https://pypi.org/
   - Download `.whl` files for your platform
   - Install with: `pip install package.whl`

2. **Use offline mode:**
   ```bash
   pip install --no-index --find-links /path/to/wheels -r requirements.txt
   ```

3. **Skip optional features:**
   - The script will run but with limited functionality
   - Passwords/cookies may not decrypt without crypto libraries

## Platform-Specific Notes

### macOS
- **Full Disk Access** may be required for browser data
- **Keychain Access** may prompt for permission
- Homebrew Python recommended for SSL support

### Linux
- May need `sudo` for some operations
- Different package managers (apt, yum, pacman)
- Desktop environment affects file manager opening

### Windows
- **Administrator privileges** recommended
- May need to allow script execution: `Set-ExecutionPolicy RemoteSigned`
- Windows Defender may flag the script (false positive)

## Support

If you encounter issues:
1. Check the error messages - they provide specific guidance
2. Review `extraction.log` for detailed error information
3. Try manual installation steps above
4. Ensure Python 3.7+ is installed and in PATH

