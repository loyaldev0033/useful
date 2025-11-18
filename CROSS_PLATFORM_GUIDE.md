# Cross-Platform Guide

This project now supports **Windows, Linux, and macOS** with automatic platform detection.

## Quick Start

### Windows:
```bash
start.bat
```

### macOS/Linux:
```bash
chmod +x start.sh
./start.sh
```

## Files Updated for Cross-Platform Support

### 1. **start.bat** (Windows Batch File)
- ✅ Detects platform automatically
- ✅ Installs platform-specific dependencies
- ✅ Runs all available Python scripts
- ✅ Handles missing scripts gracefully

### 2. **start.sh** (Unix Shell Script)
- ✅ New file for macOS/Linux
- ✅ Equivalent functionality to start.bat
- ✅ Smart Python detection (prefers Homebrew on macOS)
- ✅ SSL workarounds for Python without SSL support
- ✅ Multiple installation fallback methods

### 3. **run.py** (Advanced Credential Extractor)
- ✅ Cross-platform browser paths (Windows/macOS/Linux)
- ✅ Platform-aware encryption methods
- ✅ Graceful handling of missing dependencies
- ✅ Works on all platforms

### 4. **ultimate.py** (Ultimate Credential Extractor)
- ✅ Cross-platform browser paths
- ✅ Platform-specific credential manager extraction:
  - Windows: Credential Manager, Registry, PowerShell
  - macOS: Keychain, Security command
  - Linux: Keyring, Secret Service
- ✅ Platform-aware encryption
- ✅ All Windows-specific methods guarded with platform checks

## Platform-Specific Features

### Windows
- Windows Credential Manager API
- Registry extraction
- PowerShell credential extraction
- DPAPI encryption
- Windows service credentials

### macOS
- Keychain extraction (via `security` command)
- Keyring library support
- Keychain file access
- Network password extraction

### Linux
- Keyring extraction (GNOME Keyring, KWallet)
- Secret Service support
- Keyring file access
- System credential stores

## Browser Paths by Platform

### Chrome
- **Windows**: `%USERPROFILE%\AppData\Local\Google\Chrome\User Data`
- **macOS**: `~/Library/Application Support/Google/Chrome`
- **Linux**: `~/.config/google-chrome`

### Edge
- **Windows**: `%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data`
- **macOS**: `~/Library/Application Support/Microsoft Edge`
- **Linux**: `~/.config/microsoft-edge`

### Firefox
- **Windows**: `%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles`
- **macOS**: `~/Library/Application Support/Firefox/Profiles`
- **Linux**: `~/.mozilla/firefox`

### Brave
- **Windows**: `%USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data`
- **macOS**: `~/Library/Application Support/BraveSoftware/Brave-Browser`
- **Linux**: `~/.config/BraveSoftware/Brave-Browser`

### Opera
- **Windows**: `%USERPROFILE%\AppData\Roaming\Opera Software\Opera Stable`
- **macOS**: `~/Library/Application Support/com.operasoftware.Opera`
- **Linux**: `~/.config/opera`

## Running on Different Platforms

### Windows
1. Double-click `start.bat` or run from Command Prompt
2. Script detects Windows and installs Windows-specific dependencies
3. Runs all available Python scripts

### macOS
1. Open Terminal
2. Navigate to project directory
3. Run: `chmod +x start.sh && ./start.sh`
4. Script detects macOS and installs macOS-specific dependencies
5. May require Full Disk Access permission

### Linux
1. Open Terminal
2. Navigate to project directory
3. Run: `chmod +x start.sh && ./start.sh`
4. Script detects Linux and installs Linux-specific dependencies
5. May require sudo for some operations

## Dependencies by Platform

### Windows
- `pywin32` - Windows API access
- `pycryptodome` - Encryption
- `colorama`, `tqdm` - UI enhancements

### macOS
- `pyobjc-framework-Security` - Keychain access
- `pycryptodome` - Encryption
- `keyring` - Keyring support
- `colorama`, `tqdm` - UI enhancements

### Linux
- `keyring` - Keyring support
- `pycryptodome` - Encryption
- `colorama`, `tqdm` - UI enhancements

## Troubleshooting

### Script Not Found
- **Windows**: Ensure you're in the correct directory
- **macOS/Linux**: Make script executable: `chmod +x start.sh`

### Python Not Found
- Install Python 3.7+ from https://www.python.org/downloads/
- **macOS**: `brew install python3`
- **Linux**: `sudo apt install python3 python3-pip`

### Dependencies Fail to Install
- Script automatically tries multiple installation methods
- Check internet connection
- Try manual installation: `pip install -r requirements_<platform>.txt`

### Permission Errors
- **Windows**: Run as Administrator
- **macOS**: Grant Full Disk Access in System Preferences
- **Linux**: May need sudo for some operations

## Output Files

All scripts generate output files:
- `output1.txt` - Ultimate extractor results
- `output2.txt` - Aggressive extractor results
- `output3.txt` - Remote desktop configuration
- `output4.txt` - Advanced extractor results
- `summary.txt` - Summary report

## Notes

- Scripts automatically detect which Python scripts are available
- Missing scripts are skipped gracefully
- Platform-specific features only run on appropriate platforms
- All output is saved to text files for review

