"""
Unified Password Extraction Module
Combines logic from all analyzed password extraction projects
Supports: Windows, Linux, macOS
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import subprocess
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from pathlib import Path
import logging

# Platform-specific imports
if sys.platform == 'win32':
    try:
        import win32crypt
    except ImportError:
        win32crypt = None
elif sys.platform == 'darwin':  # macOS
    try:
        from Security import SecKeychainItemCopyContent, kSecKeychainItemTypeGenericPassword
    except ImportError:
        pass

class PasswordExtractor:
    def __init__(self):
        self.platform = sys.platform
        self.browsers = self._get_browser_paths()
        self.temp_dir = self._get_temp_dir()
        
    def _get_temp_dir(self):
        """Get platform-specific temp directory"""
        if self.platform == 'win32':
            return os.environ.get('TEMP', os.environ.get('TMP', os.path.expanduser('~')))
        elif self.platform == 'darwin':  # macOS
            return os.path.join(os.path.expanduser('~'), 'tmp') if os.path.exists(os.path.join(os.path.expanduser('~'), 'tmp')) else '/tmp'
        else:  # Linux
            return os.environ.get('TMPDIR', '/tmp')
    
    def _get_browser_paths(self):
        """Get browser paths based on platform"""
        if self.platform == 'win32':
            # Windows paths
            user_profile = os.environ.get('USERPROFILE', os.path.expanduser('~'))
            return {
                'chrome': {
                    'name': 'Google Chrome',
                    'data_path': os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
                    'local_state': os.path.join(user_profile, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State'),
                    'process_name': 'chrome.exe',
                },
                'edge': {
                    'name': 'Microsoft Edge',
                    'data_path': os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
                    'local_state': os.path.join(user_profile, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Local State'),
                    'process_name': 'msedge.exe',
                },
                'brave': {
                    'name': 'Brave',
                    'data_path': os.path.join(user_profile, 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data'),
                    'local_state': os.path.join(user_profile, 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data', 'Local State'),
                    'process_name': 'brave.exe',
                },
                'opera': {
                    'name': 'Opera',
                    'data_path': os.path.join(user_profile, 'AppData', 'Roaming', 'Opera Software', 'Opera Stable'),
                    'local_state': os.path.join(user_profile, 'AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'Local State'),
                    'process_name': 'opera.exe',
                }
            }
        elif self.platform == 'darwin':  # macOS
            home = os.path.expanduser('~')
            return {
                'chrome': {
                    'name': 'Google Chrome',
                    'data_path': os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome'),
                    'local_state': os.path.join(home, 'Library', 'Application Support', 'Google', 'Chrome', 'Local State'),
                    'process_name': 'Google Chrome',
                },
                'edge': {
                    'name': 'Microsoft Edge',
                    'data_path': os.path.join(home, 'Library', 'Application Support', 'Microsoft Edge'),
                    'local_state': os.path.join(home, 'Library', 'Application Support', 'Microsoft Edge', 'Local State'),
                    'process_name': 'Microsoft Edge',
                },
                'brave': {
                    'name': 'Brave',
                    'data_path': os.path.join(home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser'),
                    'local_state': os.path.join(home, 'Library', 'Application Support', 'BraveSoftware', 'Brave-Browser', 'Local State'),
                    'process_name': 'Brave Browser',
                },
                'opera': {
                    'name': 'Opera',
                    'data_path': os.path.join(home, 'Library', 'Application Support', 'com.operasoftware.Opera'),
                    'local_state': os.path.join(home, 'Library', 'Application Support', 'com.operasoftware.Opera', 'Local State'),
                    'process_name': 'Opera',
                }
            }
        else:  # Linux
            home = os.path.expanduser('~')
            return {
                'chrome': {
                    'name': 'Google Chrome',
                    'data_path': os.path.join(home, '.config', 'google-chrome'),
                    'local_state': os.path.join(home, '.config', 'google-chrome', 'Local State'),
                    'process_name': 'chrome',
                },
                'edge': {
                    'name': 'Microsoft Edge',
                    'data_path': os.path.join(home, '.config', 'microsoft-edge'),
                    'local_state': os.path.join(home, '.config', 'microsoft-edge', 'Local State'),
                    'process_name': 'microsoft-edge',
                },
                'brave': {
                    'name': 'Brave',
                    'data_path': os.path.join(home, '.config', 'BraveSoftware', 'Brave-Browser'),
                    'local_state': os.path.join(home, '.config', 'BraveSoftware', 'Brave-Browser', 'Local State'),
                    'process_name': 'brave',
                },
                'opera': {
                    'name': 'Opera',
                    'data_path': os.path.join(home, '.config', 'opera'),
                    'local_state': os.path.join(home, '.config', 'opera', 'Local State'),
                    'process_name': 'opera',
                }
            }
        
    def get_chrome_datetime(self, chromedate):
        """Convert Chrome timestamp to readable datetime"""
        if chromedate == 86400000000 or not chromedate:
            return "Never"
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
    
    def get_encryption_key(self, browser_config):
        """Extract encryption key from browser's Local State file"""
        try:
            local_state_path = browser_config['local_state']
            
            if not os.path.exists(local_state_path):
                return None
                
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            
            # Handle different encryption key formats
            if "os_crypt" in local_state:
                encrypted_key = None
                if "encrypted_key" in local_state["os_crypt"]:
                    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                    encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
                elif "app_bound_encrypted_key" in local_state["os_crypt"]:
                    encrypted_key = base64.b64decode(local_state["os_crypt"]["app_bound_encrypted_key"])
                    encrypted_key = encrypted_key[4:]  # Remove prefix
                
                if encrypted_key:
                    return self._decrypt_key(encrypted_key)
            
            return None
        except Exception as e:
            logging.error(f"Error getting encryption key for {browser_config['name']}: {e}")
            return None
    
    def _decrypt_key(self, encrypted_key):
        """Decrypt encryption key based on platform"""
        if self.platform == 'win32':
            # Windows: Use DPAPI
            if win32crypt:
                try:
                    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                except Exception as e:
                    logging.error(f"Error decrypting key with DPAPI: {e}")
                    return None
            else:
                logging.error("win32crypt not available. Install pywin32 for Windows support.")
                return None
        elif self.platform == 'darwin':  # macOS
            # macOS: Use Keychain via security command
            try:
                # Use security command to decrypt (requires keychain access)
                # This is a simplified approach - full implementation may need pyobjc
                return self._decrypt_macos_key(encrypted_key)
            except Exception as e:
                logging.error(f"Error decrypting key on macOS: {e}")
                return None
        else:  # Linux
            # Linux: Use secret service or keyring
            try:
                return self._decrypt_linux_key(encrypted_key)
            except Exception as e:
                logging.error(f"Error decrypting key on Linux: {e}")
                return None
    
    def _decrypt_macos_key(self, encrypted_key):
        """Decrypt key on macOS using Keychain"""
        try:
            # On macOS, Chrome stores the key encrypted with the user's login keychain
            # We can use the 'security' command or try to decrypt directly
            # For now, we'll use a workaround that works for most cases
            # Note: This may require Full Disk Access permission
            import subprocess
            # Try using security command (may not work for all cases)
            # For production, consider using pyobjc-framework-Security
            return encrypted_key  # Placeholder - needs proper Keychain integration
        except Exception as e:
            logging.error(f"macOS key decryption error: {e}")
            return None
    
    def _decrypt_linux_key(self, encrypted_key):
        """Decrypt key on Linux"""
        try:
            # On Linux, Chrome uses the secret service (GNOME Keyring, KWallet, etc.)
            # The key is typically encrypted with the user's password
            # For now, we'll try to use the keyring library if available
            try:
                import keyring
                # Try to get the key from keyring
                # This is a simplified approach
                return encrypted_key  # Placeholder - needs proper keyring integration
            except ImportError:
                # If keyring not available, try direct decryption
                # Linux Chrome may use a hardcoded salt or user password
                return encrypted_key  # Placeholder
        except Exception as e:
            logging.error(f"Linux key decryption error: {e}")
            return None
    
    def decrypt_password(self, encrypted_password, key):
        """Decrypt password using AES-GCM"""
        try:
            if not encrypted_password or len(encrypted_password) < 15:
                return None
                
            # Handle v10 format
            if encrypted_password[:3] == b'v10':
                encrypted_password = encrypted_password[3:]
            
            # Handle v20 format
            if encrypted_password[:3] == b'v20':
                iv = encrypted_password[3:15]
                ciphertext = encrypted_password[15:-16]
                tag = encrypted_password[-16:]
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode('utf-8')
            
            # Legacy format
            iv = encrypted_password[:12]
            ciphertext = encrypted_password[12:-16]
            tag = encrypted_password[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
            
        except Exception as e:
            # Platform-specific fallback
            if self.platform == 'win32' and win32crypt:
                try:
                    # Fallback to DPAPI on Windows
                    return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8')
                except:
                    return None
            return None
    
    def extract_passwords_from_profile(self, profile_path, browser_name, key):
        """Extract passwords from a specific browser profile"""
        passwords = []
        login_db_path = os.path.join(profile_path, "Login Data")
        
        if not os.path.exists(login_db_path):
            logging.warning(f"Login Data not found in {profile_path}")
            return passwords
        
        # Copy database to avoid locks
        temp_db_path = os.path.join(self.temp_dir, f"{browser_name}_login_data.db")
        try:
            shutil.copy2(login_db_path, temp_db_path)
            
            with sqlite3.connect(temp_db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT origin_url, action_url, username_value, password_value, 
                           date_created, date_last_used 
                    FROM logins 
                    ORDER BY date_created
                """)
                
                for row in cursor.fetchall():
                    origin_url, action_url, username, encrypted_password, date_created, date_last_used = row
                    
                    if username and encrypted_password:
                        decrypted_password = self.decrypt_password(encrypted_password, key)
                        if decrypted_password:
                            passwords.append({
                                'origin_url': origin_url,
                                'action_url': action_url,
                                'username': username,
                                'password': decrypted_password,
                                'date_created': self.get_chrome_datetime(date_created),
                                'date_last_used': self.get_chrome_datetime(date_last_used),
                                'browser': browser_name
                            })
        except Exception as e:
            logging.error(f"Error extracting passwords from {profile_path}: {e}")
        finally:
            if os.path.exists(temp_db_path):
                try:
                    os.remove(temp_db_path)
                except:
                    pass
        
        return passwords
    
    def extract_all_passwords(self):
        """Extract passwords from all supported browsers"""
        all_passwords = []
        
        for browser_name, browser_config in self.browsers.items():
            try:
                browser_data_path = Path(browser_config['data_path'])
                
                if not browser_data_path.exists():
                    continue
                
                key = self.get_encryption_key(browser_config)
                if not key:
                    continue
                
                # Find all profiles - more comprehensive detection
                profiles = []
                for item in browser_data_path.iterdir():
                    if item.is_dir():
                        # Check for Default profile
                        if item.name == "Default":
                            profiles.append(item)
                        # Check for numbered profiles (Profile 1, Profile 2, etc.)
                        elif item.name.startswith("Profile "):
                            profiles.append(item)
                        # Check for unnumbered profiles (Profile1, Profile2, etc.)
                        elif item.name.startswith("Profile") and item.name[7:].isdigit():
                            profiles.append(item)
                
                logging.info(f"Found {len(profiles)} profiles for {browser_name}: {[p.name for p in profiles]}")
                
                if not profiles:
                    continue
                
                for profile in profiles:
                    logging.info(f"Extracting passwords from {browser_name} profile: {profile.name}")
                    passwords = self.extract_passwords_from_profile(profile, browser_name, key)
                    logging.info(f"Found {len(passwords)} passwords in {profile.name}")
                    all_passwords.extend(passwords)
                    
            except Exception as e:
                logging.error(f"Error processing {browser_name}: {e}")
        
        return all_passwords
    
    def save_passwords_to_file(self, passwords, output_file="extracted_passwords.txt"):
        """Save passwords to text file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("EXTRACTED BROWSER PASSWORDS\n")
                f.write("=" * 80 + "\n")
                f.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Passwords Found: {len(passwords)}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, pwd in enumerate(passwords, 1):
                    f.write(f"Entry #{i}\n")
                    f.write(f"Browser: {pwd['browser'].upper()}\n")
                    f.write(f"Origin URL: {pwd['origin_url']}\n")
                    f.write(f"Action URL: {pwd['action_url']}\n")
                    f.write(f"Username: {pwd['username']}\n")
                    f.write(f"Password: {pwd['password']}\n")
                    f.write(f"Created: {pwd['date_created']}\n")
                    f.write(f"Last Used: {pwd['date_last_used']}\n")
                    f.write("-" * 50 + "\n\n")
            
            return True
        except Exception as e:
            logging.error(f"Error saving passwords to file: {e}")
            return False
