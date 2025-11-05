"""
Unified Browser Data Extractor
Combines all analyzed projects into one comprehensive tool
"""

import os
import sys
import io
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style
from tqdm import tqdm

# Fix encoding issues on Windows
if sys.platform == 'win32':
    # Set console encoding to UTF-8
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Import our custom modules
from password_extractor import PasswordExtractor
from cookie_extractor import CookieExtractor

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class UnifiedBrowserExtractor:
    def __init__(self):
        self.password_extractor = PasswordExtractor()
        self.cookie_extractor = CookieExtractor()
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('extraction.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}{'='*80}
{Fore.YELLOW}    UNIFIED BROWSER DATA EXTRACTOR
{Fore.CYAN}{'='*80}
{Fore.GREEN}    Combines logic from all analyzed password/cookie extraction projects
{Fore.GREEN}    Supports: Chrome, Edge, Brave, Opera
{Fore.GREEN}    Extracts: Passwords, Cookies, Autofill Data
{Fore.CYAN}{'='*80}
{Style.RESET_ALL}
"""
        print(banner)
    
    def check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def kill_browser_processes(self):
        """Terminate browser processes to avoid file locks"""
        browsers = ['chrome.exe', 'msedge.exe', 'brave.exe', 'opera.exe']
        killed_processes = []
        
        print(f"{Fore.YELLOW}Terminating browser processes to avoid file locks...")
        
        for browser in browsers:
            try:
                result = subprocess.run(['taskkill', '/F', '/IM', browser], 
                                     capture_output=True, text=True)
                if result.returncode == 0:
                    killed_processes.append(browser)
            except:
                pass
        
        if killed_processes:
            print(f"{Fore.GREEN}Terminated: {', '.join(killed_processes)}")
        else:
            print(f"{Fore.YELLOW}No browser processes found running")
        
        time.sleep(2)  # Wait for processes to fully terminate
    
    def extract_passwords(self):
        """Extract passwords from all browsers"""
        print(f"\n{Fore.CYAN}Extracting passwords from all browsers...")
        
        try:
            passwords = self.password_extractor.extract_all_passwords()
            
            if passwords:
                # Save to text file
                if self.password_extractor.save_passwords_to_file(passwords):
                    print(f"{Fore.GREEN}[+] Passwords saved to: extracted_passwords.txt")
                
                # Save to CSV for easy analysis
                self.save_passwords_to_csv(passwords)
                
                print(f"{Fore.GREEN}[+] Found {len(passwords)} passwords")
                
                # Show browser breakdown
                browser_counts = {}
                for pwd in passwords:
                    browser = pwd['browser']
                    browser_counts[browser] = browser_counts.get(browser, 0) + 1
                
                print(f"{Fore.YELLOW}Browser breakdown:")
                for browser, count in browser_counts.items():
                    print(f"  {browser}: {count} passwords")
                
                return True
            else:
                print(f"{Fore.YELLOW}[!] No passwords found")
                return False
                
        except Exception as e:
            logging.error(f"Error extracting passwords: {e}")
            print(f"{Fore.RED}[-] Error extracting passwords: {e}")
            return False
    
    def extract_cookies(self):
        """Extract cookies from all browsers"""
        print(f"\n{Fore.CYAN}Extracting cookies from all browsers...")
        
        try:
            cookies = self.cookie_extractor.extract_all_cookies()
            
            if cookies:
                # Save to text file
                if self.cookie_extractor.save_cookies_to_file(cookies):
                    print(f"{Fore.GREEN}[+] Cookies saved to: extracted_cookies.txt")
                
                # Save to JSON for easy import
                if self.cookie_extractor.save_cookies_to_json(cookies):
                    print(f"{Fore.GREEN}[+] Cookies saved to: extracted_cookies.json")
                
                print(f"{Fore.GREEN}[+] Found {len(cookies)} cookies")
                
                # Show browser breakdown
                browser_counts = {}
                for cookie in cookies:
                    browser = cookie['browser']
                    browser_counts[browser] = browser_counts.get(browser, 0) + 1
                
                print(f"{Fore.YELLOW}Browser breakdown:")
                for browser, count in browser_counts.items():
                    print(f"  {browser}: {count} cookies")
                
                return True
            else:
                print(f"{Fore.YELLOW}[!] No cookies found")
                return False
                
        except Exception as e:
            logging.error(f"Error extracting cookies: {e}")
            print(f"{Fore.RED}[-] Error extracting cookies: {e}")
            return False
    
    def save_passwords_to_csv(self, passwords):
        """Save passwords to CSV file"""
        try:
            import csv
            with open('extracted_passwords.csv', 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['browser', 'origin_url', 'action_url', 'username', 'password', 'date_created', 'date_last_used']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for pwd in passwords:
                    writer.writerow({
                        'browser': pwd['browser'],
                        'origin_url': pwd['origin_url'],
                        'action_url': pwd['action_url'],
                        'username': pwd['username'],
                        'password': pwd['password'],
                        'date_created': pwd['date_created'],
                        'date_last_used': pwd['date_last_used']
                    })
            
            print(f"{Fore.GREEN}[+] Passwords saved to: extracted_passwords.csv")
            return True
        except Exception as e:
            logging.error(f"Error saving passwords to CSV: {e}")
            return False
    
    def generate_summary_report(self, passwords_count, cookies_count):
        """Generate a summary report"""
        try:
            with open('extraction_summary.txt', 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("BROWSER DATA EXTRACTION SUMMARY\n")
                f.write("=" * 80 + "\n")
                f.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Passwords Extracted: {passwords_count}\n")
                f.write(f"Total Cookies Extracted: {cookies_count}\n")
                f.write("=" * 80 + "\n")
                f.write("FILES GENERATED:\n")
                f.write("- extracted_passwords.txt (Detailed password list)\n")
                f.write("- extracted_passwords.csv (CSV format for analysis)\n")
                f.write("- extracted_cookies.txt (Detailed cookie list)\n")
                f.write("- extracted_cookies.json (JSON format for import)\n")
                f.write("- extraction_summary.txt (This summary)\n")
                f.write("- extraction.log (Detailed extraction log)\n")
                f.write("=" * 80 + "\n")
                f.write("IMPORTANT NOTES:\n")
                f.write("- All data extracted for educational purposes only\n")
                f.write("- Use responsibly and only on authorized systems\n")
                f.write("- Keep extracted data secure and delete when no longer needed\n")
                f.write("=" * 80 + "\n")
            
            print(f"{Fore.GREEN}[+] Summary report saved to: extraction_summary.txt")
            return True
        except Exception as e:
            logging.error(f"Error generating summary report: {e}")
            return False
    
    def run_extraction(self):
        """Main extraction process"""
        self.print_banner()
        
        # Check admin privileges
        if not self.check_admin_privileges():
            print(f"{Fore.RED}[!] WARNING: Not running as administrator")
            print(f"{Fore.YELLOW}Some extractions may fail without admin privileges")
            print(f"{Fore.YELLOW}Consider running as administrator for best results\n")
        
        # Kill browser processes
        self.kill_browser_processes()
        
        # Track results
        passwords_count = 0
        cookies_count = 0
        
        # Extract passwords
        print(f"{Fore.CYAN}Starting password extraction...")
        if self.extract_passwords():
            passwords_count = len(self.password_extractor.extract_all_passwords())
        
        # Extract cookies
        print(f"{Fore.CYAN}Starting cookie extraction...")
        if self.extract_cookies():
            cookies_count = len(self.cookie_extractor.extract_all_cookies())
        
        # Generate summary
        self.generate_summary_report(passwords_count, cookies_count)
        
        # Final output
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.GREEN}EXTRACTION COMPLETED SUCCESSFULLY!")
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.GREEN}[+] Passwords extracted: {passwords_count}")
        print(f"{Fore.GREEN}[+] Cookies extracted: {cookies_count}")
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.YELLOW}Check the generated files for detailed results")
        print(f"{Fore.YELLOW}All files saved in current directory")
        print(f"{Fore.CYAN}{'='*80}")

def main():
    """Main entry point"""
    try:
        extractor = UnifiedBrowserExtractor()
        extractor.run_extraction()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Extraction interrupted by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"{Fore.RED}Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
