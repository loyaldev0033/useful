#!/usr/bin/env python3
"""
Remote Desktop Configuration Tool
================================

This tool helps configure Windows Remote Desktop for remote access.
It will:
- Get PC IP address and username
- Enable Remote Desktop
- Configure firewall rules
- Set up remote access permissions
- Provide connection instructions

WARNING: Only use this on systems you own and have permission to access.
"""

import os
import sys
import subprocess
import platform
import socket
import getpass
import json
from datetime import datetime
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Try to import Windows-specific modules
try:
    import win32api
    import win32con
    import win32net
    import win32security
    import win32service
    import winreg
    WINDOWS_MODULES_AVAILABLE = True
except ImportError:
    WINDOWS_MODULES_AVAILABLE = False

class RemoteDesktopConfigurator:
    def __init__(self):
        self.system = platform.system().lower()
        self.pc_info = {
            'timestamp': datetime.now().isoformat(),
            'system': self.system,
            'ip_addresses': [],
            'username': '',
            'computer_name': '',
            'remote_desktop_status': '',
            'firewall_status': '',
            'configuration_steps': []
        }
        
    def log(self, message):
        """Log messages with timestamp"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def get_pc_information(self):
        """Get PC IP address, username, and computer name"""
        self.log("Getting PC information...")
        
        try:
            # Get username
            self.pc_info['username'] = getpass.getuser()
            
            # Get computer name
            self.pc_info['computer_name'] = platform.node()
            
            # Get IP addresses
            self._get_ip_addresses()
            
            self.log(f"Username: {self.pc_info['username']}")
            self.log(f"Computer Name: {self.pc_info['computer_name']}")
            self.log(f"IP Addresses: {', '.join(self.pc_info['ip_addresses'])}")
            
        except Exception as e:
            self.log(f"Error getting PC information: {e}")
            
    def _get_ip_addresses(self):
        """Get all IP addresses of the PC"""
        try:
            # Get hostname
            hostname = socket.gethostname()
            
            # Get local IP
            local_ip = socket.gethostbyname(hostname)
            self.pc_info['ip_addresses'].append(f"Local: {local_ip}")
            
            # Get all network interfaces
            if self.system == 'windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'IPv4 Address' in line and '127.0.0.1' not in line:
                            ip = line.split(':')[1].strip()
                            if ip not in [addr.split(': ')[1] for addr in self.pc_info['ip_addresses']]:
                                self.pc_info['ip_addresses'].append(f"Network: {ip}")
            
            # Get external IP (if possible)
            try:
                import requests
                response = requests.get('https://api.ipify.org', timeout=5)
                if response.status_code == 200:
                    external_ip = response.text.strip()
                    self.pc_info['ip_addresses'].append(f"External: {external_ip}")
            except:
                pass
                
        except Exception as e:
            self.log(f"Error getting IP addresses: {e}")
            
    def check_remote_desktop_status(self):
        """Check current Remote Desktop status"""
        self.log("Checking Remote Desktop status...")
        
        try:
            if self.system == 'windows':
                # Check if Remote Desktop is enabled
                result = subprocess.run(['reg', 'query', 
                                       'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', 
                                       '/v', 'fDenyTSConnections'], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    if '0x0' in result.stdout:
                        self.pc_info['remote_desktop_status'] = 'Enabled'
                        self.log("Remote Desktop is already enabled")
                    else:
                        self.pc_info['remote_desktop_status'] = 'Disabled'
                        self.log("Remote Desktop is currently disabled")
                else:
                    self.pc_info['remote_desktop_status'] = 'Unknown'
                    self.log("Could not determine Remote Desktop status")
            else:
                self.pc_info['remote_desktop_status'] = 'Not Windows'
                self.log("Remote Desktop is only available on Windows")
                
        except Exception as e:
            self.log(f"Error checking Remote Desktop status: {e}")
            
    def enable_remote_desktop(self):
        """Enable Remote Desktop on Windows"""
        self.log("Enabling Remote Desktop...")
        
        try:
            if self.system != 'windows':
                self.log("Remote Desktop is only available on Windows")
                return False
                
            # Enable Remote Desktop via registry
            result = subprocess.run(['reg', 'add', 
                                   'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', 
                                   '/v', 'fDenyTSConnections', '/t', 'REG_DWORD', '/d', '0', '/f'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.log("Remote Desktop enabled via registry")
                self.pc_info['configuration_steps'].append("Enabled Remote Desktop via registry")
                
                # Also try using PowerShell
                ps_script = """
                Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0
                Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
                """
                
                ps_result = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script], 
                                         capture_output=True, text=True, timeout=30)
                
                if ps_result.returncode == 0:
                    self.log("Remote Desktop enabled via PowerShell")
                    self.pc_info['configuration_steps'].append("Enabled Remote Desktop via PowerShell")
                else:
                    self.log("PowerShell method failed, but registry method succeeded")
                    
                return True
            else:
                self.log("Failed to enable Remote Desktop")
                return False
                
        except Exception as e:
            self.log(f"Error enabling Remote Desktop: {e}")
            return False
            
    def configure_firewall(self):
        """Configure Windows Firewall for Remote Desktop"""
        self.log("Configuring Windows Firewall...")
        
        try:
            if self.system != 'windows':
                self.log("Firewall configuration is only available on Windows")
                return False
                
            # Enable Remote Desktop firewall rules
            firewall_commands = [
                ['netsh', 'advfirewall', 'firewall', 'set', 'rule', 'group="Remote Desktop"', 'new', 'enable=yes'],
                ['netsh', 'advfirewall', 'firewall', 'set', 'rule', 'name="Remote Desktop (TCP-In)"', 'new', 'enable=yes'],
                ['netsh', 'advfirewall', 'firewall', 'set', 'rule', 'name="Remote Desktop (UDP-In)"', 'new', 'enable=yes']
            ]
            
            for cmd in firewall_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.log(f"Firewall rule configured: {' '.join(cmd)}")
                        self.pc_info['configuration_steps'].append(f"Configured firewall: {' '.join(cmd)}")
                    else:
                        self.log(f"Firewall rule failed: {' '.join(cmd)}")
                except Exception as e:
                    self.log(f"Error configuring firewall rule: {e}")
                    
            # Check firewall status
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                if 'ON' in result.stdout:
                    self.pc_info['firewall_status'] = 'Enabled'
                else:
                    self.pc_info['firewall_status'] = 'Disabled'
                    
            return True
            
        except Exception as e:
            self.log(f"Error configuring firewall: {e}")
            return False
            
    def configure_user_permissions(self):
        """Configure user permissions for Remote Desktop"""
        self.log("Configuring user permissions...")
        
        try:
            if self.system != 'windows':
                self.log("User permissions configuration is only available on Windows")
                return False
                
            # Add current user to Remote Desktop Users group
            username = self.pc_info['username']
            
            # Method 1: Using net command
            result = subprocess.run(['net', 'localgroup', 'Remote Desktop Users', username, '/add'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.log(f"Added {username} to Remote Desktop Users group")
                self.pc_info['configuration_steps'].append(f"Added {username} to Remote Desktop Users group")
            else:
                self.log(f"Failed to add {username} to Remote Desktop Users group")
                
            # Method 2: Using PowerShell
            ps_script = f"""
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member "{username}"
            """
            
            ps_result = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script], 
                                     capture_output=True, text=True, timeout=30)
            
            if ps_result.returncode == 0:
                self.log(f"Added {username} to Remote Desktop Users group via PowerShell")
                self.pc_info['configuration_steps'].append(f"Added {username} to Remote Desktop Users group via PowerShell")
            else:
                self.log(f"PowerShell method failed for user permissions")
                
            return True
            
        except Exception as e:
            self.log(f"Error configuring user permissions: {e}")
            return False
            
    def configure_advanced_settings(self):
        """Configure advanced Remote Desktop settings"""
        self.log("Configuring advanced settings...")
        
        try:
            if self.system != 'windows':
                self.log("Advanced settings configuration is only available on Windows")
                return False
                
            # Configure advanced registry settings
            advanced_settings = [
                ['reg', 'add', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', 
                 '/v', 'UserAuthentication', '/t', 'REG_DWORD', '/d', '0', '/f'],
                ['reg', 'add', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', 
                 '/v', 'fSingleSessionPerUser', '/t', 'REG_DWORD', '/d', '0', '/f'],
                ['reg', 'add', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', 
                 '/v', 'fDisableForcereboot', '/t', 'REG_DWORD', '/d', '1', '/f']
            ]
            
            for cmd in advanced_settings:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.log(f"Advanced setting configured: {' '.join(cmd)}")
                        self.pc_info['configuration_steps'].append(f"Configured advanced setting: {' '.join(cmd)}")
                    else:
                        self.log(f"Advanced setting failed: {' '.join(cmd)}")
                except Exception as e:
                    self.log(f"Error configuring advanced setting: {e}")
                    
            return True
            
        except Exception as e:
            self.log(f"Error configuring advanced settings: {e}")
            return False
            
    def restart_services(self):
        """Restart Remote Desktop services"""
        self.log("Restarting Remote Desktop services...")
        
        try:
            if self.system != 'windows':
                self.log("Service restart is only available on Windows")
                return False
                
            # Restart Terminal Services
            services = ['TermService', 'UmRdpService']
            
            for service in services:
                try:
                    # Stop service
                    subprocess.run(['net', 'stop', service], capture_output=True, text=True, timeout=30)
                    self.log(f"Stopped {service}")
                    
                    # Start service
                    subprocess.run(['net', 'start', service], capture_output=True, text=True, timeout=30)
                    self.log(f"Started {service}")
                    
                    self.pc_info['configuration_steps'].append(f"Restarted {service}")
                    
                except Exception as e:
                    self.log(f"Error restarting {service}: {e}")
                    
            return True
            
        except Exception as e:
            self.log(f"Error restarting services: {e}")
            return False
            
    def generate_connection_instructions(self):
        """Generate connection instructions"""
        self.log("Generating connection instructions...")
        
        instructions = {
            'connection_methods': [],
            'troubleshooting': [],
            'security_notes': []
        }
        
        # Connection methods
        for ip_info in self.pc_info['ip_addresses']:
            ip_type, ip_address = ip_info.split(': ')
            if ip_type == 'External':
                instructions['connection_methods'].append({
                    'method': 'External Connection',
                    'address': ip_address,
                    'port': '3389',
                    'command': f'mstsc /v:{ip_address}',
                    'note': 'Requires port forwarding on router'
                })
            else:
                instructions['connection_methods'].append({
                    'method': 'Local Network Connection',
                    'address': ip_address,
                    'port': '3389',
                    'command': f'mstsc /v:{ip_address}',
                    'note': 'Only works within local network'
                })
                
        # Troubleshooting
        instructions['troubleshooting'] = [
            'If connection fails, check Windows Firewall settings',
            'Ensure Remote Desktop is enabled in System Properties',
            'Verify user has Remote Desktop permissions',
            'Check if antivirus is blocking the connection',
            'Try connecting with computer name instead of IP',
            'Restart Remote Desktop services if needed'
        ]
        
        # Security notes
        instructions['security_notes'] = [
            'Change default RDP port (3389) for security',
            'Use strong passwords for user accounts',
            'Enable Network Level Authentication (NLA)',
            'Consider using VPN for external connections',
            'Regularly update Windows and security patches',
            'Monitor Remote Desktop connection logs'
        ]
        
        return instructions
        
    def save_configuration_report(self, filename="remote_desktop_config.txt"):
        """Save configuration report to file"""
        try:
            instructions = self.generate_connection_instructions()
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("REMOTE DESKTOP CONFIGURATION REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated: {self.pc_info['timestamp']}\n")
                f.write(f"System: {self.pc_info['system']}\n")
                f.write("=" * 50 + "\n\n")
                
                # PC Information
                f.write("PC INFORMATION:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Username: {self.pc_info['username']}\n")
                f.write(f"Computer Name: {self.pc_info['computer_name']}\n")
                f.write("IP Addresses:\n")
                for ip in self.pc_info['ip_addresses']:
                    f.write(f"  {ip}\n")
                f.write(f"Remote Desktop Status: {self.pc_info['remote_desktop_status']}\n")
                f.write(f"Firewall Status: {self.pc_info['firewall_status']}\n\n")
                
                # Configuration Steps
                f.write("CONFIGURATION STEPS:\n")
                f.write("-" * 20 + "\n")
                for step in self.pc_info['configuration_steps']:
                    f.write(f"✓ {step}\n")
                f.write("\n")
                
                # Connection Instructions
                f.write("CONNECTION INSTRUCTIONS:\n")
                f.write("-" * 20 + "\n")
                for method in instructions['connection_methods']:
                    f.write(f"Method: {method['method']}\n")
                    f.write(f"Address: {method['address']}\n")
                    f.write(f"Port: {method['port']}\n")
                    f.write(f"Command: {method['command']}\n")
                    f.write(f"Note: {method['note']}\n\n")
                
                # Troubleshooting
                f.write("TROUBLESHOOTING:\n")
                f.write("-" * 20 + "\n")
                for tip in instructions['troubleshooting']:
                    f.write(f"• {tip}\n")
                f.write("\n")
                
                # Security Notes
                f.write("SECURITY NOTES:\n")
                f.write("-" * 20 + "\n")
                for note in instructions['security_notes']:
                    f.write(f"⚠ {note}\n")
                f.write("\n")
                
                f.write("=" * 50 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 50 + "\n")
                
            self.log(f"Configuration report saved to: {filename}")
            return filename
            
        except Exception as e:
            self.log(f"Error saving configuration report: {e}")
            return None
            
    def run_full_configuration(self):
        """Run full Remote Desktop configuration"""
        self.log("Starting full Remote Desktop configuration...")
        
        # Get PC information
        self.get_pc_information()
        
        # Check current status
        self.check_remote_desktop_status()
        
        # Configure Remote Desktop
        if self.pc_info['remote_desktop_status'] != 'Enabled':
            self.enable_remote_desktop()
            
        # Configure firewall
        self.configure_firewall()
        
        # Configure user permissions
        self.configure_user_permissions()
        
        # Configure advanced settings
        self.configure_advanced_settings()
        
        # Restart services
        self.restart_services()
        
        # Save report
        filename = self.save_configuration_report()
        
        self.log("Remote Desktop configuration completed!")
        return filename

def main():
    """Main application entry point"""
    try:
        print("=" * 50)
        print("REMOTE DESKTOP CONFIGURATION TOOL")
        print("=" * 50)
        print("WARNING: This tool configures Remote Desktop access.")
        print("Only use this on systems you own and have permission to access.")
        print("=" * 50)
        
        configurator = RemoteDesktopConfigurator()
        
        # Run full configuration
        filename = configurator.run_full_configuration()
        
        if filename:
            print(f"\nRemote Desktop configuration completed successfully!")
            print(f"Configuration report saved to: {filename}")
            print("\nIMPORTANT SECURITY NOTES:")
            print("- Remote Desktop is now enabled on this PC")
            print("- You can connect from other PCs using the IP addresses shown")
            print("- Use strong passwords and consider security best practices")
            print("- The configuration report contains connection instructions")
        else:
            print("Failed to save configuration report.")
            
    except KeyboardInterrupt:
        print("\nRemote Desktop configuration interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
