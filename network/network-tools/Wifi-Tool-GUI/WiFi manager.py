import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import re
import threading
import json
import time
import socket
import struct
import requests
from datetime import datetime
import os
import sys

class WiFiManager:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Network Manager")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2c3e50')

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()

        self.setup_gui()
        self.refresh_networks()
        self.refresh_devices()

    def configure_styles(self):
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#2c3e50', foreground='white')
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'), background='#34495e', foreground='white')
        self.style.configure('Custom.TFrame', background='#34495e')
        self.style.configure('Custom.TNotebook', background='#2c3e50')
        self.style.configure('Custom.TNotebook.Tab', background='#34495e', foreground='white')

    def setup_gui(self):
        # Main title
        title_label = ttk.Label(self.root, text="🌐 WiFi Network Manager", style='Title.TLabel')
        title_label.pack(pady=10)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root, style='Custom.TNotebook')
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Networks tab
        self.networks_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(self.networks_frame, text="Networks")
        self.setup_networks_tab()

        # Devices tab
        self.devices_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(self.devices_frame, text="Connected Devices")
        self.setup_devices_tab()

        # Passwords tab
        self.passwords_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(self.passwords_frame, text="Saved Passwords")
        self.setup_passwords_tab()

        # Tools tab
        self.tools_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(self.tools_frame, text="Network Tools")
        self.setup_tools_tab()

    def setup_networks_tab(self):
        # Scan button
        scan_btn = tk.Button(self.networks_frame, text="🔍 Scan Networks",
                           command=self.refresh_networks, bg='#3498db', fg='white',
                           font=('Arial', 10, 'bold'), relief='flat', pady=5)
        scan_btn.pack(pady=10)

        # Networks listbox with scrollbar
        list_frame = tk.Frame(self.networks_frame, bg='#34495e')
        list_frame.pack(fill='both', expand=True, padx=20, pady=10)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')

        self.networks_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                                         bg='#ecf0f1', fg='#2c3e50', font=('Arial', 10),
                                         selectbackground='#3498db')
        self.networks_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.networks_listbox.yview)

        # Network actions
        actions_frame = tk.Frame(self.networks_frame, bg='#34495e')
        actions_frame.pack(fill='x', padx=20, pady=10)

        connect_btn = tk.Button(actions_frame, text="Connect", command=self.connect_to_network,
                              bg='#27ae60', fg='white', relief='flat', padx=20)
        connect_btn.pack(side='left', padx=5)

        disconnect_btn = tk.Button(actions_frame, text="Disconnect", command=self.disconnect_network,
                                 bg='#e74c3c', fg='white', relief='flat', padx=20)
        disconnect_btn.pack(side='left', padx=5)

        details_btn = tk.Button(actions_frame, text="Details", command=self.show_network_details,
                              bg='#9b59b6', fg='white', relief='flat', padx=20)
        details_btn.pack(side='left', padx=5)

    def setup_devices_tab(self):
        # Refresh button
        refresh_btn = tk.Button(self.devices_frame, text="🔄 Refresh Devices",
                              command=self.refresh_devices, bg='#3498db', fg='white',
                              font=('Arial', 10, 'bold'), relief='flat', pady=5)
        refresh_btn.pack(pady=10)

        # Devices treeview
        self.devices_tree = ttk.Treeview(self.devices_frame, columns=('IP', 'MAC', 'Device', 'Status'), show='headings')
        self.devices_tree.heading('IP', text='IP Address')
        self.devices_tree.heading('MAC', text='MAC Address')
        self.devices_tree.heading('Device', text='Device Name')
        self.devices_tree.heading('Status', text='Status')

        self.devices_tree.pack(fill='both', expand=True, padx=20, pady=10)

        # Device actions
        device_actions_frame = tk.Frame(self.devices_frame, bg='#34495e')
        device_actions_frame.pack(fill='x', padx=20, pady=10)

        block_btn = tk.Button(device_actions_frame, text="Block Device", command=self.block_device,
                            bg='#e74c3c', fg='white', relief='flat', padx=20)
        block_btn.pack(side='left', padx=5)

        unblock_btn = tk.Button(device_actions_frame, text="Unblock Device", command=self.unblock_device,
                              bg='#27ae60', fg='white', relief='flat', padx=20)
        unblock_btn.pack(side='left', padx=5)

        ping_btn = tk.Button(device_actions_frame, text="Ping Device", command=self.ping_device,
                           bg='#f39c12', fg='white', relief='flat', padx=20)
        ping_btn.pack(side='left', padx=5)

    def setup_passwords_tab(self):
        # Get passwords button
        get_passwords_btn = tk.Button(self.passwords_frame, text="🔑 Get Saved Passwords",
                                    command=self.get_saved_passwords, bg='#3498db', fg='white',
                                    font=('Arial', 10, 'bold'), relief='flat', pady=5)
        get_passwords_btn.pack(pady=10)

        # Passwords display
        self.passwords_text = scrolledtext.ScrolledText(self.passwords_frame, bg='#ecf0f1', fg='#2c3e50',
                                                      font=('Courier', 10), wrap='word')
        self.passwords_text.pack(fill='both', expand=True, padx=20, pady=10)

    def setup_tools_tab(self):
        # Network diagnostics
        tools_label = ttk.Label(self.tools_frame, text="Network Diagnostic Tools", style='Header.TLabel')
        tools_label.pack(pady=10)

        # IP Scanner
        ip_frame = tk.Frame(self.tools_frame, bg='#34495e')
        ip_frame.pack(fill='x', padx=20, pady=10)

        tk.Label(ip_frame, text="IP Range:", bg='#34495e', fg='white').pack(side='left')
        self.ip_entry = tk.Entry(ip_frame, bg='white', fg='black')
        self.ip_entry.insert(0, "192.168.1.1-254")
        self.ip_entry.pack(side='left', padx=5)

        scan_ip_btn = tk.Button(ip_frame, text="Scan IP Range", command=self.scan_ip_range,
                              bg='#27ae60', fg='white', relief='flat')
        scan_ip_btn.pack(side='left', padx=5)

        # Results display
        self.tools_text = scrolledtext.ScrolledText(self.tools_frame, bg='#ecf0f1', fg='#2c3e50',
                                                  font=('Courier', 9), wrap='word')
        self.tools_text.pack(fill='both', expand=True, padx=20, pady=10)

    def run_command(self, command):
        """Execute Windows command and return output"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "", "Command timeout"
        except Exception as e:
            return "", str(e)

    def refresh_networks(self):
        """Scan and display available WiFi networks"""
        self.networks_listbox.delete(0, tk.END)
        self.networks_listbox.insert(0, "Scanning networks...")

        def scan_thread():
            stdout, stderr = self.run_command("netsh wlan show profiles")
            if stderr:
                self.root.after(0, lambda: self.networks_listbox.insert(tk.END, f"Error: {stderr}"))
                return

            # Parse WiFi profiles
            profiles = []
            for line in stdout.split('\n'):
                if 'All User Profile' in line:
                    profile_name = line.split(':')[1].strip()
                    profiles.append(profile_name)

            # Get available networks
            stdout2, stderr2 = self.run_command("netsh wlan show profile")

            # Also scan for available networks
            stdout3, stderr3 = self.run_command("netsh wlan show interfaces")

            self.root.after(0, lambda: self.update_networks_display(profiles))

        threading.Thread(target=scan_thread, daemon=True).start()

    def update_networks_display(self, profiles):
        """Update the networks display"""
        self.networks_listbox.delete(0, tk.END)

        if not profiles:
            self.networks_listbox.insert(0, "No saved networks found")
            return

        for profile in profiles:
            # Get signal strength and details
            stdout, stderr = self.run_command(f'netsh wlan show profile name="{profile}" key=clear')

            signal_info = "Unknown"
            security_info = "Unknown"

            if not stderr:
                for line in stdout.split('\n'):
                    if 'Authentication' in line:
                        security_info = line.split(':')[1].strip()
                    elif 'Signal' in line:
                        signal_info = line.split(':')[1].strip()

            display_text = f"{profile} | Security: {security_info} | Signal: {signal_info}"
            self.networks_listbox.insert(tk.END, display_text)

    def connect_to_network(self):
        """Connect to selected network"""
        selection = self.networks_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a network")
            return

        network_info = self.networks_listbox.get(selection[0])
        network_name = network_info.split(' | ')[0]

        # Try to connect
        stdout, stderr = self.run_command(f'netsh wlan connect name="{network_name}"')

        if stderr:
            messagebox.showerror("Error", f"Failed to connect: {stderr}")
        else:
            messagebox.showinfo("Success", f"Attempting to connect to {network_name}")

    def disconnect_network(self):
        """Disconnect from current network"""
        stdout, stderr = self.run_command("netsh wlan disconnect")

        if stderr:
            messagebox.showerror("Error", f"Failed to disconnect: {stderr}")
        else:
            messagebox.showinfo("Success", "Disconnected from network")

    def show_network_details(self):
        """Show detailed network information"""
        selection = self.networks_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a network")
            return

        network_info = self.networks_listbox.get(selection[0])
        network_name = network_info.split(' | ')[0]

        stdout, stderr = self.run_command(f'netsh wlan show profile name="{network_name}" key=clear')

        if stderr:
            messagebox.showerror("Error", f"Failed to get details: {stderr}")
        else:
            # Create new window for details
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Network Details: {network_name}")
            details_window.geometry("600x400")

            text_widget = scrolledtext.ScrolledText(details_window, wrap='word')
            text_widget.pack(fill='both', expand=True, padx=10, pady=10)
            text_widget.insert('1.0', stdout)

    def refresh_devices(self):
        """Scan for connected devices on the network"""
        self.devices_tree.delete(*self.devices_tree.get_children())

        def scan_devices_thread():
            # Get current network info
            stdout, stderr = self.run_command("ipconfig")

            if stderr:
                return

            # Extract network range
            network_base = None
            for line in stdout.split('\n'):
                if 'IPv4 Address' in line and '192.168' in line:
                    ip = line.split(':')[1].strip()
                    network_base = '.'.join(ip.split('.')[:-1])
                    break

            if not network_base:
                self.root.after(0, lambda: self.devices_tree.insert('', 'end', values=('No network', 'detected', '', '')))
                return

            # Scan network range
            devices = []
            for i in range(1, 255):
                ip = f"{network_base}.{i}"

                # Ping to check if device is alive
                ping_result = subprocess.run(f"ping -n 1 -w 1000 {ip}",
                                           shell=True, capture_output=True, text=True)

                if ping_result.returncode == 0:
                    # Try to get MAC address
                    arp_result = subprocess.run(f"arp -a {ip}",
                                              shell=True, capture_output=True, text=True)

                    mac = "Unknown"
                    if arp_result.returncode == 0:
                        for line in arp_result.stdout.split('\n'):
                            if ip in line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    mac = parts[1]
                                break

                    # Try to get hostname
                    hostname = "Unknown"
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        pass

                    devices.append((ip, mac, hostname, "Online"))

            # Update UI
            self.root.after(0, lambda: self.update_devices_display(devices))

        threading.Thread(target=scan_devices_thread, daemon=True).start()

    def update_devices_display(self, devices):
        """Update the devices tree view"""
        self.devices_tree.delete(*self.devices_tree.get_children())

        if not devices:
            self.devices_tree.insert('', 'end', values=('No devices', 'found', '', ''))
            return

        for device in devices:
            self.devices_tree.insert('', 'end', values=device)

    def block_device(self):
        """Block selected device (requires router access)"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device")
            return

        device_info = self.devices_tree.item(selection[0])['values']
        ip = device_info[0]

        # This would require router API access
        messagebox.showinfo("Info", f"Blocking device {ip} requires router admin access.\n"
                                   f"Please access your router's admin panel to block this device.")

    def unblock_device(self):
        """Unblock selected device"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device")
            return

        device_info = self.devices_tree.item(selection[0])['values']
        ip = device_info[0]

        messagebox.showinfo("Info", f"Unblocking device {ip} requires router admin access.\n"
                                   f"Please access your router's admin panel to unblock this device.")

    def ping_device(self):
        """Ping selected device"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device")
            return

        device_info = self.devices_tree.item(selection[0])['values']
        ip = device_info[0]

        def ping_thread():
            stdout, stderr = self.run_command(f"ping -n 4 {ip}")

            # Show results in new window
            self.root.after(0, lambda: self.show_ping_results(ip, stdout, stderr))

        threading.Thread(target=ping_thread, daemon=True).start()

    def show_ping_results(self, ip, stdout, stderr):
        """Show ping results in new window"""
        results_window = tk.Toplevel(self.root)
        results_window.title(f"Ping Results: {ip}")
        results_window.geometry("500x300")

        text_widget = scrolledtext.ScrolledText(results_window, wrap='word')
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)

        if stderr:
            text_widget.insert('1.0', f"Error: {stderr}")
        else:
            text_widget.insert('1.0', stdout)

    def get_saved_passwords(self):
        """Get saved WiFi passwords"""
        self.passwords_text.delete('1.0', tk.END)
        self.passwords_text.insert('1.0', "Retrieving saved passwords...\n\n")

        def get_passwords_thread():
            # Get all profiles
            stdout, stderr = self.run_command("netsh wlan show profiles")

            if stderr:
                self.root.after(0, lambda: self.passwords_text.insert(tk.END, f"Error: {stderr}"))
                return

            profiles = []
            for line in stdout.split('\n'):
                if 'All User Profile' in line:
                    profile_name = line.split(':')[1].strip()
                    profiles.append(profile_name)

            password_info = []
            for profile in profiles:
                stdout2, stderr2 = self.run_command(f'netsh wlan show profile name="{profile}" key=clear')

                if not stderr2:
                    password = "No password or access denied"
                    for line in stdout2.split('\n'):
                        if 'Key Content' in line:
                            password = line.split(':')[1].strip()
                            break

                    password_info.append(f"Network: {profile}\nPassword: {password}\n{'-'*50}")

            self.root.after(0, lambda: self.update_passwords_display(password_info))

        threading.Thread(target=get_passwords_thread, daemon=True).start()

    def update_passwords_display(self, password_info):
        """Update passwords display"""
        self.passwords_text.delete('1.0', tk.END)

        if not password_info:
            self.passwords_text.insert('1.0', "No saved passwords found or access denied.\n\n")
            self.passwords_text.insert(tk.END, "Note: You may need to run this application as Administrator to access saved passwords.")
            return

        for info in password_info:
            self.passwords_text.insert(tk.END, info + "\n\n")

    def scan_ip_range(self):
        """Scan IP range for active devices"""
        ip_range = self.ip_entry.get()
        self.tools_text.delete('1.0', tk.END)
        self.tools_text.insert('1.0', f"Scanning IP range: {ip_range}\n\n")

        def scan_thread():
            if '-' in ip_range:
                base_ip, end_range = ip_range.split('-')
                base_parts = base_ip.split('.')
                base_network = '.'.join(base_parts[:-1])
                start_ip = int(base_parts[-1])
                end_ip = int(end_range)

                active_devices = []
                for i in range(start_ip, end_ip + 1):
                    ip = f"{base_network}.{i}"

                    # Quick ping
                    ping_result = subprocess.run(f"ping -n 1 -w 500 {ip}",
                                               shell=True, capture_output=True, text=True)

                    if ping_result.returncode == 0:
                        # Try to get additional info
                        hostname = "Unknown"
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except:
                            pass

                        active_devices.append(f"{ip} - {hostname}")

                result_text = f"Found {len(active_devices)} active devices:\n\n"
                for device in active_devices:
                    result_text += f"✓ {device}\n"

                self.root.after(0, lambda: self.tools_text.insert(tk.END, result_text))
            else:
                self.root.after(0, lambda: self.tools_text.insert(tk.END, "Invalid IP range format"))

        threading.Thread(target=scan_thread, daemon=True).start()


def main():
    # Check if running as administrator
    def is_admin():
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    root = tk.Tk()

    if not is_admin():
        messagebox.showinfo("Info", "For full functionality (especially password retrieval), "
                                   "consider running this application as Administrator.")

    app = WiFiManager(root)
    root.mainloop()


if __name__ == "__main__":
    main()
