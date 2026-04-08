# File: gui/alerts.py - Enhanced Industrial-Grade Security Alerts

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import os
import re
import json
import csv
from datetime import datetime, timedelta
from gui.styles import ModernStyles
from collections import defaultdict
import threading
import queue


class AlertsPanel:
    def __init__(self, master, user_id):
        self.master = master
        self.user_id = user_id
        self.all_alerts = []
        self.filtered_alerts = []
        self.current_filter = None
        self.sort_column = None
        self.sort_reverse = False
        self._stopped = False
        
        self.container = ttk.Frame(master, style="TFrame")
        self.container.pack(expand=True, fill='both', padx=5, pady=5)
        
        # Header with title and controls
        self.header = ttk.Frame(self.container, style="Card.TFrame", padding=15)
        self.header.pack(fill='x', pady=(0, 15))
        
        title_section = ttk.Frame(self.header, style="Card.TFrame")
        title_section.pack(side='left', fill='x', expand=True)
        
        ttk.Label(title_section, text="🛡️ Security Alert Center", style="CardTitle.TLabel").pack(anchor='w')
        self.stats_label = ttk.Label(title_section, text="", style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED, font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_SMALL))
        self.stats_label.pack(anchor='w', pady=(5, 0))
        
        self.button_frame = ttk.Frame(self.header, style="Card.TFrame")
        self.button_frame.pack(side='right')
        
        # Quick filter buttons
        self.quick_filter_frame = ttk.Frame(self.button_frame, style="Card.TFrame")
        self.quick_filter_frame.pack(fill='x', pady=(0, 5))
        
        ModernStyles.create_button(self.quick_filter_frame, "Critical", lambda: self.quick_filter('CRITICAL')).pack(side='left', padx=2)
        ModernStyles.create_button(self.quick_filter_frame, "Attacks", lambda: self.quick_filter('attack')).pack(side='left', padx=2)
        ModernStyles.create_button(self.quick_filter_frame, "Today", lambda: self.quick_filter('today')).pack(side='left', padx=2)
        
        # Main action buttons
        self.action_frame = ttk.Frame(self.button_frame, style="Card.TFrame")
        self.action_frame.pack(fill='x')
        
        ModernStyles.create_button(self.action_frame, "🔍 Filter", self.show_filter_dialog).pack(side='left', padx=2)
        ModernStyles.create_button(self.action_frame, "Clear Filter", self.clear_filter, is_secondary=True).pack(side='left', padx=2)
        ModernStyles.create_button(self.action_frame, "🗑️ Clear All", self.clear_all_alerts, is_secondary=True).pack(side='left', padx=2)
        ModernStyles.create_button(self.action_frame, "📊 Export", self.export_alerts, is_secondary=True).pack(side='left', padx=2)

        self.filter_indicator = ttk.Label(self.header, text="", style="Card.TLabel", foreground=ModernStyles.PRIMARY_COLOR)
        self.filter_indicator.pack(side='right', padx=(0, 10))
        
        # Treeview in its own card
        self.tree_frame = ttk.Frame(self.container, style="Card.TFrame")
        self.tree_frame.pack(expand=True, fill='both')
        
        self.scrollbar = ttk.Scrollbar(self.tree_frame)
        self.scrollbar.pack(side='right', fill='y')
        
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=('severity', 'timestamp', 'attack_type', 'source_ip', 'dest_ip', 'alert_message', 'action'),
            show='headings', style="Treeview", yscrollcommand=self.scrollbar.set
        )
        self.scrollbar.config(command=self.tree.yview)
        
        columns_config = [('severity', 'Severity', 100, 'center'), ('timestamp', 'Timestamp', 160, 'w'), 
                          ('attack_type', 'Attack Type', 150, 'w'), ('source_ip', 'Source IP', 120, 'center'),
                          ('dest_ip', 'Dest IP', 120, 'center'), ('alert_message', 'Alert Message', 300, 'w'),
                          ('action', 'Action', 100, 'center')]
        
        for col_id, col_text, col_width, col_anchor in columns_config:
            self.tree.heading(col_id, text=col_text, anchor='w', command=lambda c=col_id: self.sort_column_data(c))
            self.tree.column(col_id, width=col_width, anchor=col_anchor, minwidth=50)
        
        self.tree.pack(expand=True, fill='both')
        
        # Configure theme-based tag colors
        self.tree.tag_configure('CRITICAL', foreground=ModernStyles.DANGER_COLOR, font=(ModernStyles.FONT_FAMILY, 11, 'bold'))
        self.tree.tag_configure('ERROR', foreground=ModernStyles.DANGER_COLOR)
        self.tree.tag_configure('WARNING', foreground=ModernStyles.WARNING_COLOR)
        self.tree.tag_configure('INFO', foreground=ModernStyles.SUCCESS_COLOR)

        self.tree.bind('<Double-1>', self.on_alert_double_click)
        self.tree.bind('<Button-3>', self.on_right_click)

        self.log_file = "logs/system.log"
        self.last_size = 0
        
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="View Details", command=self.view_alert_details)
        self.context_menu.add_command(label="Block Source IP", command=self.block_source_ip)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Alert", command=self.copy_alert)

        self.load_alerts(initial=True)
        self.schedule_refresh()

    def load_alerts(self, initial=False):
        if not os.path.exists(self.log_file): return
        if initial:
            self.all_alerts = []
            self.last_size = 0
            self.tree.delete(*self.tree.get_children())
        try:
            with open(self.log_file, "r") as f:
                if not initial: f.seek(self.last_size)
                lines = f.readlines()
                self.last_size = f.tell()

                new_alerts = []
                for line in lines:
                    parts = line.strip().split(' - ', 2)
                    if len(parts) == 3:
                        time, level, msg = parts
                        if level in ("WARNING", "ERROR", "CRITICAL", "INFO") and (f"user_id={self.user_id}" in msg or "user_id" not in msg):
                            source_ip = self.extract_ip(msg, "source")
                            dest_ip = self.extract_ip(msg, "destination")
                            attack_type = self.extract_attack_type(msg)
                            new_alerts.append({'time': time, 'level': level, 'message': msg, 'source_ip': source_ip, 'dest_ip': dest_ip, 'attack_type': attack_type})
                
                if new_alerts:
                    self.all_alerts.extend(new_alerts)
                    self.apply_filter()
        except Exception as e:
            print(f"[AlertsPanel] Failed to read alerts: {e}")

    def display_alerts(self, alerts_to_show):
        self.tree.delete(*self.tree.get_children())
        self.filtered_alerts = alerts_to_show
        for alert in alerts_to_show:
            if "blocked" in alert['message'].lower(): action = "Blocked"
            elif "detected" in alert['message'].lower(): action = "Detected"
            else: action = "Monitored"
            self.tree.insert('', 'end', values=(
                alert['level'], alert['time'], alert.get('attack_type') or "Unknown",
                alert.get('source_ip') or "-", alert.get('dest_ip') or "-",
                alert['message'], action), tags=(alert['level'],))
        self.update_stats()
        
    def schedule_refresh(self):
        if self._stopped:
            return
        try:
            self.load_alerts()
        except Exception as e:
            print(f"Alert loading error: {e}")
        try:
            if not self._stopped and hasattr(self, 'master') and self.master.winfo_exists():
                self.master.after(5000, self.schedule_refresh)
        except (tk.TclError, AttributeError):
            # Widget destroyed, stop scheduling
            self._stopped = True

    def show_filter_dialog(self):
        # Create a Toplevel window for the dialog
        filter_window = tk.Toplevel(self.master, bg=ModernStyles.BG_DARK)
        filter_window.title("Advanced Filter")
        filter_window.geometry("500x450")
        filter_window.resizable(False, False)
        filter_window.transient(self.master)
        filter_window.grab_set()
        
        main_frame = ttk.Frame(filter_window, padding=15, style="TFrame")
        main_frame.pack(fill='both', expand=True)

        ttk.Label(main_frame, text="Filter Alerts", style="Title.TLabel").pack(pady=(0, 15), anchor='w')

        # Filter sections using Card.TFrame
        self.create_filter_section(main_frame, "Severity Level", ["INFO", "WARNING", "ERROR", "CRITICAL"])
        self.create_filter_section(main_frame, "Time Range", ["All Time", "Last Hour", "Last Day"])
        self.create_filter_section(main_frame, "IP Address", is_ip_filter=True)
        self.create_filter_section(main_frame, "Attack Type", ["SQL Injection", "XSS", "DDoS", "Brute Force"])

        button_frame = ttk.Frame(main_frame, style="TFrame")
        button_frame.pack(fill='x', pady=15)
        
        ModernStyles.create_button(button_frame, "Apply Filter").pack(side='right', padx=5)
        ModernStyles.create_button(button_frame, "Cancel", is_secondary=True).pack(side='right', padx=5)
        
    def create_filter_section(self, parent, title, options=None, is_ip_filter=False):
        frame = ttk.Frame(parent, style="Card.TFrame", padding=15)
        frame.pack(fill='x', pady=(0, 15))
        ttk.Label(frame, text=title, style="CardTitle.TLabel").pack(anchor='w', pady=(0, 5))
        
        if is_ip_filter:
            ip_frame = ttk.Frame(frame, style="Card.TFrame")
            ip_frame.pack(fill='x')
            ttk.Label(ip_frame, text="Source IP:", style="Card.TLabel").pack(side='left', padx=5)
            ttk.Entry(ip_frame, width=20).pack(side='left', fill='x', expand=True, padx=5)
        elif options:
            options_frame = ttk.Frame(frame, style="Card.TFrame")
            options_frame.pack(fill='x')
            for option in options:
                ttk.Checkbutton(options_frame, text=option, style="TCheckbutton").pack(side='left', padx=5)

    def on_alert_double_click(self, event):
        """Handle double-click on alert entry"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            alert_data = item['values']
            if alert_data:
                self.view_alert_details()
    
    def on_right_click(self, event):
        """Show context menu on right-click"""
        # Select the item under the cursor
        item = self.tree.identify('item', event.x, event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def view_alert_details(self):
        """View detailed information about selected alert"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an alert to view details.")
            return
        
        item = self.tree.item(selection[0])
        alert_data = item['values']
        
        details_window = tk.Toplevel(self.master)
        details_window.title("Alert Details")
        details_window.geometry("600x400")
        details_window.configure(bg=ModernStyles.BG_DARK)
        
        # Create details content
        main_frame = ttk.Frame(details_window, style="Card.TFrame", padding=20)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Label(main_frame, text="Alert Details", style="Title.TLabel").pack(anchor='w', pady=(0, 15))
        
        details_text = tk.Text(main_frame, height=15, width=70, 
                              font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_NORMAL),
                              bg=ModernStyles.BG_PANEL, fg=ModernStyles.TEXT_NORMAL,
                              relief='solid', bd=1)
        details_text.pack(fill='both', expand=True)
        
        # Format alert details
        if len(alert_data) >= 7:
            details = f"""Severity: {alert_data[0]}
Timestamp: {alert_data[1]}
Attack Type: {alert_data[2]}
Source IP: {alert_data[3]}
Destination IP: {alert_data[4]}
Alert Message: {alert_data[5]}
Action Taken: {alert_data[6]}"""
        else:
            details = "Alert details not available"
        
        details_text.insert('1.0', details)
        details_text.config(state='disabled')
    
    def block_source_ip(self):
        """Block the source IP of selected alert"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an alert to block its source IP.")
            return
        
        item = self.tree.item(selection[0])
        alert_data = item['values']
        
        if len(alert_data) >= 4 and alert_data[3] != "-":
            source_ip = alert_data[3]
            result = messagebox.askyesno("Block IP", f"Block source IP {source_ip}?")
            if result:
                try:
                    from backend.firewall import block_ip_manual
                    block_ip_manual(source_ip, self.user_id)
                    messagebox.showinfo("IP Blocked", f"IP {source_ip} has been blocked.")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to block IP: {str(e)}")
        else:
            messagebox.showwarning("No Source IP", "No valid source IP found for this alert.")
    
    def copy_alert(self):
        """Copy selected alert to clipboard"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an alert to copy.")
            return
        
        item = self.tree.item(selection[0])
        alert_data = item['values']
        
        if alert_data:
            alert_text = "\t".join(str(val) for val in alert_data)
            self.master.clipboard_clear()
            self.master.clipboard_append(alert_text)
            messagebox.showinfo("Copied", "Alert copied to clipboard.")
    
    def quick_filter(self, filter_type):
        """Apply quick filter"""
        if filter_type == 'CRITICAL':
            filtered = [alert for alert in self.all_alerts if alert.get('level') == 'CRITICAL']
        elif filter_type == 'attack':
            filtered = [alert for alert in self.all_alerts if 'attack' in alert.get('message', '').lower()]
        elif filter_type == 'today':
            today = datetime.now().strftime('%Y-%m-%d')
            filtered = [alert for alert in self.all_alerts if today in alert.get('time', '')]
        else:
            filtered = self.all_alerts
        
        self.display_alerts(filtered)
        self.filter_indicator.config(text=f"Filter: {filter_type}" if filter_type else "")
    
    def clear_filter(self):
        """Clear all filters"""
        self.display_alerts(self.all_alerts)
        self.filter_indicator.config(text="")
    
    def export_alerts(self):
        """Export current alerts to CSV"""
        if not self.filtered_alerts:
            messagebox.showwarning("No Data", "No alerts to export.")
            return
        
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                import csv
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(['Severity', 'Timestamp', 'Attack Type', 'Source IP', 'Dest IP', 'Alert Message', 'Action'])
                    # Write data
                    for alert in self.filtered_alerts:
                        writer.writerow([
                            alert.get('level', ''),
                            alert.get('time', ''),
                            alert.get('attack_type', ''),
                            alert.get('source_ip', ''),
                            alert.get('dest_ip', ''),
                            alert.get('message', ''),
                            'Blocked' if 'blocked' in alert.get('message', '').lower() else 'Detected'
                        ])
                messagebox.showinfo("Export Successful", f"Alerts exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export alerts: {str(e)}")
    
    def sort_column_data(self, col):
        """Sort table by column"""
        # Toggle sort direction
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_reverse = False
        self.sort_column = col
        
        # Sort the filtered alerts
        if col == 'timestamp':
            self.filtered_alerts.sort(key=lambda x: x.get('time', ''), reverse=self.sort_reverse)
        elif col == 'severity':
            severity_order = {'INFO': 0, 'WARNING': 1, 'ERROR': 2, 'CRITICAL': 3}
            self.filtered_alerts.sort(key=lambda x: severity_order.get(x.get('level', ''), 0), reverse=self.sort_reverse)
        elif col == 'source_ip':
            self.filtered_alerts.sort(key=lambda x: x.get('source_ip', ''), reverse=self.sort_reverse)
        
        # Redisplay sorted alerts
        self.display_alerts(self.filtered_alerts)
    
    def extract_ip(self, message, ip_type):
        """Extract IP address from log message"""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, message)
        return ips[0] if ips else "-"
    
    def extract_attack_type(self, message):
        """Extract attack type from log message"""
        message_lower = message.lower()
        if 'malicious' in message_lower or 'attack' in message_lower:
            return 'Malicious Activity'
        elif 'blocked' in message_lower:
            return 'IP Block'
        elif 'failed' in message_lower and 'login' in message_lower:
            return 'Failed Login'
        elif 'intrusion' in message_lower:
            return 'Intrusion Attempt'
        else:
            return 'Security Event'
    
    def update_stats(self):
        """Update statistics display"""
        total = len(self.filtered_alerts)
        critical = len([a for a in self.filtered_alerts if a.get('level') == 'CRITICAL'])
        blocked = len([a for a in self.filtered_alerts if 'blocked' in a.get('message', '').lower()])
        
        stats_text = f"Total: {total} alerts | Critical: {critical} | Blocked: {blocked}"
        self.stats_label.config(text=stats_text)
    
    def clear_all_alerts(self):
        """Clear all alerts from the system"""
        result = messagebox.askyesno("Clear All Alerts", 
                                   "Are you sure you want to clear all alerts?\n\nThis will remove all alert history and cannot be undone.")
        if result:
            try:
                # Clear the log file
                if os.path.exists(self.log_file):
                    with open(self.log_file, 'w') as f:
                        f.write("")
                
                # Clear internal data
                self.all_alerts = []
                self.filtered_alerts = []
                self.last_size = 0
                
                # Clear the display
                self.tree.delete(*self.tree.get_children())
                self.update_stats()
                self.filter_indicator.config(text="")
                
                messagebox.showinfo("Alerts Cleared", "All security alerts have been cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear alerts: {str(e)}")
    
    def apply_filter(self):
        """Apply current filter to display alerts"""
        if not self.current_filter:
            self.display_alerts(self.all_alerts)
            return
            
        filtered = []
        for alert in self.all_alerts:
            if self.current_filter == 'CRITICAL' and alert['level'] == 'CRITICAL':
                filtered.append(alert)
            elif self.current_filter == 'attack' and ('attack' in alert['message'].lower() or 'blocked' in alert['message'].lower()):
                filtered.append(alert)
            elif self.current_filter == 'today':
                try:
                    alert_date = datetime.strptime(alert['time'].split('.')[0], '%Y-%m-%d %H:%M:%S')
                    if alert_date.date() == datetime.now().date():
                        filtered.append(alert)
                except:
                    pass
        self.display_alerts(filtered)
    
    def destroy(self):
        """Cleanup resources when panel is destroyed"""
        try:
            self._stopped = True
        except Exception as e:
            print(f"Alert panel cleanup error: {e}")
