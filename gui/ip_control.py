# File: gui/ip_control.py
import tkinter as tk
from tkinter import ttk, messagebox
from backend.firewall import block_ip_manual, unblock_ip_manual
from backend.virustotal import check_ip, get_formatted_report
import mysql.connector
import yaml
from datetime import datetime
from gui.styles import ModernStyles

# Load DB config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

mysql_cfg = config['mysql']


class IPControlPanel:
    def __init__(self, master, user_id):
        self.master = master
        self.user_id = user_id
        
        # Main container with a 2-column grid layout
        self.container = ttk.Frame(master, style="TFrame")
        self.container.pack(fill='both', expand=True)
        self.container.columnconfigure(0, weight=1)
        self.container.columnconfigure(1, weight=2) # Table gets more space
        self.container.rowconfigure(1, weight=1)
        
        # Title
        self.title = ttk.Label(self.container, text="🚦 Network Control Panel", style="Title.TLabel")
        self.title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))
        
        # Left column - IP controls in a card
        self.left_frame = ttk.Frame(self.container, style="Card.TFrame", padding=20)
        self.left_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        
        # IP input section
        ttk.Label(self.left_frame, text="IP Address to Check / Manage", style="Card.TLabel").pack(anchor='w')
        
        ip_entry_frame = ttk.Frame(self.left_frame, style="Card.TFrame")
        ip_entry_frame.pack(fill='x', pady=5)
        
        self.ip_entry = ttk.Entry(ip_entry_frame)
        self.ip_entry.pack(side='left', fill='x', expand=True)
        self.ip_entry.bind("<Return>", lambda event: self.check_ip())
        
        ModernStyles.create_button(ip_entry_frame, "Check", self.check_ip).pack(side='right', padx=(10, 0))
        
        # Action buttons
        button_frame = ttk.Frame(self.left_frame, style="Card.TFrame")
        button_frame.pack(fill='x', pady=15)
        
        ModernStyles.create_button(button_frame, "Block IP", self.block_ip, is_secondary=True).pack(side='left', fill='x', expand=True, padx=(0, 5))
        ModernStyles.create_button(button_frame, "Unblock IP", self.unblock_ip, is_secondary=True).pack(side='left', fill='x', expand=True, padx=(5, 0))
        
        # VirusTotal results section
        ttk.Label(self.left_frame, text="VirusTotal Results", style="Card.TLabel").pack(anchor='w', pady=(10, 5))
        
        self.vt_result = tk.Text(self.left_frame, height=10, width=40, wrap='word', 
                                 font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_NORMAL),
                                 bg=ModernStyles.BG_DARK, fg=ModernStyles.TEXT_NORMAL,
                                 relief="solid", bd=1, highlightthickness=1,
                                 highlightbackground=ModernStyles.BORDER_COLOR,
                                 highlightcolor=ModernStyles.PRIMARY_COLOR)
        self.vt_result.pack(fill='both', expand=True, pady=5)
        self.vt_result.config(state='disabled')

        # Right column - Blocked IPs list in a card
        self.right_frame = ttk.Frame(self.container, style="Card.TFrame", padding=15)
        self.right_frame.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
        self.right_frame.rowconfigure(1, weight=1)
        self.right_frame.columnconfigure(0, weight=1)

        ttk.Label(self.right_frame, text="Currently Blocked IPs", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        tree_container = ttk.Frame(self.right_frame, style="Card.TFrame")
        tree_container.grid(row=1, column=0, sticky="nsew")
        
        self.scrollbar = ttk.Scrollbar(tree_container)
        self.scrollbar.pack(side='right', fill='y')
        
        self.tree = ttk.Treeview(tree_container, columns=('ip', 'reason', 'timestamp'), show='headings', style="Treeview", yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.tree.yview)
        
        self.tree.heading('ip', text='Blocked IP')
        self.tree.heading('reason', text='Reason')
        self.tree.heading('timestamp', text='Blocked At')
        self.tree.column('ip', width=150, anchor='center')
        self.tree.column('reason', width=200, anchor='w')
        self.tree.column('timestamp', width=150, anchor='center')
        self.tree.pack(fill='both', expand=True)
        
        self.load_blocked_ips()

    def get_db_connection(self):
        return mysql.connector.connect(
            host=mysql_cfg['host'],
            user=mysql_cfg['user'],
            password=mysql_cfg['password'],
            database=mysql_cfg['database']
        )

    def block_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IP address.")
            return

        reason = "Manual block by user"
        vt_text = self.vt_result.get(1.0, tk.END).strip()
        if "Malicious" in vt_text and "not malicious" not in vt_text.lower():
            reason = f"VirusTotal: {vt_text.splitlines()[0]}"

        try:
            block_ip_manual(ip, self.user_id)
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO blocked_ips (user_id, ip_address, block_type, reason, is_active) VALUES (%s, %s, %s, %s, %s)",
                (self.user_id, ip, "manual", reason, 1)
            )
            conn.commit()
            conn.close()
            self.load_blocked_ips()
            messagebox.showinfo("IP Control", f"Blocked {ip}")
            self.ip_entry.delete(0, tk.END)
            self.vt_result.config(state='normal')
            self.vt_result.delete(1.0, tk.END)
            self.vt_result.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block IP: {e}")

    def unblock_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IP address.")
            return
        try:
            unblock_ip_manual(ip, self.user_id)
            conn = self.get_db_connection()
            cursor = conn.cursor()
            # Set is_active to 0 for the IP to mark it as inactive/unblocked
            cursor.execute(
                "UPDATE blocked_ips SET is_active = 0 WHERE user_id = %s AND ip_address = %s AND is_active = 1",
                (self.user_id, ip)
            )
            conn.commit()
            conn.close()
            self.load_blocked_ips()
            messagebox.showinfo("IP Control", f"Unblocked {ip}")
            self.ip_entry.delete(0, tk.END)
            self.vt_result.config(state='normal')
            self.vt_result.delete(1.0, tk.END)
            self.vt_result.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock IP: {e}")

    def check_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showwarning("Input Error", "Please enter an IP address.")
            return
            
        self.vt_result.config(state='normal')
        self.vt_result.delete(1.0, tk.END)
        self.vt_result.insert(tk.END, "Checking IP with VirusTotal...")
        self.vt_result.config(state='disabled')
        self.master.update()
        
        try:
            is_malicious, results = check_ip(ip)
            report = get_formatted_report(ip, results)
            
            self.vt_result.config(state='normal')
            self.vt_result.delete(1.0, tk.END)
            self.vt_result.insert(tk.END, report)
            
            self.vt_result.tag_configure("malicious", foreground=ModernStyles.DANGER_COLOR)
            self.vt_result.tag_configure("clean", foreground=ModernStyles.SUCCESS_COLOR)
            
            if is_malicious:
                self.vt_result.tag_add("malicious", "1.0", "1.end")
            else:
                self.vt_result.tag_add("clean", "1.0", "1.end")
                
        except Exception as e:
            self.vt_result.config(state='normal')
            self.vt_result.delete(1.0, tk.END)
            self.vt_result.insert(tk.END, f"Error checking IP: {str(e)}")
        finally:
            self.vt_result.config(state='disabled')
    
    def load_blocked_ips(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            # Query using the actual database schema
            cursor.execute("SELECT ip_address, reason, blocked_at FROM blocked_ips WHERE user_id = %s AND is_active = 1 ORDER BY blocked_at DESC", (self.user_id,))
            
            for ip, reason, ts in cursor.fetchall():
                self.tree.insert('', tk.END, values=(ip, reason or "Manual block", ts.strftime('%Y-%m-%d %H:%M:%S')))
            conn.close()
        except Exception as e:
            # Table might not exist yet, which is fine on first run
            print("Failed to load blocked IPs:", e)