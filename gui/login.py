# File: gui/login.py
import tkinter as tk
from tkinter import ttk, messagebox
from backend.auth import authenticate_user, add_user
from gui.dashboard import DashboardWindow
from gui.styles import ModernStyles
import time

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced IDS/IPS - Login")
        self.root.geometry("900x600")
        
        # Apply the new "SOC Pro Theme"
        self.style = ModernStyles.apply(root)
        
        # This single frame is the main login card, styled with "Card.TFrame".
        center_frame = ttk.Frame(self.root, style="Card.TFrame", padding=(40, 30))
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # --- Widgets INSIDE the Card ---

        # Title & Subtitle
        title_label = ttk.Label(center_frame, text="Advanced IDS/IPS", style="CardSubtitle.TLabel", foreground=ModernStyles.TEXT_NORMAL)
        title_label.pack(pady=(0, 5))

        subtitle_frame = ttk.Frame(center_frame, style="Card.TFrame", relief="solid", borderwidth=1, padding=(10, 5))
        subtitle_frame.pack(pady=(0, 40))
        subtitle_label = ttk.Label(subtitle_frame, text="Security Management System", style="Card.TLabel")
        subtitle_label.pack()

        # Username
        username_label = ttk.Label(center_frame, text="👤 Username", style="Card.TLabel")
        username_label.pack(anchor="w", padx=5, pady=(0, 5))
        self.username_entry = ttk.Entry(center_frame, width=40, font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_NORMAL))
        self.username_entry.pack(fill='x', pady=(0, 15))
        
        # Password
        password_label = ttk.Label(center_frame, text="🔒 Password", style="Card.TLabel")
        password_label.pack(anchor="w", padx=5, pady=(0, 5))
        self.password_entry = ttk.Entry(center_frame, show="*", width=40, font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_NORMAL))
        self.password_entry.pack(fill='x', pady=(0, 10))
        self.password_entry.bind("<Return>", lambda e: self.login())
        
        # Status message
        self.status_label = ttk.Label(center_frame, text="", style="Card.TLabel", font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_SMALL))
        self.status_label.pack(anchor='w', pady=(10, 0))
        
        # Buttons Frame
        button_frame = ttk.Frame(center_frame, style="Card.TFrame")
        button_frame.pack(fill='x', pady=(25, 10))
        
        self.login_button = ModernStyles.create_button(button_frame, text="Login", command=self.login)
        self.login_button.pack(side='left', fill='x', expand=True, ipady=4, padx=(0, 5))
        
        self.register_button = ModernStyles.create_button(button_frame, text="Register", command=self.register, is_secondary=True)
        self.register_button.pack(side='right', fill='x', expand=True, ipady=4, padx=(5, 0))

    def login(self):
        user = self.username_entry.get().strip()
        pw = self.password_entry.get().strip()
        
        if not user or not pw:
            self.status_label.config(text="⚠️ Both fields are required", foreground=ModernStyles.WARNING_COLOR)
            return

        self.status_label.config(text="🔄 Authenticating...", foreground=ModernStyles.TEXT_MUTED)
        self.root.update()
        time.sleep(0.5)
        
        uid = authenticate_user(user, pw)
        if not uid:
            self.password_entry.delete(0, tk.END)
            self.status_label.config(text="❌ Invalid credentials", foreground=ModernStyles.DANGER_COLOR)
            return

        self.status_label.config(text="✅ Login successful", foreground=ModernStyles.SUCCESS_COLOR)
        self.root.update()
        time.sleep(0.5)
        
        # Destroy all widgets in the root window to prepare for the dashboard
        for widget in self.root.winfo_children():
            widget.destroy()
            
        DashboardWindow(self.root, uid)

    def register(self):
        user = self.username_entry.get().strip()
        pw = self.password_entry.get().strip()
        
        if not user or not pw:
            self.status_label.config(text="⚠️ Both fields are required", foreground=ModernStyles.WARNING_COLOR)
            return
            
        self.status_label.config(text="🔄 Registering new user...", foreground=ModernStyles.TEXT_MUTED)
        self.root.update()
        time.sleep(0.5)
        
        if add_user(user, pw):
            messagebox.showinfo("Success", "Registration successful. You can now log in.")
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.status_label.config(text="")
        else:
            messagebox.showerror("Error", "Username already exists. Please choose another.")
            self.status_label.config(text="❌ Username taken", foreground=ModernStyles.DANGER_COLOR)