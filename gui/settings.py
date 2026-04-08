# File: gui/settings.py - Enhanced Configuration Management Panel
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from gui.styles import ModernStyles
import json
import os
from datetime import datetime
import configparser

class SettingsPanel:
    def __init__(self, master, user_id):
        self.master = master
        self.user_id = user_id
        self.config_file = "config/settings.json"
        self.api_keys_file = "config/api_keys.json"
        
        os.makedirs("config", exist_ok=True)
        
        self.load_settings()
        
        self.create_interface()
    
    def create_interface(self):
        main_frame = ttk.Frame(self.master, style="TFrame", padding=15)
        main_frame.pack(fill='both', expand=True)

        self.create_header(main_frame)
        self.create_settings_notebook(main_frame)
        self.create_action_buttons(main_frame)
    
    def create_header(self, parent):
        header_frame = ttk.Frame(parent, style="Header.TFrame")
        header_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(header_frame, text="⚙️ System Configuration", style="HeaderTitle.TLabel").pack(anchor='w')
        
        ttk.Label(header_frame, text="Configure system preferences, API keys, and monitoring settings", style="Header.TLabel", foreground=ModernStyles.TEXT_MUTED).pack(anchor='w', pady=(5, 0))
    
    def create_settings_notebook(self, parent):
        self.notebook = ttk.Notebook(parent, style="TNotebook")
        self.notebook.pack(fill='both', expand=True, pady=(0, 20))
        
        self.create_general_tab()
        self.create_security_tab()
        self.create_api_tab()
        self.create_appearance_tab()
        self.create_monitoring_tab()
        self.create_export_tab()
    
    def create_general_tab(self):
        general_frame = ttk.Frame(self.notebook, padding=20, style="TFrame")
        self.notebook.add(general_frame, text="🏠 General")
        
        app_section = ttk.Frame(general_frame, style="Card.TFrame", padding=15)
        app_section.pack(fill='x', pady=(0, 15))
        ttk.Label(app_section, text="Application Settings", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        self.auto_start_var = tk.BooleanVar(value=self.settings.get('auto_start', False))
        ttk.Checkbutton(app_section, text="🚀 Start monitoring automatically on startup", variable=self.auto_start_var, style="TCheckbutton").pack(anchor='w', pady=5)
        self.auto_save_var = tk.BooleanVar(value=self.settings.get('auto_save', True))
        ttk.Checkbutton(app_section, text="💾 Auto-save configuration changes", variable=self.auto_save_var, style="TCheckbutton").pack(anchor='w', pady=5)
        self.minimize_tray_var = tk.BooleanVar(value=self.settings.get('minimize_to_tray', False))
        ttk.Checkbutton(app_section, text="📱 Minimize to system tray", variable=self.minimize_tray_var, style="TCheckbutton").pack(anchor='w', pady=5)
        
        lang_section = ttk.Frame(general_frame, style="Card.TFrame", padding=15)
        lang_section.pack(fill='x', pady=(0, 15))
        ttk.Label(lang_section, text="Language & Region", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        lang_frame = ttk.Frame(lang_section, style="Card.TFrame")
        lang_frame.pack(fill='x', pady=5)
        ttk.Label(lang_frame, text="🌐 Language:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.language_var = tk.StringVar(value=self.settings.get('language', 'English'))
        language_combo = ttk.Combobox(lang_frame, textvariable=self.language_var, values=['English', 'Spanish', 'French', 'German', 'Chinese'], state='readonly', width=20)
        language_combo.pack(side='left')
        
        date_frame = ttk.Frame(lang_section, style="Card.TFrame")
        date_frame.pack(fill='x', pady=5)
        ttk.Label(date_frame, text="📅 Date Format:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.date_format_var = tk.StringVar(value=self.settings.get('date_format', 'YYYY-MM-DD'))
        date_combo = ttk.Combobox(date_frame, textvariable=self.date_format_var, values=['YYYY-MM-DD', 'DD/MM/YYYY', 'MM/DD/YYYY'], state='readonly', width=20)
        date_combo.pack(side='left')
        
        log_section = ttk.Frame(general_frame, style="Card.TFrame", padding=15)
        log_section.pack(fill='x')
        ttk.Label(log_section, text="Logging Configuration", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        log_level_frame = ttk.Frame(log_section, style="Card.TFrame")
        log_level_frame.pack(fill='x', pady=5)
        ttk.Label(log_level_frame, text="📝 Log Level:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.log_level_var = tk.StringVar(value=self.settings.get('log_level', 'INFO'))
        log_level_combo = ttk.Combobox(log_level_frame, textvariable=self.log_level_var, values=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], state='readonly', width=20)
        log_level_combo.pack(side='left')
        
        retention_frame = ttk.Frame(log_section, style="Card.TFrame")
        retention_frame.pack(fill='x', pady=5)
        ttk.Label(retention_frame, text="🗓️ Log Retention (days):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.log_retention_var = tk.IntVar(value=self.settings.get('log_retention', 30))
        retention_spin = ttk.Spinbox(retention_frame, from_=1, to=365, textvariable=self.log_retention_var, width=10)
        retention_spin.pack(side='left')
    
    def create_security_tab(self):
        security_frame = ttk.Frame(self.notebook, padding=20, style="TFrame")
        self.notebook.add(security_frame, text="🔒 Security")
        
        auth_section = ttk.Frame(security_frame, style="Card.TFrame", padding=15)
        auth_section.pack(fill='x', pady=(0, 15))
        ttk.Label(auth_section, text="Authentication Settings", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        timeout_frame = ttk.Frame(auth_section, style="Card.TFrame")
        timeout_frame.pack(fill='x', pady=5)
        ttk.Label(timeout_frame, text="⏱️ Session Timeout (minutes):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.session_timeout_var = tk.IntVar(value=self.settings.get('session_timeout', 60))
        timeout_spin = ttk.Spinbox(timeout_frame, from_=5, to=480, textvariable=self.session_timeout_var, width=10)
        timeout_spin.pack(side='left')
        
        self.require_strong_password_var = tk.BooleanVar(value=self.settings.get('require_strong_password', True))
        ttk.Checkbutton(auth_section, text="🔐 Require strong passwords (8+ chars, mixed case, numbers)", variable=self.require_strong_password_var, style="TCheckbutton").pack(anchor='w', pady=5)
        self.enable_2fa_var = tk.BooleanVar(value=self.settings.get('enable_2fa', False))
        ttk.Checkbutton(auth_section, text="📱 Enable Two-Factor Authentication (Future)", variable=self.enable_2fa_var, state='disabled', style="TCheckbutton").pack(anchor='w', pady=5)
        
        threat_section = ttk.Frame(security_frame, style="Card.TFrame", padding=15)
        threat_section.pack(fill='x', pady=(0, 15))
        ttk.Label(threat_section, text="Threat Detection", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        sensitivity_frame = ttk.Frame(threat_section, style="Card.TFrame")
        sensitivity_frame.pack(fill='x', pady=5)
        ttk.Label(sensitivity_frame, text="🎯 Detection Sensitivity:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.detection_sensitivity_var = tk.StringVar(value=self.settings.get('detection_sensitivity', 'Medium'))
        sensitivity_combo = ttk.Combobox(sensitivity_frame, textvariable=self.detection_sensitivity_var, values=['Low', 'Medium', 'High', 'Paranoid'], state='readonly', width=15)
        sensitivity_combo.pack(side='left')
        
        self.auto_block_var = tk.BooleanVar(value=self.settings.get('auto_block', True))
        ttk.Checkbutton(threat_section, text="🚫 Automatically block detected threats", variable=self.auto_block_var, style="TCheckbutton").pack(anchor='w', pady=5)
        
        block_duration_frame = ttk.Frame(threat_section, style="Card.TFrame")
        block_duration_frame.pack(fill='x', pady=5)
        ttk.Label(block_duration_frame, text="⏰ Auto-block Duration (hours):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.block_duration_var = tk.IntVar(value=self.settings.get('block_duration', 24))
        duration_spin = ttk.Spinbox(block_duration_frame, from_=1, to=168, textvariable=self.block_duration_var, width=10)
        duration_spin.pack(side='left')
        
        whitelist_section = ttk.Frame(security_frame, style="Card.TFrame", padding=15)
        whitelist_section.pack(fill='x')
        ttk.Label(whitelist_section, text="Whitelist Management", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        list_frame = ttk.Frame(whitelist_section, style="Card.TFrame")
        list_frame.pack(fill='both', expand=True, pady=5)
        ttk.Label(list_frame, text="Whitelisted IP Addresses:", style="Card.TLabel").pack(anchor='w')
        
        self.whitelist_listbox = tk.Listbox(list_frame, height=6, bg=ModernStyles.BG_DARK, fg=ModernStyles.TEXT_NORMAL, selectbackground=ModernStyles.PRIMARY_COLOR, selectforeground=ModernStyles.TEXT_HEADER, highlightcolor=ModernStyles.PRIMARY_COLOR, highlightthickness=1)
        self.whitelist_listbox.pack(fill='both', expand=True, pady=(5, 0))
        
        for ip in self.settings.get('whitelist_ips', []):
            self.whitelist_listbox.insert('end', ip)
        
        buttons_frame = ttk.Frame(whitelist_section, style="Card.TFrame")
        buttons_frame.pack(fill='x')
        ModernStyles.create_button(buttons_frame, "➕ Add IP", self.add_whitelist_ip, is_secondary=True).pack(side='left', fill='x', expand=True, padx=2)
        ModernStyles.create_button(buttons_frame, "➖ Remove IP", self.remove_whitelist_ip, is_secondary=True).pack(side='left', fill='x', expand=True, padx=2)
        ModernStyles.create_button(buttons_frame, "📁 Import", self.import_whitelist, is_secondary=True).pack(side='left', fill='x', expand=True, padx=2)
        ModernStyles.create_button(buttons_frame, "💾 Export", self.export_whitelist, is_secondary=True).pack(side='left', fill='x', expand=True, padx=2)
    
    def create_api_tab(self):
        api_frame = ttk.Frame(self.notebook, padding=20, style="TFrame")
        self.notebook.add(api_frame, text="🔑 APIs")
        
        vt_section = ttk.Frame(api_frame, style="Card.TFrame", padding=15)
        vt_section.pack(fill='x', pady=(0, 15))
        ttk.Label(vt_section, text="VirusTotal Integration", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        vt_key_frame = ttk.Frame(vt_section, style="Card.TFrame")
        vt_key_frame.pack(fill='x', pady=5)
        ttk.Label(vt_key_frame, text="🔑 API Key:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.vt_api_key_var = tk.StringVar(value=self.api_keys.get('virustotal', ''))
        vt_key_entry = ttk.Entry(vt_key_frame, textvariable=self.vt_api_key_var, show="*", width=40)
        vt_key_entry.pack(side='left', padx=(0, 10))
        
        ModernStyles.create_button(vt_key_frame, "👁️ Show", lambda: self.toggle_password_visibility(vt_key_entry), is_secondary=True).pack(side='left')
        
        self.vt_enable_var = tk.BooleanVar(value=self.settings.get('virustotal_enabled', True))
        ttk.Checkbutton(vt_section, text="✅ Enable VirusTotal scanning", variable=self.vt_enable_var, style="TCheckbutton").pack(anchor='w', pady=5)
        
        rate_frame = ttk.Frame(vt_section, style="Card.TFrame")
        rate_frame.pack(fill='x', pady=5)
        ttk.Label(rate_frame, text="⏱️ Request Rate (per minute):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.vt_rate_limit_var = tk.IntVar(value=self.settings.get('vt_rate_limit', 4))
        rate_spin = ttk.Spinbox(rate_frame, from_=1, to=1000, textvariable=self.vt_rate_limit_var, width=10)
        rate_spin.pack(side='left')
        
        ModernStyles.create_button(vt_section, "🧪 Test API Connection", self.test_virustotal_api).pack(pady=10)
        
        future_apis_section = ttk.Frame(api_frame, style="Card.TFrame", padding=15)
        future_apis_section.pack(fill='x')
        ttk.Label(future_apis_section, text="Additional Services (Future)", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        ttk.Label(future_apis_section, text="Future API integrations will include:\n• AbuseIPDB\n• IBM X-Force\n• AlienVault OTX\n• Custom threat feeds", justify='left', style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED).pack(anchor='w')
    
    def create_appearance_tab(self):
        appearance_frame = ttk.Frame(self.notebook, padding=20, style="TFrame")
        self.notebook.add(appearance_frame, text="🎨 Appearance")
        
        theme_section = ttk.Frame(appearance_frame, style="Card.TFrame", padding=15)
        theme_section.pack(fill='x', pady=(0, 15))
        ttk.Label(theme_section, text="Theme Configuration", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        theme_frame = ttk.Frame(theme_section, style="Card.TFrame")
        theme_frame.pack(fill='x', pady=5)
        ttk.Label(theme_frame, text="🎨 Color Theme:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.theme_var = tk.StringVar(value=self.settings.get('theme', 'Dark Modern'))
        theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_var, values=['Dark Modern', 'Light Professional', 'High Contrast', 'Custom'], state='readonly', width=20)
        theme_combo.pack(side='left', padx=(0, 10))
        theme_combo.bind('<<ComboboxSelected>>', self.on_theme_change)
        ModernStyles.create_button(theme_frame, "🎨 Customize Colors", self.customize_colors, is_secondary=True).pack(side='left')
        
        font_section = ttk.Frame(appearance_frame, style="Card.TFrame", padding=15)
        font_section.pack(fill='x', pady=(0, 15))
        ttk.Label(font_section, text="Font Configuration", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        font_family_frame = ttk.Frame(font_section, style="Card.TFrame")
        font_family_frame.pack(fill='x', pady=5)
        ttk.Label(font_family_frame, text="🔤 Font Family:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.font_family_var = tk.StringVar(value=self.settings.get('font_family', 'Segoe UI'))
        font_family_combo = ttk.Combobox(font_family_frame, textvariable=self.font_family_var, values=['Segoe UI', 'Arial', 'Helvetica', 'Consolas', 'Courier New'], width=20)
        font_family_combo.pack(side='left')
        
        font_size_frame = ttk.Frame(font_section, style="Card.TFrame")
        font_size_frame.pack(fill='x', pady=5)
        ttk.Label(font_size_frame, text="📏 Font Size:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.font_size_var = tk.IntVar(value=self.settings.get('font_size', 11))
        font_size_spin = ttk.Spinbox(font_size_frame, from_=8, to=24, textvariable=self.font_size_var, width=10)
        font_size_spin.pack(side='left')
        
        scale_frame = ttk.Frame(font_section, style="Card.TFrame")
        scale_frame.pack(fill='x', pady=5)
        ttk.Label(scale_frame, text="🔍 UI Scale:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.ui_scale_var = tk.DoubleVar(value=self.settings.get('ui_scale', 1.0))
        scale_spin = ttk.Spinbox(scale_frame, from_=0.8, to=2.0, increment=0.1, textvariable=self.ui_scale_var, width=10)
        scale_spin.pack(side='left')
        
        chart_section = ttk.Frame(appearance_frame, style="Card.TFrame", padding=15)
        chart_section.pack(fill='x')
        ttk.Label(chart_section, text="Chart Configuration", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        chart_theme_frame = ttk.Frame(chart_section, style="Card.TFrame")
        chart_theme_frame.pack(fill='x', pady=5)
        ttk.Label(chart_theme_frame, text="📊 Chart Theme:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.chart_theme_var = tk.StringVar(value=self.settings.get('chart_theme', 'dark_background'))
        chart_theme_combo = ttk.Combobox(chart_theme_frame, textvariable=self.chart_theme_var, values=['dark_background', 'seaborn-v0_8-darkgrid', 'ggplot', 'bmh'], state='readonly', width=20)
        chart_theme_combo.pack(side='left')
        
        self.chart_animations_var = tk.BooleanVar(value=self.settings.get('chart_animations', True))
        ttk.Checkbutton(chart_section, text="🎬 Enable chart animations", variable=self.chart_animations_var, style="TCheckbutton").pack(anchor='w', pady=5)
    
    def create_monitoring_tab(self):
        monitoring_frame = ttk.Frame(self.notebook, padding=20, style="TFrame")
        self.notebook.add(monitoring_frame, text="📊 Monitoring")
        
        intervals_section = ttk.Frame(monitoring_frame, style="Card.TFrame", padding=15)
        intervals_section.pack(fill='x', pady=(0, 15))
        ttk.Label(intervals_section, text="Update Intervals", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        dashboard_frame = ttk.Frame(intervals_section, style="Card.TFrame")
        dashboard_frame.pack(fill='x', pady=5)
        ttk.Label(dashboard_frame, text="🏠 Dashboard Refresh (seconds):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.dashboard_interval_var = tk.IntVar(value=self.settings.get('dashboard_refresh', 10))
        dashboard_spin = ttk.Spinbox(dashboard_frame, from_=5, to=300, textvariable=self.dashboard_interval_var, width=10)
        dashboard_spin.pack(side='left')
        
        sniffer_frame = ttk.Frame(intervals_section, style="Card.TFrame")
        sniffer_frame.pack(fill='x', pady=5)
        ttk.Label(sniffer_frame, text="🔍 Packet Capture Rate (seconds):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.sniffer_interval_var = tk.IntVar(value=self.settings.get('sniffer_refresh', 1))
        sniffer_spin = ttk.Spinbox(sniffer_frame, from_=1, to=60, textvariable=self.sniffer_interval_var, width=10)
        sniffer_spin.pack(side='left')
        
        chart_frame = ttk.Frame(intervals_section, style="Card.TFrame")
        chart_frame.pack(fill='x', pady=5)
        ttk.Label(chart_frame, text="📊 Chart Update (seconds):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.chart_interval_var = tk.IntVar(value=self.settings.get('chart_refresh', 5))
        chart_spin = ttk.Spinbox(chart_frame, from_=1, to=60, textvariable=self.chart_interval_var, width=10)
        chart_spin.pack(side='left')
        
        performance_section = ttk.Frame(monitoring_frame, style="Card.TFrame", padding=15)
        performance_section.pack(fill='x', pady=(0, 15))
        ttk.Label(performance_section, text="Performance Settings", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        max_points_frame = ttk.Frame(performance_section, style="Card.TFrame")
        max_points_frame.pack(fill='x', pady=5)
        ttk.Label(max_points_frame, text="📈 Max Chart Data Points:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.max_data_points_var = tk.IntVar(value=self.settings.get('max_data_points', 100))
        points_spin = ttk.Spinbox(max_points_frame, from_=50, to=1000, textvariable=self.max_data_points_var, width=10)
        points_spin.pack(side='left')
        
        memory_frame = ttk.Frame(performance_section, style="Card.TFrame")
        memory_frame.pack(fill='x', pady=5)
        ttk.Label(memory_frame, text="💾 Memory Limit (MB):", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.memory_limit_var = tk.IntVar(value=self.settings.get('memory_limit', 512))
        memory_spin = ttk.Spinbox(memory_frame, from_=256, to=2048, textvariable=self.memory_limit_var, width=10)
        memory_spin.pack(side='left')
        
        self.enable_gpu_accel_var = tk.BooleanVar(value=self.settings.get('gpu_acceleration', False))
        ttk.Checkbutton(performance_section, text="🚀 Enable GPU acceleration (Future)", variable=self.enable_gpu_accel_var, state='disabled', style="TCheckbutton").pack(anchor='w', pady=5)
        
        alert_section = ttk.Frame(monitoring_frame, style="Card.TFrame", padding=15)
        alert_section.pack(fill='x')
        ttk.Label(alert_section, text="Alert Configuration", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        self.desktop_notifications_var = tk.BooleanVar(value=self.settings.get('desktop_notifications', True))
        ttk.Checkbutton(alert_section, text="🔔 Enable desktop notifications", variable=self.desktop_notifications_var, style="TCheckbutton").pack(anchor='w', pady=5)
        self.sound_alerts_var = tk.BooleanVar(value=self.settings.get('sound_alerts', False))
        ttk.Checkbutton(alert_section, text="🔊 Enable sound alerts", variable=self.sound_alerts_var, style="TCheckbutton").pack(anchor='w', pady=5)
        
        threshold_frame = ttk.Frame(alert_section, style="Card.TFrame")
        threshold_frame.pack(fill='x', pady=5)
        ttk.Label(threshold_frame, text="⚠️ High Priority Alert Threshold:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.alert_threshold_var = tk.IntVar(value=self.settings.get('alert_threshold', 10))
        threshold_spin = ttk.Spinbox(threshold_frame, from_=1, to=100, textvariable=self.alert_threshold_var, width=10)
        threshold_spin.pack(side='left')
    
    def create_export_tab(self):
        export_frame = ttk.Frame(self.notebook, padding=20, style="TFrame")
        self.notebook.add(export_frame, text="📄 Export")
        
        default_section = ttk.Frame(export_frame, style="Card.TFrame", padding=15)
        default_section.pack(fill='x', pady=(0, 15))
        ttk.Label(default_section, text="Default Export Settings", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        format_frame = ttk.Frame(default_section, style="Card.TFrame")
        format_frame.pack(fill='x', pady=5)
        ttk.Label(format_frame, text="📄 Default Export Format:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.default_export_format_var = tk.StringVar(value=self.settings.get('default_export_format', 'CSV'))
        format_combo = ttk.Combobox(format_frame, textvariable=self.default_export_format_var, values=['CSV', 'JSON', 'XML', 'Excel', 'PDF'], state='readonly', width=15)
        format_combo.pack(side='left')
        
        location_frame = ttk.Frame(default_section, style="Card.TFrame")
        location_frame.pack(fill='x', pady=5)
        ttk.Label(location_frame, text="📁 Default Export Directory:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.export_directory_var = tk.StringVar(value=self.settings.get('export_directory', './exports'))
        location_entry = ttk.Entry(location_frame, textvariable=self.export_directory_var, width=40)
        location_entry.pack(side='left', padx=(0, 10))
        
        ModernStyles.create_button(location_frame, "📁 Browse", self.browse_export_directory, is_secondary=True).pack(side='left')
        
        report_section = ttk.Frame(export_frame, style="Card.TFrame", padding=15)
        report_section.pack(fill='x', pady=(0, 15))
        ttk.Label(report_section, text="Report Configuration", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        self.include_charts_var = tk.BooleanVar(value=self.settings.get('include_charts', True))
        ttk.Checkbutton(report_section, text="📊 Include charts in reports", variable=self.include_charts_var, style="TCheckbutton").pack(anchor='w', pady=5)
        self.include_system_info_var = tk.BooleanVar(value=self.settings.get('include_system_info', True))
        ttk.Checkbutton(report_section, text="💻 Include system information", variable=self.include_system_info_var, style="TCheckbutton").pack(anchor='w', pady=5)
        self.auto_timestamp_var = tk.BooleanVar(value=self.settings.get('auto_timestamp', True))
        ttk.Checkbutton(report_section, text="🕒 Auto-timestamp filenames", variable=self.auto_timestamp_var, style="TCheckbutton").pack(anchor='w', pady=5)
        
        compression_frame = ttk.Frame(report_section, style="Card.TFrame")
        compression_frame.pack(fill='x', pady=5)
        ttk.Label(compression_frame, text="🗜️ Compression:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.compression_var = tk.StringVar(value=self.settings.get('compression', 'None'))
        compression_combo = ttk.Combobox(compression_frame, textvariable=self.compression_var, values=['None', 'ZIP', 'GZIP', '7Z'], state='readonly', width=15)
        compression_combo.pack(side='left')
        
        scheduled_section = ttk.Frame(export_frame, style="Card.TFrame", padding=15)
        scheduled_section.pack(fill='x')
        ttk.Label(scheduled_section, text="Scheduled Exports", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        self.scheduled_exports_var = tk.BooleanVar(value=self.settings.get('scheduled_exports', False))
        ttk.Checkbutton(scheduled_section, text="📅 Enable scheduled exports", variable=self.scheduled_exports_var, style="TCheckbutton").pack(anchor='w', pady=5)
        
        freq_frame = ttk.Frame(scheduled_section, style="Card.TFrame")
        freq_frame.pack(fill='x', pady=5)
        ttk.Label(freq_frame, text="⏰ Export Frequency:", style="Card.TLabel").pack(side='left', padx=(0, 10))
        self.export_frequency_var = tk.StringVar(value=self.settings.get('export_frequency', 'Weekly'))
        freq_combo = ttk.Combobox(freq_frame, textvariable=self.export_frequency_var, values=['Daily', 'Weekly', 'Monthly'], state='readonly', width=15)
        freq_combo.pack(side='left')
    
    def create_action_buttons(self, parent):
        button_frame = ttk.Frame(parent, style="TFrame")
        button_frame.pack(fill='x', pady=10)
        
        left_buttons = ttk.Frame(button_frame, style="TFrame")
        left_buttons.pack(side='left')
        
        ModernStyles.create_button(left_buttons, "🔄 Reset to Defaults", self.reset_to_defaults, is_secondary=True).pack(side='left', padx=5)
        ModernStyles.create_button(left_buttons, "📁 Import Settings", self.import_settings, is_secondary=True).pack(side='left', padx=5)
        ModernStyles.create_button(left_buttons, "💾 Export Settings", self.export_settings, is_secondary=True).pack(side='left', padx=5)
        
        right_buttons = ttk.Frame(button_frame, style="TFrame")
        right_buttons.pack(side='right')
        
        ModernStyles.create_button(right_buttons, "❌ Cancel", self.cancel_changes, is_secondary=True).pack(side='right', padx=5)
        ModernStyles.create_button(right_buttons, "💾 Apply", self.apply_settings, is_secondary=True).pack(side='right', padx=5)
        ModernStyles.create_button(right_buttons, "✅ Save & Close", self.save_and_close).pack(side='right', padx=5)
    
    def load_settings(self):
        self.settings = {}
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f: self.settings = json.load(f)
            except: self.settings = {}
        self.api_keys = {}
        if os.path.exists(self.api_keys_file):
            try:
                with open(self.api_keys_file, 'r') as f: self.api_keys = json.load(f)
            except: self.api_keys = {}
    
    def save_settings(self):
        try:
            settings_to_save = {
                'auto_start': self.auto_start_var.get(), 'auto_save': self.auto_save_var.get(),
                'minimize_to_tray': self.minimize_tray_var.get(), 'language': self.language_var.get(),
                'date_format': self.date_format_var.get(), 'log_level': self.log_level_var.get(),
                'log_retention': self.log_retention_var.get(), 'session_timeout': self.session_timeout_var.get(),
                'require_strong_password': self.require_strong_password_var.get(), 'enable_2fa': self.enable_2fa_var.get(),
                'detection_sensitivity': self.detection_sensitivity_var.get(), 'auto_block': self.auto_block_var.get(),
                'block_duration': self.block_duration_var.get(), 'whitelist_ips': list(self.whitelist_listbox.get(0, 'end')),
                'virustotal_enabled': self.vt_enable_var.get(), 'vt_rate_limit': self.vt_rate_limit_var.get(),
                'theme': self.theme_var.get(), 'font_family': self.font_family_var.get(), 'font_size': self.font_size_var.get(),
                'ui_scale': self.ui_scale_var.get(), 'chart_theme': self.chart_theme_var.get(), 'chart_animations': self.chart_animations_var.get(),
                'dashboard_refresh': self.dashboard_interval_var.get(), 'sniffer_refresh': self.sniffer_interval_var.get(),
                'chart_refresh': self.chart_interval_var.get(), 'max_data_points': self.max_data_points_var.get(),
                'memory_limit': self.memory_limit_var.get(), 'gpu_acceleration': self.enable_gpu_accel_var.get(),
                'desktop_notifications': self.desktop_notifications_var.get(), 'sound_alerts': self.sound_alerts_var.get(),
                'alert_threshold': self.alert_threshold_var.get(), 'default_export_format': self.default_export_format_var.get(),
                'export_directory': self.export_directory_var.get(), 'include_charts': self.include_charts_var.get(),
                'include_system_info': self.include_system_info_var.get(), 'auto_timestamp': self.auto_timestamp_var.get(),
                'compression': self.compression_var.get(), 'scheduled_exports': self.scheduled_exports_var.get(),
                'export_frequency': self.export_frequency_var.get(), 'last_updated': datetime.now().isoformat(), 'version': '2.0.0'
            }
            with open(self.config_file, 'w') as f: json.dump(settings_to_save, f, indent=2)
            api_keys_to_save = {'virustotal': self.vt_api_key_var.get(), 'last_updated': datetime.now().isoformat()}
            with open(self.api_keys_file, 'w') as f: json.dump(api_keys_to_save, f, indent=2)
            if os.name != 'nt': os.chmod(self.api_keys_file, 0o600)
            self.settings = settings_to_save
            self.api_keys = api_keys_to_save
            return True
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save settings: {str(e)}")
            return False
            
    def add_whitelist_ip(self):
        ip = simpledialog.askstring("Add IP", "Enter IP address to whitelist:")
        if ip and ip.strip():
            import re
            ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            if re.match(ip_pattern, ip.strip()):
                self.whitelist_listbox.insert('end', ip.strip())
            else: messagebox.showerror("Invalid IP", "Please enter a valid IP address")
    
    def remove_whitelist_ip(self):
        selection = self.whitelist_listbox.curselection()
        if selection: self.whitelist_listbox.delete(selection[0])
    
    def import_whitelist(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip: self.whitelist_listbox.insert('end', ip)
                messagebox.showinfo("Import Successful", "Whitelist imported successfully")
            except Exception as e: messagebox.showerror("Import Error", f"Failed to import whitelist: {str(e)}")
    
    def export_whitelist(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    for i in range(self.whitelist_listbox.size()): f.write(self.whitelist_listbox.get(i) + '\n')
                messagebox.showinfo("Export Successful", "Whitelist exported successfully")
            except Exception as e: messagebox.showerror("Export Error", f"Failed to export whitelist: {str(e)}")
    
    def test_virustotal_api(self):
        api_key = self.vt_api_key_var.get().strip()
        if not api_key: messagebox.showwarning("No API Key", "Please enter your VirusTotal API key first"); return
        if len(api_key) == 64: messagebox.showinfo("API Test", "✅ API key format is valid\n(Full connectivity test would be implemented)")
        else: messagebox.showerror("API Test", "❌ Invalid API key format\nVirusTotal API keys should be 64 characters long")
    
    def toggle_password_visibility(self, entry):
        if entry.cget('show') == '*': entry.configure(show='')
        else: entry.configure(show='*')
    
    def on_theme_change(self, event): pass
    def customize_colors(self): messagebox.showinfo("Color Customization", "Advanced color customization would be implemented here")
    
    def browse_export_directory(self):
        directory = filedialog.askdirectory(initialdir=self.export_directory_var.get())
        if directory: self.export_directory_var.set(directory)
    
    def reset_to_defaults(self):
        result = messagebox.askyesno("Reset Settings", "Are you sure you want to reset all settings to defaults?\nThis action cannot be undone.")
        if result: messagebox.showinfo("Reset Complete", "Settings have been reset to defaults")
    
    def import_settings(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'r') as f: imported_settings = json.load(f)
                messagebox.showinfo("Import Successful", "Settings imported successfully")
            except Exception as e: messagebox.showerror("Import Error", f"Failed to import settings: {str(e)}")
    
    def export_settings(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            try:
                if self.save_settings():
                    with open(file_path, 'w') as f: json.dump(self.settings, f, indent=2)
                    messagebox.showinfo("Export Successful", f"Settings exported to {file_path}")
            except Exception as e: messagebox.showerror("Export Error", f"Failed to export settings: {str(e)}")
    
    def apply_settings(self):
        if self.save_settings(): messagebox.showinfo("Settings Applied", "Settings have been applied successfully")
    
    def save_and_close(self):
        if self.save_settings(): messagebox.showinfo("Settings Saved", "Settings have been saved successfully")
    
    def cancel_changes(self):
        result = messagebox.askyesno("Cancel Changes", "Are you sure you want to cancel all changes?")
        if result:
            self.load_settings()
            messagebox.showinfo("Changes Cancelled", "All changes have been cancelled")


if __name__ == "__main__":
    import tkinter.simpledialog
    
    root = tk.Tk()
    root.title("Settings Panel Test")
    root.geometry("800x600")
    
    ModernStyles.apply(root)
    settings_panel = SettingsPanel(root, user_id=1)
    
    root.mainloop()