# File: gui/dashboard.py - Enhanced Industrial-Grade Security Dashboard
import tkinter as tk
from tkinter import ttk
from tkinter import font # <-- ADDED THIS IMPORT
import os
import re
import threading
import time
import psutil
from datetime import datetime
from collections import deque, defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# <<< FIX: Load the Noto Color Emoji font file using pyglet >>>
# Make sure you have run 'pip install pyglet'
try:
    import pyglet
    # This loads the font file from your main project folder
    pyglet.font.add_file("NotoColorEmoji-Regular.ttf")
    print("Noto Color Emoji font loaded successfully.")
    EMOJI_FONT_FAMILY = "Noto Color Emoji"
except Exception as e:
    print(f"Warning: Could not load Noto Color Emoji font. Icons may not display. Error: {e}")
    # Use a fallback font so the app doesn't crash
    EMOJI_FONT_FAMILY = "TkDefaultFont"

from gui.alerts import AlertsPanel
from gui.ip_control import IPControlPanel
from gui.sniffer import SnifferPanel
from gui.settings import SettingsPanel
from gui.styles import ModernStyles
from backend.system_logs import get_system_health, start_system_monitoring

# Set matplotlib style for dark background
try:
    plt.style.use('dark_background')
except Exception:
    pass


class DashboardOverview:
    def __init__(self, master, user_id):
        self.master = master
        self.user_id = user_id
        self.log_file = os.path.join("logs", "system.log")

        # <<< FIX: Create a font object for the emoji icons in the KPI cards >>>
        self.kpi_icon_font = font.Font(family=EMOJI_FONT_FAMILY, size=20)
        
        # Initialize data structures (unchanged)
        self.system_metrics = {
            'cpu_usage': deque(maxlen=50), 'memory_usage': deque(maxlen=50),
            'network_activity': deque(maxlen=50), 'threat_level': deque(maxlen=50),
            'timestamps': deque(maxlen=50)
        }
        self.threat_intelligence = {'total_threats': 0, 'blocked_attacks': 0}
        
        # --- Main Layout ---
        # A scrollable frame ensures the dashboard is usable on smaller screens
        self.canvas = tk.Canvas(master, bg=ModernStyles.BG_DARK, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas, style="TFrame")

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Build the UI components
        self.init_dashboard_components()
        
        # Start background monitoring and UI updates
        self.start_monitoring()
        self.schedule_refresh()
        
        # Initialize system log monitoring
        try:
            start_system_monitoring(self.user_id)
        except Exception as e:
            print(f"Warning: Could not start system monitoring: {e}")
    
    def init_dashboard_components(self):
        """Initialize all dashboard components with the new theme."""
        self.create_kpi_dashboard()
        self.create_monitoring_charts()
        self.create_system_health_section()
        self.create_security_events_section()

    def create_kpi_dashboard(self):
        """Create Key Performance Indicator cards."""
        kpi_frame = ttk.Frame(self.scrollable_frame, padding=10, style="TFrame")
        kpi_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(kpi_frame, text="Key Performance Indicators", style="Title.TLabel").pack(anchor='w', pady=(0, 10))
        
        cards_container = ttk.Frame(kpi_frame, style="TFrame")
        cards_container.pack(fill='x')
        
        for i in range(3):
            cards_container.columnconfigure(i, weight=1)
        
        # <<< FIX: Replace broken text with colorful emoji characters >>>
        self.create_kpi_card(cards_container, "Total Threats Detected", "0", "danger", "🚨", 0, 0)
        self.create_kpi_card(cards_container, "Active Blocks", "0", "warning", "🚫", 0, 1)
        self.create_kpi_card(cards_container, "System Uptime", "0d 00:00:00", "success", "🕒", 0, 2)
        
        self.create_kpi_card(cards_container, "Network Activity", "0 MB/s", "primary", "🌐", 1, 0)
        self.create_kpi_card(cards_container, "CPU Usage", "0%", "primary", "💻", 1, 1)
        self.create_kpi_card(cards_container, "Memory Usage", "0%", "primary", "💾", 1, 2)
        
        # Add last update label
        self.last_update_label = ttk.Label(kpi_frame, text="", style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED)
        self.last_update_label.pack(anchor='w', pady=(10, 0))
    
    def create_kpi_card(self, parent, title, value, status, icon, row, col):
        """Create a modern KPI card using the SOC Pro Theme."""
        card_frame = ttk.Frame(parent, style="Card.TFrame", padding=20)
        card_frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
        
        header_frame = ttk.Frame(card_frame, style="Card.TFrame")
        header_frame.pack(fill='x')
        
        # <<< FIX: Apply the emoji font to the icon label >>>
        icon_label = ttk.Label(header_frame, text=icon, font=self.kpi_icon_font, style="Card.TLabel")
        icon_label.pack(side='left')
        
        title_label = ttk.Label(header_frame, text=title, style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED)
        title_label.pack(side='right')
        
        # Determine the style for the value based on status
        value_style = "Value.TLabel"
        if status == 'danger': value_style = "DangerValue.TLabel"
        elif status == 'warning': value_style = "WarningValue.TLabel"
        elif status == 'success': value_style = "SuccessValue.TLabel"
        
        value_label = ttk.Label(card_frame, text=value, style=value_style)
        value_label.pack(anchor='center', pady=15)
        
        # <<< FIX: Replace broken arrow with an emoji >>>
        trend_label = ttk.Label(card_frame, text="📈 +0.0%", style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED)
        trend_label.pack(anchor='center')
        
        card_name = title.lower().replace(' ', '_')
        setattr(self, f"{card_name}_value", value_label)
        setattr(self, f"{card_name}_trend", trend_label)
    
    def create_monitoring_charts(self):
        """Create real-time monitoring charts using a clean, card-based layout."""
        main_frame = ttk.Frame(self.scrollable_frame, padding=10, style="TFrame")
        main_frame.pack(fill='both', expand=True, pady=(0, 20))

        ttk.Label(main_frame, text="Real-Time System Monitoring", style="Title.TLabel").pack(anchor='w', pady=(0, 15))
        
        charts_container = ttk.Frame(main_frame, style="TFrame")
        charts_container.pack(fill='both', expand=True)
        charts_container.columnconfigure((0, 1), weight=1)
        charts_container.rowconfigure((0, 1), weight=1)
        
        self.create_chart(charts_container, "System Performance", 0, 0, self.setup_performance_chart)
        self.create_chart(charts_container, "Threat Level Indicator", 0, 1, self.setup_threat_chart)
        self.create_chart(charts_container, "Network Activity", 1, 0, self.setup_network_chart)
        self.create_chart(charts_container, "Attack Distribution", 1, 1, self.setup_attack_pie_chart)

    def create_chart(self, parent, title, row, col, setup_func):
        """Generic helper to create a chart card."""
        card = ttk.Frame(parent, style="Card.TFrame", padding=15)
        card.grid(row=row, column=col, sticky="nsew", padx=10, pady=10)
        card.rowconfigure(1, weight=1)
        card.columnconfigure(0, weight=1)
        
        ttk.Label(card, text=title, style="CardTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        fig, ax = plt.subplots(figsize=(5, 3))
        self._style_matplotlib_chart(fig, ax)
        
        canvas = FigureCanvasTkAgg(fig, card)
        canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew")
        
        setup_func(fig, ax, canvas) # Call the specific setup function
        return card

    def _style_matplotlib_chart(self, fig, ax):
        """Apply SOC Pro theme to a matplotlib chart."""
        fig.patch.set_facecolor(ModernStyles.BG_PANEL)
        ax.set_facecolor(ModernStyles.BG_PANEL)
        ax.tick_params(colors=ModernStyles.TEXT_MUTED, which='both')
        ax.grid(True, alpha=0.2, color=ModernStyles.BORDER_COLOR)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color(ModernStyles.BORDER_COLOR)
        ax.spines['left'].set_color(ModernStyles.BORDER_COLOR)
        ax.yaxis.label.set_color(ModernStyles.TEXT_MUTED)
        ax.xaxis.label.set_color(ModernStyles.TEXT_MUTED)

    def setup_performance_chart(self, fig, ax, canvas):
        self.perf_fig, self.perf_ax, self.perf_canvas = fig, ax, canvas
        ax.set_ylabel('Usage (%)')
        ax.set_ylim(0, 100)
        self.cpu_line, = ax.plot([], [], color=ModernStyles.PRIMARY_COLOR, label='CPU', linewidth=2)
        self.mem_line, = ax.plot([], [], color=ModernStyles.WARNING_COLOR, label='Memory', linewidth=2)
        ax.legend(facecolor=ModernStyles.BG_PANEL, edgecolor=ModernStyles.BORDER_COLOR, labelcolor=ModernStyles.TEXT_NORMAL)
        plt.tight_layout(pad=2)

    def setup_threat_chart(self, fig, ax, canvas):
        self.threat_fig, self.threat_ax, self.threat_canvas = fig, ax, canvas
        ax.set_ylabel('Threats/Hour')
        self.threat_line, = ax.plot([], [], color=ModernStyles.DANGER_COLOR, linewidth=2, marker='o', markersize=4)
        plt.tight_layout(pad=2)

    def setup_network_chart(self, fig, ax, canvas):
        self.network_fig, self.network_ax, self.network_canvas = fig, ax, canvas
        ax.set_ylabel('MB/s')
        self.traffic_in_line, = ax.plot([], [], color=ModernStyles.SUCCESS_COLOR, label='Incoming', linewidth=2)
        self.traffic_out_line, = ax.plot([], [], color=ModernStyles.TEXT_NORMAL, label='Outgoing', linewidth=2)
        ax.legend(facecolor=ModernStyles.BG_PANEL, edgecolor=ModernStyles.BORDER_COLOR, labelcolor=ModernStyles.TEXT_NORMAL)
        plt.tight_layout(pad=2)

    def setup_attack_pie_chart(self, fig, ax, canvas):
        self.attack_fig, self.attack_ax, self.attack_canvas = fig, ax, canvas
        ax.pie([1], labels=['No Data'], colors=[ModernStyles.BORDER_COLOR])
        plt.tight_layout(pad=2)
        
    def create_system_health_section(self):
        """Create system health and services status section."""
        main_frame = ttk.Frame(self.scrollable_frame, padding=10, style="TFrame")
        main_frame.pack(fill='x', pady=(0, 20))

        ttk.Label(main_frame, text="System Health & Services", style="Title.TLabel").pack(anchor='w', pady=(0, 15))
        
        health_container = ttk.Frame(main_frame, style="TFrame")
        health_container.pack(fill='x')
        health_container.columnconfigure((0, 1), weight=1)

        services_card = ttk.Frame(health_container, style="Card.TFrame", padding=15)
        services_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        ttk.Label(services_card, text="Services Status", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        self.create_service_status_list(services_card)
        
        metrics_card = ttk.Frame(health_container, style="Card.TFrame", padding=15)
        metrics_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        ttk.Label(metrics_card, text="System Metrics", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        self.create_system_metrics_display(metrics_card)
    
    def create_service_status_list(self, parent):
        """Create service status indicators."""
        services = [("IDS Engine", True), ("VirusTotal API", True), ("Database Connection", True),
                    ("Firewall Integration", True), ("Log Monitoring", True)]
        
        for service, status in services:
            status_frame = ttk.Frame(parent, style="Card.TFrame")
            status_frame.pack(fill='x', pady=5)
            
            status_color = ModernStyles.SUCCESS_COLOR if status else ModernStyles.DANGER_COLOR
            # <<< FIX: Replace broken bullet with a standard one >>>
            ttk.Label(status_frame, text="●", font=("", 16, "bold"), foreground=status_color, style="Card.TLabel").pack(side='left')
            ttk.Label(status_frame, text=service, style="Card.TLabel").pack(side='left', padx=(10, 0))
            ttk.Label(status_frame, text="Running" if status else "Offline", foreground=status_color, style="Card.TLabel").pack(side='right')
    
    def create_system_metrics_display(self, parent):
        """Create system metrics text display."""
        self.metrics_text = tk.Text(parent, height=8, width=40, font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_SMALL),
                                      bg=ModernStyles.BG_PANEL, fg=ModernStyles.TEXT_NORMAL, relief='flat', bd=0,
                                      insertbackground=ModernStyles.TEXT_NORMAL)
        self.metrics_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.update_system_metrics_display()
    
    def create_security_events_section(self):
        """Create enhanced security events section."""
        events_frame = ttk.Frame(self.scrollable_frame, padding=10, style="TFrame")
        events_frame.pack(fill='both', expand=True)
        
        ttk.Label(events_frame, text="Recent Security Events", style="Title.TLabel").pack(anchor='w', pady=(0, 15))
        
        tree_container = ttk.Frame(events_frame, style="Card.TFrame")
        tree_container.pack(fill='both', expand=True)

        self.events_tree = ttk.Treeview(tree_container, columns=("time", "severity", "event", "source", "details"), show="headings", height=8)
        
        columns_config = [("time", "Time", 150), ("severity", "Severity", 100), ("event", "Event Type", 150),
                          ("source", "Source", 120), ("details", "Details", 300)]
        
        for col_id, col_text, col_width in columns_config:
            self.events_tree.heading(col_id, text=col_text, anchor='w')
            self.events_tree.column(col_id, width=col_width, anchor='w')
        
        events_scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=events_scrollbar.set)
        
        self.events_tree.pack(side="left", fill="both", expand=True)
        events_scrollbar.pack(side="right", fill="y")
        
        self.events_tree.tag_configure('CRITICAL', foreground=ModernStyles.DANGER_COLOR, font=(ModernStyles.FONT_FAMILY, 11, 'bold'))
        self.events_tree.tag_configure('ERROR', foreground=ModernStyles.DANGER_COLOR)
        self.events_tree.tag_configure('WARNING', foreground=ModernStyles.WARNING_COLOR)
        self.events_tree.tag_configure('INFO', foreground=ModernStyles.TEXT_MUTED)
    
    # --- DATA PROCESSING AND UPDATE LOGIC (Functionality Preserved) ---

    def start_monitoring(self):
        """Start real-time system monitoring thread (unchanged)."""
        def monitor_loop():
            while True:
                try:
                    self.system_metrics['cpu_usage'].append(psutil.cpu_percent(interval=1))
                    self.system_metrics['memory_usage'].append(psutil.virtual_memory().percent)
                    net_io = psutil.net_io_counters()
                    self.system_metrics['network_activity'].append(net_io.bytes_sent / 1024 / 1024)
                    self.system_metrics['timestamps'].append(datetime.now().strftime('%H:%M:%S'))
                    
                    threat_level = min(100, self.system_metrics['cpu_usage'][-1] + self.system_metrics['memory_usage'][-1] / 2)
                    self.system_metrics['threat_level'].append(threat_level)
                    
                    try:
                        if self.master.winfo_exists():
                            self.master.after(0, self.update_real_time_charts)
                    except tk.TclError:
                        # Window has been destroyed, exit loop
                        break
                    
                    time.sleep(5)
                except Exception as e:
                    print(f"Monitoring error: {e}")
                    time.sleep(10)
                    # Check if window still exists
                    try:
                        if not self.master.winfo_exists():
                            break
                    except:
                        break
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def update_real_time_charts(self):
        """Update real-time charts with new data (logic preserved, styling applied)."""
        try:
            if len(self.system_metrics['timestamps']) > 1:
                timestamps = list(self.system_metrics['timestamps'])[-20:]
                
                # Update performance chart
                cpu_data = list(self.system_metrics['cpu_usage'])[-20:]
                mem_data = list(self.system_metrics['memory_usage'])[-20:]
                self.cpu_line.set_data(range(len(cpu_data)), cpu_data)
                self.mem_line.set_data(range(len(mem_data)), mem_data)
                self.perf_ax.set_xlim(0, max(1, len(cpu_data)-1))
                self.perf_ax.set_xticks(range(0, len(timestamps), max(1, len(timestamps)//5)))
                self.perf_ax.set_xticklabels([timestamps[i] for i in range(0, len(timestamps), max(1, len(timestamps)//5))], rotation=30, ha='right')
                self.perf_canvas.draw()
                
                # Update threat chart
                threat_data = list(self.system_metrics['threat_level'])[-20:]
                self.threat_line.set_data(range(len(threat_data)), threat_data)
                self.threat_ax.set_xlim(0, max(1, len(threat_data)-1))
                self.threat_ax.set_ylim(0, max(100, max(threat_data) * 1.1) if threat_data else 100)
                self.threat_canvas.draw()
                
                # Update network chart
                network_data = list(self.system_metrics['network_activity'])[-20:]
                incoming_data = [x * 0.7 for x in network_data]
                outgoing_data = [x * 0.3 for x in network_data]
                self.traffic_in_line.set_data(range(len(incoming_data)), incoming_data)
                self.traffic_out_line.set_data(range(len(outgoing_data)), outgoing_data)
                self.network_ax.set_xlim(0, max(1, len(network_data)-1))
                if network_data: self.network_ax.set_ylim(0, max(1, max(network_data) * 1.1))
                self.network_canvas.draw()

                self.update_kpi_values()
        except Exception as e:
            # This can happen if the window is closed during an update
            pass
    
    def update_kpi_values(self):
        """Update KPI card values (unchanged)."""
        try:
            if hasattr(self, 'cpu_usage_value'):
                cpu = self.system_metrics['cpu_usage'][-1] if self.system_metrics['cpu_usage'] else 0
                self.cpu_usage_value.config(text=f"{cpu:.1f}%")
            if hasattr(self, 'memory_usage_value'):
                mem = self.system_metrics['memory_usage'][-1] if self.system_metrics['memory_usage'] else 0
                self.memory_usage_value.config(text=f"{mem:.1f}%")
            if hasattr(self, 'network_activity_value'):
                net = self.system_metrics['network_activity'][-1] if self.system_metrics['network_activity'] else 0
                self.network_activity_value.config(text=f"{net:.1f} MB/s")
            
            self.last_update_label.config(text=f"Last Updated: {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"KPI update error: {e}")
    
    def update_system_metrics_display(self):
        """Update system metrics text display (unchanged)."""
        try:
            if hasattr(self, 'metrics_text'):
                boot_time = datetime.fromtimestamp(psutil.boot_time())
                uptime = datetime.now() - boot_time
                # <<< FIX: Replace broken bullet with a standard one >>>
                metrics_text = f"""● CPU Cores: {psutil.cpu_count()}
● Total Memory: {psutil.virtual_memory().total / (1024**3):.1f} GB
● Disk Usage: {psutil.disk_usage('C:/').percent if os.name == 'nt' else psutil.disk_usage('/').percent:.1f}%
● Uptime: {str(uptime).split('.')[0]}"""
                self.metrics_text.config(state='normal')
                self.metrics_text.delete(1.0, tk.END)
                self.metrics_text.insert(1.0, metrics_text)
                self.metrics_text.config(state='disabled')
        except Exception as e:
            print(f"Metrics display update error: {e}")
    
    def update_activity_list(self, activities):
        """Update activity list in treeview (unchanged)."""
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        for time, event, details in activities:
            self.events_tree.insert("", 0, values=(time, event, details))

    def update_statistics(self):
        """Update statistics from logs (logic preserved)."""
        try:
            total_alerts, blocked_ips, attack_types = 0, set(), {}
            if os.path.exists(self.log_file):
                with open(self.log_file, "r") as f:
                    for line in f.readlines()[-1000:]:
                        total_alerts += 1
                        if "blocked" in line.lower():
                            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                            if ip_match: blocked_ips.add(ip_match.group(0))
            
            if hasattr(self, 'total_threats_detected_value'):
                self.total_threats_detected_value.config(text=str(total_alerts))
            if hasattr(self, 'active_blocks_value'):
                self.active_blocks_value.config(text=str(len(blocked_ips)))
            if hasattr(self, 'system_uptime_value'):
                uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
                self.system_uptime_value.config(text=str(uptime).split('.')[0])
        except Exception as e:
            print(f"Error updating statistics: {e}")

    def schedule_refresh(self):
        """Schedule periodic updates (unchanged)."""
        try:
            self.update_statistics()
            self.update_system_metrics_display()
        except Exception as e:
            print(f"Dashboard refresh error: {e}")
        try:
            if hasattr(self, 'master') and self.master.winfo_exists():
                self.master.after(10000, self.schedule_refresh)
        except (tk.TclError, AttributeError):
            # Widget destroyed, stop scheduling
            pass


class DashboardWindow:
    def __init__(self, master, user_id):
        self.master = master
        self.user_id = user_id
        
        self.style = ModernStyles.apply(master)
        
        # <<< FIX: Configure the style for notebook tabs to use the Emoji font >>>
        tab_font = font.Font(family=EMOJI_FONT_FAMILY, size=11)
        self.style.configure('TNotebook.Tab', font=tab_font, padding=[15, 5])
        
        self.master.title("Advanced IDS/IPS Security Dashboard")
        self.master.geometry("1200x800")
        self.master.minsize(1000, 700)
        
        # Main container
        self.main_frame = ttk.Frame(master, style="TFrame")
        self.main_frame.pack(fill='both', expand=True)

        # Header with title and status
        self.header_frame = ttk.Frame(self.main_frame, style="Header.TFrame", padding=(20, 15))
        self.header_frame.pack(fill='x')
        
        title_label = ttk.Label(self.header_frame, text="Advanced IDS/IPS Security Dashboard", style="HeaderTitle.TLabel")
        title_label.pack(side='left')
        
        status_frame = ttk.Frame(self.header_frame, style="Header.TFrame")
        status_frame.pack(side='right')
        
        ttk.Label(status_frame, text="System Status: ", style="Header.TLabel").pack(side='left')
        ttk.Label(status_frame, text="Active", style="Success.TLabel", background=ModernStyles.BG_DARK).pack(side='left')

        self.sniffer_panel = None

        # Tabbed UI (Notebook)
        self.notebook = ttk.Notebook(self.main_frame, style="TNotebook")
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)
        
        # <<< FIX: Replace broken text with the colorful emojis you wanted >>>
        self.add_tab("📊  Dashboard", DashboardOverview)
        self.add_tab("⚠️  Security Alerts", AlertsPanel)
        self.add_tab("🌐  Network Control", IPControlPanel)
        self.add_tab("🔍  Packet Analysis", SnifferPanel)
        self.add_tab("⚙️  Settings", SettingsPanel)
        
    def add_tab(self, title, panel_class):
        """Helper to create and add a tab to the notebook."""
        frame = ttk.Frame(self.notebook, padding=10, style="TFrame")
        self.notebook.add(frame, text=f' {title} ')
        
        if panel_class == SnifferPanel:
            self.sniffer_panel = panel_class(frame, self.user_id)
        else:
            panel_class(frame, self.user_id)

    def destroy(self):
        """Cleanup resources before window is closed."""
        if self.sniffer_panel and hasattr(self.sniffer_panel, 'destroy'):
            self.sniffer_panel.destroy()
        self.master.destroy()