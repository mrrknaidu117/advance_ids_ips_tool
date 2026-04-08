# File: gui/sniffer.py - Enhanced Network Traffic Analyzer
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from backend.sniffer import start_sniffing, stop_sniffing
from backend.firewall import block_ip_manual
from gui.styles import ModernStyles
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import csv
import json
import time
from datetime import datetime
from collections import deque, defaultdict
import os

# Set matplotlib to dark theme for consistency
try:
    plt.style.use('dark_background')
except:
    pass

class SnifferPanel:
    def __init__(self, master, user_id):
        self.master = master
        self.user_id = user_id
        self.running = False
        self.queue = deque(maxlen=1000)
        self.job_id = None
        self._stopped = False
        self.packet_stats = {
            'total_packets': 0, 'attack_count': 0, 'normal_count': 0,
            'blocked_count': 0, 'protocols': defaultdict(int), 'start_time': None
        }
        
        self.create_interface()
        self._schedule()
    
    def create_interface(self):
        """Create the modern interface with professional styling"""
        
        self.create_header()
        self.create_main_content()
        self.create_statistics_section()
    
    def create_header(self):
        """Create professional header with title and status indicators"""
        header_frame = ttk.Frame(self.master, style="Header.TFrame", padding=15)
        header_frame.pack(fill='x', pady=(0, 20))
        
        title_section = ttk.Frame(header_frame, style="Header.TFrame")
        title_section.pack(side='left', fill='x', expand=True)
        
        ttk.Label(title_section, text="🔍 Live Network Traffic Analyzer", style="HeaderTitle.TLabel").pack(anchor='w')
        
        self.status_subtitle = ttk.Label(title_section, text="Real-time packet capture and analysis", style="Header.TLabel", foreground=ModernStyles.TEXT_MUTED)
        self.status_subtitle.pack(anchor='w', pady=(5, 0))
        
        status_section = ttk.Frame(header_frame, style="Header.TFrame")
        status_section.pack(side='right')
        
        self.status_indicator = ttk.Label(status_section, text="●", font=(ModernStyles.FONT_FAMILY, 20, "bold"), foreground=ModernStyles.TEXT_MUTED, background=ModernStyles.BG_DARK)
        self.status_indicator.pack()
        
        self.status_text = ttk.Label(status_section, text="Ready", font=(ModernStyles.FONT_FAMILY, ModernStyles.FONT_SIZE_SMALL), foreground=ModernStyles.TEXT_MUTED, background=ModernStyles.BG_DARK)
        self.status_text.pack()
    
    def create_main_content(self):
        """Create main content area with controls and packet table"""
        main_container = ttk.Frame(self.master, style="TFrame")
        main_container.pack(fill='both', expand=True, pady=(0, 20))
        
        left_panel = ttk.Frame(main_container, style="TFrame")
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        
        self.create_control_panel(left_panel)
        self.create_stats_cards(left_panel)
        
        right_panel = ttk.Frame(main_container, style="TFrame")
        right_panel.pack(side='right', fill='both', expand=True)
        
        self.create_packet_table(right_panel)
    
    def create_control_panel(self, parent):
        """Create enhanced control panel with modern buttons"""
        control_frame = ttk.Frame(parent, style="Card.TFrame", padding=15)
        control_frame.pack(fill='x', pady=(0, 20))
        ttk.Label(control_frame, text="Control Panel", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        button_frame = ttk.Frame(control_frame, style="Card.TFrame")
        button_frame.pack(fill='x', pady=(0, 15))
        
        self.start_btn = ModernStyles.create_button(button_frame, "🚀 Start Monitoring", self.start)
        self.start_btn.pack(fill='x', pady=(0, 5))
        
        self.stop_btn = ttk.Button(button_frame, text="⏹️ Stop Monitoring", command=self.stop, state=tk.DISABLED, style="Danger.TButton", cursor="hand2")
        self.stop_btn.pack(fill='x', pady=(5, 0))
        
        actions_frame = ttk.Frame(control_frame, style="Card.TFrame")
        actions_frame.pack(fill='x')
        
        ModernStyles.create_button(actions_frame, "🗑️ Clear Data", self.clear_data, is_secondary=True).pack(fill='x', pady=(0, 5))
        ModernStyles.create_button(actions_frame, "📊 Export Data", self.export, is_secondary=True).pack(fill='x')
    
    def create_stats_cards(self, parent):
        """Create statistics cards with real-time updates"""
        stats_frame = ttk.Frame(parent, style="Card.TFrame", padding=15)
        stats_frame.pack(fill='x')
        ttk.Label(stats_frame, text="Live Statistics", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        packets_card = ttk.Frame(stats_frame, style="Card.TFrame")
        packets_card.pack(fill='x', pady=(0, 10))
        ttk.Label(packets_card, text="📦 Total Packets", style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED).pack(anchor='w')
        self.packets_value = ttk.Label(packets_card, text="0", style="PrimaryValue.TLabel", font=(ModernStyles.FONT_FAMILY_TITLE, 20, "bold"))
        self.packets_value.pack(anchor='w')
        
        threats_card = ttk.Frame(stats_frame, style="Card.TFrame")
        threats_card.pack(fill='x', pady=(0, 10))
        ttk.Label(threats_card, text="⚠️ Threats Detected", style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED).pack(anchor='w')
        self.threats_value = ttk.Label(threats_card, text="0", style="DangerValue.TLabel", font=(ModernStyles.FONT_FAMILY_TITLE, 20, "bold"))
        self.threats_value.pack(anchor='w')
        
        duration_card = ttk.Frame(stats_frame, style="Card.TFrame")
        duration_card.pack(fill='x')
        ttk.Label(duration_card, text="⏱️ Session Duration", style="Card.TLabel", foreground=ModernStyles.TEXT_MUTED).pack(anchor='w')
        self.duration_value = ttk.Label(duration_card, text="00:00:00", style="Card.TLabel", font=(ModernStyles.FONT_FAMILY_TITLE, 20, "bold"))
        self.duration_value.pack(anchor='w')
    
    def create_packet_table(self, parent):
        """Create enhanced packet table with modern styling"""
        table_frame = ttk.Frame(parent, style="Card.TFrame", padding=15)
        table_frame.pack(fill='both', expand=True)
        ttk.Label(table_frame, text="Captured Packets", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        self.tree = ttk.Treeview(table_frame, columns=('timestamp', 'source', 'destination', 'protocol', 'size', 'status', 'action'), show='headings', height=15)
        
        columns_config = {
            'timestamp': ('🕒 Timestamp', 150), 'source': ('📤 Source IP', 120),
            'destination': ('📥 Destination IP', 120), 'protocol': ('🌐 Protocol', 80),
            'size': ('📏 Size', 80), 'status': ('🔍 Status', 100), 'action': ('⚡ Action', 100)
        }
        
        for col, (header, width) in columns_config.items():
            self.tree.heading(col, text=header, anchor='w')
            self.tree.column(col, width=width, anchor='w', minwidth=50)
        
        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Configure theme-based tag colors
        self.tree.tag_configure('normal', foreground=ModernStyles.TEXT_NORMAL)
        self.tree.tag_configure('suspicious', foreground=ModernStyles.WARNING_COLOR)
        self.tree.tag_configure('malicious', foreground=ModernStyles.DANGER_COLOR)
        self.tree.tag_configure('blocked', foreground=ModernStyles.DANGER_COLOR)
        
        self.create_context_menu()
    
    def create_context_menu(self):
        """Create context menu for packet table"""
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="🚫 Block Source IP", command=self.block_source_ip)
        self.context_menu.add_command(label="📋 Copy IP Address", command=self.copy_ip)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🔍 Analyze Packet", command=self.analyze_packet)
        self.context_menu.add_command(label="🗑️ Delete Entry", command=self.delete_entry)
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def create_statistics_section(self):
        """Create charts and statistics section"""
        stats_container = ttk.Frame(self.master, style="TFrame")
        stats_container.pack(fill='x', pady=(20, 0))
        
        chart_frame = ttk.Frame(stats_container, style="Card.TFrame", padding=15)
        chart_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        ttk.Label(chart_frame, text="Traffic Analysis", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        self.fig, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 4))
        self._style_matplotlib_chart(self.fig, self.ax1)
        self._style_matplotlib_chart(self.fig, self.ax2)
        
        self.canvas = FigureCanvasTkAgg(self.fig, chart_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        self._setup_charts()
        
        protocol_frame = ttk.Frame(stats_container, style="Card.TFrame", padding=15)
        protocol_frame.pack(side='right', fill='y')
        ttk.Label(protocol_frame, text="Protocol Distribution", style="CardTitle.TLabel").pack(anchor='w', pady=(0, 10))
        
        self.protocol_tree = ttk.Treeview(protocol_frame, columns=('count',), show='tree headings', height=8, style="Treeview")
        self.protocol_tree.heading('#0', text='Protocol')
        self.protocol_tree.heading('count', text='Count')
        self.protocol_tree.column('#0', width=100)
        self.protocol_tree.column('count', width=80)
        self.protocol_tree.pack(fill='both', expand=True)
    
    def _style_matplotlib_chart(self, fig, ax):
        """Helper to style matplotlib charts for the dark theme"""
        fig.patch.set_facecolor(ModernStyles.BG_PANEL)
        ax.set_facecolor(ModernStyles.BG_PANEL)
        ax.tick_params(colors=ModernStyles.TEXT_MUTED, which='both')
        ax.grid(True, alpha=0.2, color=ModernStyles.BORDER_COLOR)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color(ModernStyles.BORDER_COLOR)
        ax.spines['left'].set_color(ModernStyles.BORDER_COLOR)
        ax.set_title('', color=ModernStyles.TEXT_NORMAL)
        ax.set_ylabel('', color=ModernStyles.TEXT_MUTED)
        ax.set_xlabel('', color=ModernStyles.TEXT_MUTED)
        
    def _setup_charts(self):
        """Setup initial chart configuration"""
        self.ax1.set_title('Traffic Classification')
        self.ax1.set_ylabel('Packet Count')
        self.ax2.set_title('Protocol Distribution')
        self._update_charts()
        plt.tight_layout()
    
    def _update_charts(self):
        """Update charts with current data"""
        try:
            self.ax1.clear()
            self.ax2.clear()
            
            categories = ['Normal', 'Suspicious', 'Malicious']
            counts = [self.packet_stats['normal_count'], max(0, self.packet_stats['attack_count'] - self.packet_stats['blocked_count']), self.packet_stats['blocked_count']]
            colors = [ModernStyles.SUCCESS_COLOR, ModernStyles.WARNING_COLOR, ModernStyles.DANGER_COLOR]
            
            self.ax1.bar(categories, counts, color=colors, alpha=0.8)
            self.ax1.set_title('Traffic Classification', color=ModernStyles.TEXT_NORMAL, fontsize=12)
            self.ax1.set_ylabel('Packet Count', color=ModernStyles.TEXT_MUTED)
            self.ax1.tick_params(colors=ModernStyles.TEXT_MUTED)
            self.ax1.set_facecolor(ModernStyles.BG_PANEL)
            
            if self.packet_stats['protocols']:
                protocols = list(self.packet_stats['protocols'].keys())
                protocol_counts = list(self.packet_stats['protocols'].values())
                self.ax2.pie(protocol_counts, labels=protocols, autopct='%1.1f%%', colors=plt.cm.Set3(range(len(protocols))), startangle=90, textprops={'color': 'white'})
                self.ax2.set_title('Protocol Distribution', color=ModernStyles.TEXT_NORMAL, fontsize=12)
            else:
                self.ax2.pie([1], labels=['No Data'], colors=[ModernStyles.BORDER_COLOR], autopct='', textprops={'color': ModernStyles.TEXT_MUTED})
                self.ax2.set_title('Protocol Distribution', color=ModernStyles.TEXT_NORMAL, fontsize=12)
            
            self.canvas.draw()
            
        except Exception as e:
            print(f"Chart update error: {e}")
    
    def show_context_menu(self, event):
        item = self.tree.identify('item', event.x, event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def block_source_ip(self):
        selection = self.tree.selection()
        if not selection: return
        values = self.tree.item(selection[0])['values']
        if len(values) >= 2:
            source_ip = values[1]
            try:
                block_ip_manual(source_ip, self.user_id, "Manual block from packet analysis")
                messagebox.showinfo("IP Blocked", f"Successfully blocked IP: {source_ip}")
            except Exception as e:
                messagebox.showerror("Block Failed", f"Failed to block IP {source_ip}: {e}")
    
    def copy_ip(self):
        selection = self.tree.selection()
        if not selection: return
        values = self.tree.item(selection[0])['values']
        if len(values) >= 2:
            source_ip = values[1]
            self.master.clipboard_clear()
            self.master.clipboard_append(source_ip)
            messagebox.showinfo("Copied", f"IP address {source_ip} copied to clipboard")
    
    def analyze_packet(self):
        selection = self.tree.selection()
        if not selection: return
        values = self.tree.item(selection[0])['values']
        analysis_text = f"""Packet Analysis:
• Timestamp: {values[0]}
• Source IP: {values[1]}
• Destination IP: {values[2]}
• Protocol: {values[3]}
• Size: {values[4]} bytes
• Status: {values[5]}
• Action: {values[6]}
This packet was captured during the current monitoring session.
Use the Block IP option to add this source to the firewall."""
        messagebox.showinfo("Packet Analysis", analysis_text)
    
    def delete_entry(self):
        selection = self.tree.selection()
        if selection:
            for item in selection: self.tree.delete(item)
    
    def clear_data(self):
        if messagebox.askyesno("Clear Data", "Are you sure you want to clear all captured packet data?"):
            for item in self.tree.get_children(): self.tree.delete(item)
            self.packet_stats = {'total_packets': 0, 'attack_count': 0, 'normal_count': 0, 'blocked_count': 0, 'protocols': defaultdict(int), 'start_time': None}
            self.update_statistics()
            self._update_charts()
    
    def start(self):
        self.running = True
        self.packet_stats['start_time'] = datetime.now()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_indicator.config(foreground=ModernStyles.SUCCESS_COLOR)
        self.status_text.config(text="Monitoring Active")
        self.status_subtitle.config(text="Capturing and analyzing network traffic...")
        try:
            start_sniffing(self.user_id, auto_block=False, packet_callback=lambda pkt: self.queue.append(pkt))
        except Exception as e:
            messagebox.showerror("Start Error", f"Failed to start monitoring: {e}")
            self.stop()
    
    def stop(self):
        self.running = False
        stop_sniffing()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_indicator.config(foreground=ModernStyles.TEXT_MUTED)
        self.status_text.config(text="Stopped")
        self.status_subtitle.config(text="Monitoring stopped")
    
    def _schedule(self):
        try:
            packets_processed = 0
            while self.queue and packets_processed < 10:
                pkt = self.queue.popleft()
                self._process_packet(pkt)
                packets_processed += 1
            if packets_processed > 0:
                self.update_statistics()
                self._update_charts()
            if self.packet_stats['start_time']:
                duration = datetime.now() - self.packet_stats['start_time']
                self.duration_value.config(text=str(duration).split('.')[0])
        except Exception as e: 
            print(f"Scheduler error: {e}")
        try:
            if not self._stopped and hasattr(self, 'master') and self.master.winfo_exists(): 
                self.job_id = self.master.after(1000, self._schedule)
        except (tk.TclError, AttributeError):
            # Widget destroyed, stop scheduling
            self._stopped = True
    
    def _process_packet(self, pkt):
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            src, dst, proto, size, status, action = pkt.get('src', 'Unknown'), pkt.get('dst', 'Unknown'), pkt.get('proto', 'Unknown'), pkt.get('size', 0), pkt.get('status', 'normal'), pkt.get('action', 'ALLOWED')
            self.packet_stats['total_packets'] += 1
            self.packet_stats['protocols'][proto] += 1
            if status in ['attack', 'malicious', 'suspicious']: self.packet_stats['attack_count'] += 1
            else: self.packet_stats['normal_count'] += 1
            if action == 'BLOCKED': self.packet_stats['blocked_count'] += 1
            tag = 'malicious' if status == 'malicious' or action == 'BLOCKED' else 'suspicious' if status == 'suspicious' else 'normal'
            if len(self.tree.get_children()) >= 1000: self.tree.delete(self.tree.get_children()[0])
            self.tree.insert('', 'end', values=(timestamp, src, dst, proto, size, status.upper(), action), tags=(tag,))
            children = self.tree.get_children()
            if children: self.tree.see(children[-1])
        except Exception as e: print(f"Packet processing error: {e}")
    
    def update_statistics(self):
        try:
            self.packets_value.config(text=str(self.packet_stats['total_packets']))
            self.threats_value.config(text=str(self.packet_stats['attack_count']))
            for item in self.protocol_tree.get_children(): self.protocol_tree.delete(item)
            for protocol, count in sorted(self.packet_stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                self.protocol_tree.insert('', 'end', text=protocol, values=(count,))
        except Exception as e: print(f"Statistics update error: {e}")
    
    def export(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("JSON Files", "*.json"), ("Text Files", "*.txt")])
        if not file_path: return
        try:
            if file_path.endswith('.csv'): self._export_csv(file_path)
            elif file_path.endswith('.json'): self._export_json(file_path)
            else: self._export_txt(file_path)
            messagebox.showinfo("Export Successful", f"Data exported to {file_path}")
        except Exception as e: messagebox.showerror("Export Failed", f"Failed to export data: {e}")
    
    def _export_csv(self, file_path):
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Size', 'Status', 'Action'])
            for item in self.tree.get_children(): writer.writerow(self.tree.item(item)['values'])
    
    def _export_json(self, file_path):
        data = {'export_time': datetime.now().isoformat(), 'session_stats': dict(self.packet_stats), 'packets': []}
        data['session_stats']['protocols'] = dict(data['session_stats']['protocols'])
        if data['session_stats']['start_time']: data['session_stats']['start_time'] = data['session_stats']['start_time'].isoformat()
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            data['packets'].append({'timestamp': values[0], 'source_ip': values[1], 'destination_ip': values[2], 'protocol': values[3], 'size': values[4], 'status': values[5], 'action': values[6]})
        with open(file_path, 'w', encoding='utf-8') as f: json.dump(data, f, indent=2)
    
    def _export_txt(self, file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Advanced IDS/IPS Tool - Network Traffic Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Export Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Session Duration: {self.duration_value.cget('text')}\n\n")
            f.write("Session Statistics:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Packets: {self.packet_stats['total_packets']}\n")
            f.write(f"Normal Packets: {self.packet_stats['normal_count']}\n")
            f.write(f"Attack Packets: {self.packet_stats['attack_count']}\n")
            f.write(f"Blocked Packets: {self.packet_stats['blocked_count']}\n\n")
            if self.packet_stats['protocols']:
                f.write("Protocol Distribution:\n")
                f.write("-" * 20 + "\n")
                for protocol, count in self.packet_stats['protocols'].items(): f.write(f"{protocol}: {count} packets\n")
                f.write("\n")
            f.write("Packet Details:\n")
            f.write("-" * 20 + "\n")
            f.write(f"{'Timestamp':<12} {'Source IP':<15} {'Dest IP':<15} {'Protocol':<10} {'Size':<8} {'Status':<12} {'Action'}\n")
            f.write("-" * 80 + "\n")
            for item in self.tree.get_children():
                values = self.tree.item(item)['values']
                f.write(f"{values[0]:<12} {values[1]:<15} {values[2]:<15} {values[3]:<10} {values[4]:<8} {values[5]:<12} {values[6]}\n")
    
    def destroy(self):
        try:
            if self.running: self.stop()
            if self.job_id: self.master.after_cancel(self.job_id)
            if hasattr(self, 'canvas'):
                self.canvas.get_tk_widget().destroy()
                plt.close(self.fig)
            self.queue.clear()
            self.packet_stats.clear()
        except Exception as e: print(f"Cleanup error: {e}")
        finally:
            for widget in self.master.winfo_children():
                try: widget.destroy()
                except: pass