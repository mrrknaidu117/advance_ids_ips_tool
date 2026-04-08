# File: gui/styles.py
import tkinter as tk
from tkinter import ttk
import os

class ModernStyles:
    """
    Defines the "SOC Pro Theme" for the Advanced IDS/IPS application.
    This theme is inspired by professional Security Operations Center (SOC) dashboards,
    emphasizing clarity, readability, and a modern, high-tech aesthetic.
    """

    # --- "SOC Pro" Color Palette ---
    BG_DARK = "#121212"       # Root background: deep, off-black charcoal
    BG_PANEL = "#1e1e1e"      # Panel/Card background: slightly lighter for depth
    BORDER_COLOR = "#2f2f2f"  # Subtle borders and separators

    # Primary accent color for a professional, high-tech feel
    PRIMARY_COLOR = "#0078d7"  # Industrial Blue
    PRIMARY_HOVER = "#2d89ef"  # A brighter blue for hover effects

    # Semantic colors for status indicators
    SUCCESS_COLOR = "#21c55d"  # Bright, clear green
    WARNING_COLOR = "#fbbf24"  # Vibrant amber/yellow
    DANGER_COLOR = "#ef4444"   # Strong, distinct red

    # --- Typography ---
    TEXT_HEADER = "#ffffff"       # Pure white for main titles
    TEXT_NORMAL = "#e0e0e0"       # Off-white for body text, easy on the eyes
    TEXT_MUTED = "#a3a3a3"        # Gray for secondary info or placeholders
    
    FONT_FAMILY = "Segoe UI" if os.name == "nt" else "Roboto"
    FONT_FAMILY_TITLE = "Segoe UI Semibold" if os.name == "nt" else "Roboto Medium"
    FONT_SIZE_SMALL = 9
    FONT_SIZE_NORMAL = 11
    FONT_SIZE_LARGE = 13
    FONT_SIZE_TITLE = 16

    @classmethod
    def apply(cls, root: tk.Tk):
        """Applies the complete SOC Pro theme to the entire application."""
        root.configure(background=cls.BG_DARK)
        
        style = ttk.Style(root)
        style.theme_use('clam') 

        # --- GLOBAL DEFAULTS ---
        style.configure(".", background=cls.BG_PANEL, foreground=cls.TEXT_NORMAL,
                        bordercolor=cls.BORDER_COLOR, font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL))
        style.configure("TFrame", background=cls.BG_DARK)
        style.configure("TLabel", background=cls.BG_DARK, foreground=cls.TEXT_NORMAL)

        # --- WIDGET-SPECIFIC STYLES ---

        # Main Header Style
        style.configure("Header.TFrame", background=cls.BG_DARK)
        style.configure("Header.TLabel", background=cls.BG_DARK, foreground=cls.TEXT_HEADER,
                        font=(cls.FONT_FAMILY, cls.FONT_SIZE_LARGE))
        style.configure("HeaderTitle.TLabel", background=cls.BG_DARK, foreground=cls.TEXT_HEADER,
                        font=(cls.FONT_FAMILY_TITLE, cls.FONT_SIZE_TITLE, "bold"))
        
        # Card Style
        style.configure("Card.TFrame", background=cls.BG_PANEL, relief="solid", borderwidth=1, bordercolor=cls.BORDER_COLOR)
        style.configure("Card.TLabel", background=cls.BG_PANEL, foreground=cls.TEXT_NORMAL)
        
        # Title & Subtitle Labels
        style.configure("Title.TLabel", font=(cls.FONT_FAMILY_TITLE, cls.FONT_SIZE_TITLE, "bold"), foreground=cls.TEXT_HEADER, background=cls.BG_DARK)
        style.configure("CardTitle.TLabel", background=cls.BG_PANEL, foreground=cls.TEXT_HEADER,
                        font=(cls.FONT_FAMILY, cls.FONT_SIZE_LARGE, "bold"))

        # KPI Card Value Styles
        base_value_font = (cls.FONT_FAMILY_TITLE, 26, "bold")
        style.configure("Value.TLabel", background=cls.BG_PANEL, foreground=cls.PRIMARY_COLOR, font=base_value_font)
        style.configure("PrimaryValue.TLabel", background=cls.BG_PANEL, foreground=cls.PRIMARY_COLOR, font=base_value_font)
        style.configure("SuccessValue.TLabel", background=cls.BG_PANEL, foreground=cls.SUCCESS_COLOR, font=base_value_font)
        style.configure("WarningValue.TLabel", background=cls.BG_PANEL, foreground=cls.WARNING_COLOR, font=base_value_font)
        style.configure("DangerValue.TLabel", background=cls.BG_PANEL, foreground=cls.DANGER_COLOR, font=base_value_font)

        # Status Labels
        style.configure("Success.TLabel", foreground=cls.SUCCESS_COLOR, font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL, "bold"))
        style.configure("Warning.TLabel", foreground=cls.WARNING_COLOR, font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL, "bold"))
        style.configure("Danger.TLabel", foreground=cls.DANGER_COLOR, font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL, "bold"))

        # Button Styles
        style.configure("TButton", background=cls.PRIMARY_COLOR, foreground=cls.TEXT_HEADER,
                        font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL, "bold"), padding=(14, 8), relief="flat", borderwidth=0)
        style.map("TButton", background=[("active", cls.PRIMARY_HOVER)])
        style.configure("Secondary.TButton", background=cls.BORDER_COLOR, foreground=cls.TEXT_NORMAL)
        style.map("Secondary.TButton", background=[("active", "#3a3a3a")])
        style.configure("Danger.TButton", background=cls.DANGER_COLOR, foreground=cls.TEXT_HEADER)
        style.map("Danger.TButton", background=[("active", "#ff6666")])
        
        # Entry Field & Similar Widgets
        style.configure("TEntry", fieldbackground=cls.BG_DARK, foreground=cls.TEXT_NORMAL, insertcolor=cls.TEXT_NORMAL,
                        bordercolor=cls.BORDER_COLOR, borderwidth=2, padding=8, relief="flat")
        style.map("TEntry", bordercolor=[("focus", cls.PRIMARY_COLOR)], relief=[("focus", "solid")])
        style.configure("TSpinbox", fieldbackground=cls.BG_DARK, foreground=cls.TEXT_NORMAL, insertcolor=cls.TEXT_NORMAL,
                        bordercolor=cls.BORDER_COLOR, borderwidth=2, relief="flat", arrowsize=14)
        style.map("TSpinbox", bordercolor=[("focus", cls.PRIMARY_COLOR)], relief=[("focus", "solid")])
        
        # Treeview (Table) Style
        style.configure("Treeview", background=cls.BG_PANEL, foreground=cls.TEXT_NORMAL, fieldbackground=cls.BG_PANEL,
                        rowheight=28, font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL), borderwidth=0, relief="flat")
        style.map("Treeview", background=[("selected", cls.PRIMARY_COLOR)])
        style.configure("Treeview.Heading", background=cls.BG_DARK, foreground=cls.TEXT_HEADER,
                        font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL, "bold"), relief="flat")
        style.map("Treeview.Heading", background=[("active", cls.BG_PANEL)])
        
        # Notebook (Tabs) Style
        style.configure("TNotebook", background=cls.BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", font=(cls.FONT_FAMILY, cls.FONT_SIZE_NORMAL, "bold"), padding=[15, 8],
                        background=cls.BG_PANEL, foreground=cls.TEXT_MUTED, borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", cls.BG_DARK)], foreground=[("selected", cls.PRIMARY_COLOR)])

        # Scrollbar Style
        style.configure("Vertical.TScrollbar", gripcount=0, background=cls.BG_PANEL, troughcolor=cls.BG_DARK,
                        bordercolor=cls.BG_DARK, arrowcolor=cls.TEXT_NORMAL, relief="flat")
        style.map("Vertical.TScrollbar", background=[("active", cls.PRIMARY_COLOR)])
        
        # Checkbutton & Radiobutton
        style.configure("TCheckbutton", background=cls.BG_PANEL, foreground=cls.TEXT_NORMAL)
        style.map("TCheckbutton",
                  background=[('active', cls.BG_PANEL)],
                  indicatorcolor=[('selected', cls.PRIMARY_COLOR), ('!selected', cls.BG_DARK)],
                  indicatorrelief=[('pressed', 'sunken'), ('!pressed', 'raised')])
        style.configure("TRadiobutton", background=cls.BG_PANEL, foreground=cls.TEXT_NORMAL)
        style.map("TRadiobutton",
                  background=[('active', cls.BG_PANEL)],
                  indicatorcolor=[('selected', cls.PRIMARY_COLOR), ('!selected', cls.BG_DARK)],
                  indicatorrelief=[('pressed', 'sunken'), ('!pressed', 'raised')])

        return style

    @classmethod
    def create_button(cls, parent, text, command=None, is_secondary=False):
        style_name = "Secondary.TButton" if is_secondary else "TButton"
        return ttk.Button(parent, text=text, command=command, style=style_name, cursor="hand2")