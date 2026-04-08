#!/usr/bin/env python3
"""
Advanced IDS/IPS Tool - Production Ready Main Application
Enterprise-grade Intrusion Detection and Prevention System
Version 2.0.0 - Production Release
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox
import traceback
import logging
import yaml
from datetime import datetime

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from gui.login import LoginWindow
    from gui.styles import ModernStyles
    from backend.logger import log_info, log_error, log_alert
    from backend.auth import initialize_db_pool
except ImportError as e:
    print(f"CRITICAL: Failed to import required modules: {e}")
    sys.exit(1)

# Application Constants
APP_NAME = "Advanced IDS/IPS Tool"
APP_VERSION = "2.0.0"
APP_DESCRIPTION = "Enterprise-grade Intrusion Detection and Prevention System"
COPYRIGHT = "© 2024 Advanced Security Systems"

def create_directories():
    """Create necessary directories for the application"""
    directories = [
        "logs",
        "exports", 
        "config",
        "assets",
        "temp"
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not create directory '{directory}': {e}")

def setup_logging():
    """Setup application logging"""
    try:
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler("logs/application.log"),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Log startup
        logging.info(f"=== {APP_NAME} v{APP_VERSION} Starting ===")
        logging.info(f"Started at: {datetime.now()}")
        logging.info(f"Platform: {sys.platform}")
        logging.info(f"Python version: {sys.version}")
        
    except Exception as e:
        print(f"Warning: Could not setup logging: {e}")

def validate_configuration():
    """Validate application configuration"""
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
        
        # Check required configuration sections
        required_sections = ["mysql", "virustotal", "security", "scanning"]
        missing_sections = []
        
        for section in required_sections:
            if section not in config:
                missing_sections.append(section)
        
        if missing_sections:
            raise ValueError(f"Missing configuration sections: {', '.join(missing_sections)}")
        
        # Validate critical settings
        mysql_config = config.get("mysql", {})
        if not all(key in mysql_config for key in ["host", "user", "password", "database"]):
            raise ValueError("Incomplete MySQL configuration")
        
        logging.info("Configuration validation passed")
        return True
        
    except FileNotFoundError:
        logging.error("config.yaml not found!")
        return False
    except Exception as e:
        logging.error(f"Configuration validation failed: {e}")
        return False


def check_dependencies():
    """Check if all required dependencies are available"""
    required_modules = [
        ("mysql.connector", "MySQL Connector"),
        ("yaml", "PyYAML"),
        ("scapy", "Scapy"),
        ("numpy", "NumPy"),
        ("pandas", "Pandas"),
        ("joblib", "Joblib"),
        ("psutil", "PSUtil"),
        ("requests", "Requests")
    ]
    
    missing_modules = []
    
    for module_name, display_name in required_modules:
        try:
            __import__(module_name)
        except ImportError:
            missing_modules.append(display_name)
    
    if missing_modules:
        error_msg = f"Missing required dependencies:\n{', '.join(missing_modules)}\n\nPlease install them using: pip install {' '.join(missing_modules)}"
        logging.error(error_msg)
        messagebox.showerror("Missing Dependencies", error_msg)
        return False
    
    # Automatically use built-in monitoring methods
    logging.info("Using built-in network monitoring methods")
    os.environ['IDS_TESTING_MODE'] = '1'
    
    logging.info("All dependencies available")
    return True

def initialize_systems():
    """Initialize application systems"""
    try:
        # Initialize database connection pool
        logging.info("Initializing database connection pool...")
        initialize_db_pool()
        
        # Check ML models
        logging.info("Checking ML models...")
        model_files = ["model/model.pkl", "model/scaler.pkl"]
        for model_file in model_files:
            if not os.path.exists(model_file):
                raise FileNotFoundError(f"ML model file not found: {model_file}")
        
        logging.info("System initialization completed successfully")
        return True
        
    except Exception as e:
        logging.error(f"System initialization failed: {e}")
        return False

def create_splash_screen():
    """Create and show splash screen during startup"""
    splash = tk.Toplevel()
    splash.title("")
    splash.geometry("400x300")
    splash.resizable(False, False)
    splash.configure(bg="#1e1e1e")
    
    # Center splash screen
    splash.update_idletasks()
    x = (splash.winfo_screenwidth() // 2) - (400 // 2)
    y = (splash.winfo_screenheight() // 2) - (300 // 2)
    splash.geometry(f"400x300+{x}+{y}")
    
    # Remove window decorations
    splash.overrideredirect(True)
    
    # Create content
    tk.Label(splash, text=APP_NAME, font=("Arial", 18, "bold"), 
             fg="#00ff41", bg="#1e1e1e").pack(pady=30)
    
    tk.Label(splash, text=f"Version {APP_VERSION}", font=("Arial", 12), 
             fg="#ffffff", bg="#1e1e1e").pack(pady=5)
    
    tk.Label(splash, text=APP_DESCRIPTION, font=("Arial", 10), 
             fg="#cccccc", bg="#1e1e1e").pack(pady=10)
    
    # Progress bar
    progress_var = tk.StringVar(value="Initializing...")
    tk.Label(splash, textvariable=progress_var, font=("Arial", 9), 
             fg="#999999", bg="#1e1e1e").pack(pady=20)
    
    progress = ttk.Progressbar(splash, length=300, mode='indeterminate')
    progress.pack(pady=10)
    progress.start()
    
    tk.Label(splash, text=COPYRIGHT, font=("Arial", 8), 
             fg="#666666", bg="#1e1e1e").pack(side="bottom", pady=10)
    
    splash.update()
    return splash, progress_var

def main():
    """Main application entry point"""
    # Create directories
    create_directories()
    
    # Setup logging
    setup_logging()
    
    try:
        logging.info("Starting application initialization...")
        
        # Create root window (hidden initially)
        root = tk.Tk()
        root.withdraw()  # Hide main window during startup
        
        # Create splash screen
        splash, progress_var = create_splash_screen()
        
        def update_progress(message):
            progress_var.set(message)
            splash.update()
        
        # Step 1: Check dependencies
        update_progress("Checking dependencies...")
        if not check_dependencies():
            splash.destroy()
            return 1
        
        # Step 2: Validate configuration
        update_progress("Validating configuration...")
        if not validate_configuration():
            splash.destroy()
            messagebox.showerror("Configuration Error", 
                               "Configuration validation failed. Please check config.yaml")
            return 1
        
        # Step 3: Initialize systems
        update_progress("Initializing systems...")
        if not initialize_systems():
            splash.destroy()
            messagebox.showerror("Initialization Error", 
                               "System initialization failed. Check logs for details.")
            return 1
        
        # Step 4: Setup main window
        update_progress("Setting up interface...")
        
        root.title(f"{APP_NAME} v{APP_VERSION} - Security Dashboard")
        root.geometry("1200x800")
        root.minsize(1000, 700)
        
        # Center the main window
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - 1200) // 2
        y = (screen_height - 800) // 2
        root.geometry(f"1200x800+{x}+{y}")
        
        # Set application icon (if available)
        try:
            if os.path.exists("assets/icon.ico"):
                root.iconbitmap("assets/icon.ico")
        except Exception as e:
            logging.warning(f"Could not set application icon: {e}")
        
        # Apply modern styling
        update_progress("Applying interface styling...")
        ModernStyles.apply(root)
        
        # Step 5: Initialize login system
        update_progress("Initializing security...")
        
        # Close splash screen
        splash.destroy()
        
        # Show main window and login
        root.deiconify()
        LoginWindow(root)
        
        logging.info("Application startup completed successfully")
        
        # Start main event loop
        root.mainloop()
        
        logging.info("Application shutdown completed")
        return 0
        
    except KeyboardInterrupt:
        logging.info("Application interrupted by user")
        return 0
    except Exception as e:
        error_msg = f"Critical startup error: {str(e)}"
        logging.critical(error_msg)
        logging.critical(traceback.format_exc())
        
        try:
            messagebox.showerror("Critical Error", 
                                f"{error_msg}\n\nPlease check the logs for more details.")
        except:
            print(f"CRITICAL ERROR: {error_msg}")
            traceback.print_exc()
        
        return 1
    finally:
        # Cleanup
        try:
            if 'splash' in locals():
                splash.destroy()
        except:
            pass

if __name__ == "__main__":
    sys.exit(main())
