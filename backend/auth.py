#!/usr/bin/env python3
"""
Advanced IDS/IPS Authentication Module - Production Ready
Secure user authentication with rate limiting, password validation, and session management
"""

import mysql.connector
import hashlib
import yaml
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from collections import defaultdict
from mysql.connector import pooling
from backend.logger import log_info, log_error, log_login_attempt, log_alert

# Load configuration
try:
    with open("config.yaml", "r") as f:
        cfg = yaml.safe_load(f)
except Exception as e:
    print(f"[Auth] ERROR: Failed to load config.yaml: {e}")
    raise

# Security settings from config
MAX_LOGIN_ATTEMPTS = cfg.get("security", {}).get("max_login_attempts", 3)
SESSION_TIMEOUT_MINUTES = cfg.get("security", {}).get("session_timeout_minutes", 60)
REQUIRE_STRONG_PASSWORDS = cfg.get("security", {}).get("require_strong_passwords", True)

# Rate limiting storage
login_attempts = defaultdict(list)
blocked_ips = defaultdict(float)
active_sessions = {}

# Connection pooling for better performance
db_config = cfg.get("mysql", {})
db_pool = None

def initialize_db_pool():
    """Initialize database connection pool"""
    global db_pool
    try:
        pool_config = {
            'pool_name': 'ids_pool',
            'pool_size': db_config.get('pool_size', 10),
            'pool_reset_session': True,
            'host': db_config['host'],
            'user': db_config['user'], 
            'password': db_config['password'],
            'database': db_config['database'],
            'autocommit': False
        }
        db_pool = pooling.MySQLConnectionPool(**pool_config)
        log_info("Database connection pool initialized")
        
        # Initialize database schema
        initialize_database_schema()
        
    except Exception as e:
        log_error(f"Failed to initialize DB pool: {e}")
        raise

def get_db_connection():
    """Get database connection from pool"""
    global db_pool
    if not db_pool:
        initialize_db_pool()
    
    try:
        return db_pool.get_connection()
    except Exception as e:
        log_error(f"DB connection failed: {e}")
        raise

def initialize_database_schema():
    """Initialize database schema with security enhancements"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Enhanced users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                salt VARCHAR(32) NOT NULL,
                failed_attempts INT DEFAULT 0,
                locked_until DATETIME NULL,
                last_login DATETIME NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_locked_until (locked_until)
            )
        """)
        
        # Session management table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id VARCHAR(64) PRIMARY KEY,
                user_id INT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                INDEX idx_user_id (user_id),
                INDEX idx_expires_at (expires_at),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Security audit log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(50) NOT NULL,
                username VARCHAR(50),
                ip_address VARCHAR(45),
                user_agent TEXT,
                details TEXT,
                severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_event_type (event_type),
                INDEX idx_created_at (created_at),
                INDEX idx_severity (severity)
            )
        """)
        
        conn.commit()
        conn.close()
        log_info("Database schema initialized successfully")
        
    except Exception as e:
        log_error(f"Failed to initialize database schema: {e}")
        raise

def validate_password_strength(password):
    """Validate password meets security requirements"""
    if not REQUIRE_STRONG_PASSWORDS:
        return True, "Password validation disabled"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets security requirements"

def generate_salt():
    """Generate a random salt for password hashing"""
    return secrets.token_hex(16)

def hash_password(password, salt=None):
    """Hash password with salt using PBKDF2"""
    if salt is None:
        salt = generate_salt()
    
    # Use PBKDF2 with SHA-256 for stronger hashing
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return password_hash.hex(), salt

def log_security_event(event_type, username=None, ip_address=None, user_agent=None, details=None, severity='MEDIUM'):
    """Log security events for audit purposes"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_events (event_type, username, ip_address, user_agent, details, severity)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (event_type, username, ip_address, user_agent, details, severity))
        conn.commit()
        conn.close()
    except Exception as e:
        log_error(f"Failed to log security event: {e}")

def is_ip_rate_limited(ip_address):
    """Check if IP is rate limited due to too many failed attempts"""
    current_time = time.time()
    
    # Clean old attempts (older than 1 hour)
    cutoff_time = current_time - 3600
    login_attempts[ip_address] = [t for t in login_attempts[ip_address] if t > cutoff_time]
    
    # Check if blocked
    if ip_address in blocked_ips and blocked_ips[ip_address] > current_time:
        return True
    
    # Check attempt count
    if len(login_attempts[ip_address]) >= MAX_LOGIN_ATTEMPTS:
        # Block IP for 30 minutes
        blocked_ips[ip_address] = current_time + 1800
        log_alert(f"IP {ip_address} blocked due to too many login attempts")
        log_security_event('IP_BLOCKED', ip_address=ip_address, 
                         details=f'Blocked after {len(login_attempts[ip_address])} failed attempts',
                         severity='HIGH')
        return True
    
    return False

def record_failed_attempt(ip_address, username=None):
    """Record a failed login attempt"""
    current_time = time.time()
    login_attempts[ip_address].append(current_time)
    
    if username:
        log_security_event('LOGIN_FAILED', username=username, ip_address=ip_address,
                         details='Invalid credentials', severity='MEDIUM')

def is_user_locked(username):
    """Check if user account is locked"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT locked_until, failed_attempts 
            FROM users 
            WHERE username = %s
        """, (username,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False
        
        locked_until, failed_attempts = result
        
        if locked_until and datetime.now() < locked_until:
            return True
        
        # Auto-unlock if time has passed
        if locked_until and datetime.now() >= locked_until:
            unlock_user(username)
        
        return False
        
    except Exception as e:
        log_error(f"Error checking user lock status: {e}")
        return False

def lock_user(username, duration_minutes=30):
    """Lock user account for specified duration"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        locked_until = datetime.now() + timedelta(minutes=duration_minutes)
        cursor.execute("""
            UPDATE users 
            SET locked_until = %s, failed_attempts = failed_attempts + 1
            WHERE username = %s
        """, (locked_until, username))
        conn.commit()
        conn.close()
        
        log_alert(f"User {username} account locked until {locked_until}")
        log_security_event('USER_LOCKED', username=username,
                         details=f'Account locked for {duration_minutes} minutes',
                         severity='HIGH')
        
    except Exception as e:
        log_error(f"Error locking user {username}: {e}")

def unlock_user(username):
    """Unlock user account and reset failed attempts"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users 
            SET locked_until = NULL, failed_attempts = 0
            WHERE username = %s
        """, (username,))
        conn.commit()
        conn.close()
        
        log_info(f"User {username} account unlocked")
        
    except Exception as e:
        log_error(f"Error unlocking user {username}: {e}")

def create_session(user_id, ip_address=None, user_agent=None):
    """Create a new user session"""
    try:
        session_id = secrets.token_urlsafe(48)
        expires_at = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_sessions (id, user_id, expires_at, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s)
        """, (session_id, user_id, expires_at, ip_address, user_agent))
        conn.commit()
        conn.close()
        
        active_sessions[session_id] = {
            'user_id': user_id,
            'expires_at': expires_at,
            'ip_address': ip_address
        }
        
        return session_id
        
    except Exception as e:
        log_error(f"Error creating session: {e}")
        return None

def validate_session(session_id):
    """Validate user session"""
    try:
        # Check in-memory cache first
        if session_id in active_sessions:
            session = active_sessions[session_id]
            if datetime.now() < session['expires_at']:
                return session['user_id']
            else:
                # Session expired, clean up
                del active_sessions[session_id]
                invalidate_session(session_id)
                return None
        
        # Check database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, expires_at FROM user_sessions 
            WHERE id = %s AND is_active = TRUE
        """, (session_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            user_id, expires_at = result
            if datetime.now() < expires_at:
                # Cache the session
                active_sessions[session_id] = {
                    'user_id': user_id,
                    'expires_at': expires_at
                }
                return user_id
            else:
                # Session expired
                invalidate_session(session_id)
        
        return None
        
    except Exception as e:
        log_error(f"Error validating session: {e}")
        return None

def invalidate_session(session_id):
    """Invalidate a user session"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE user_sessions 
            SET is_active = FALSE 
            WHERE id = %s
        """, (session_id,))
        conn.commit()
        conn.close()
        
        # Remove from memory cache
        active_sessions.pop(session_id, None)
        
    except Exception as e:
        log_error(f"Error invalidating session: {e}")

# Enhanced authentication logic
def authenticate_user(username, password, ip_address=None, user_agent=None):
    """Enhanced authentication with rate limiting and security checks"""
    try:
        # Check IP rate limiting
        if ip_address and is_ip_rate_limited(ip_address):
            log_security_event('LOGIN_BLOCKED_RATE_LIMIT', username=username, 
                             ip_address=ip_address, severity='HIGH')
            return None
        
        # Check if user is locked
        if is_user_locked(username):
            log_security_event('LOGIN_BLOCKED_USER_LOCKED', username=username,
                             ip_address=ip_address, severity='HIGH')
            return None
        
        # Get user data with salt
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, password_hash, salt, failed_attempts 
            FROM users 
            WHERE username = %s
        """, (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            # User doesn't exist
            if ip_address:
                record_failed_attempt(ip_address, username)
            log_login_attempt(username, success=False)
            return None
        
        user_id, stored_hash, salt, failed_attempts = user_data
        
        # Verify password
        password_hash, _ = hash_password(password, salt)
        
        if password_hash == stored_hash:
            # Successful authentication
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = 0, last_login = %s
                WHERE id = %s
            """, (datetime.now(), user_id))
            conn.commit()
            conn.close()
            
            log_login_attempt(username, success=True)
            log_security_event('LOGIN_SUCCESS', username=username, 
                             ip_address=ip_address, severity='LOW')
            
            return user_id
        else:
            # Failed authentication
            failed_attempts += 1
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = %s
                WHERE id = %s
            """, (failed_attempts, user_id))
            
            # Lock user after max attempts
            if failed_attempts >= MAX_LOGIN_ATTEMPTS:
                lock_user(username)
            
            conn.commit()
            conn.close()
            
            if ip_address:
                record_failed_attempt(ip_address, username)
            
            log_login_attempt(username, success=False)
            return None
            
    except Exception as e:
        log_error(f"Authentication failed for user '{username}': {e}")
        log_login_attempt(username, success=False)
        return None

# Enhanced user registration
def add_user(username, password, ip_address=None):
    """Enhanced user registration with password validation"""
    try:
        # Validate input
        if not username or not password:
            return False, "Username and password are required"
        
        if len(username) < 3 or len(username) > 50:
            return False, "Username must be between 3 and 50 characters"
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        
        # Validate password strength
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            return False, message
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user already exists
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            conn.close()
            return False, "Username already exists"
        
        # Hash password with salt
        password_hash, salt = hash_password(password)
        
        # Create user
        cursor.execute("""
            INSERT INTO users (username, password_hash, salt)
            VALUES (%s, %s, %s)
        """, (username, password_hash, salt))
        conn.commit()
        conn.close()
        
        log_info(f"New user registered: {username}")
        log_security_event('USER_REGISTERED', username=username, 
                         ip_address=ip_address, severity='LOW')
        return True, "User registered successfully"
        
    except Exception as e:
        log_error(f"User registration failed for '{username}': {e}")
        return False, "Registration failed due to system error"

# Initialize on import
if db_config:
    try:
        initialize_db_pool()
    except Exception as e:
        log_error(f"Failed to initialize authentication module: {e}")
