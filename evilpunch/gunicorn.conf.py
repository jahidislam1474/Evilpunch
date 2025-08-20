"""
Gunicorn configuration file for EvilPunch Django application.
This file reads configuration from core/config.py
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from core.config import get_config
    cfg = get_config()
    
    # Server configuration
    host = str(cfg.get("dashboard_host") or "127.0.0.1")
    port = str(cfg.get("dashboard_port") or "8000")
    
    # SSL configuration
    ssl_dir = project_root.parent / "server_ssl"
    cert_file = ssl_dir / "server.crt"
    key_file = ssl_dir / "server.key"
    
    # Check if SSL certificates exist
    if cert_file.exists() and key_file.exists():
        # Use HTTPS with SSL
        bind = f"{host}:{port}"
        certfile = str(cert_file)
        keyfile = str(key_file)
        do_handshake_on_connect = True
        print(f"[gunicorn] SSL enabled: {certfile}")
        print(f"[gunicorn] SSL key: {keyfile}")
    else:
        # Fallback to HTTP
        bind = f"{host}:{port}"
        print(f"[gunicorn] SSL certificates not found, using HTTP: {bind}")
    
    # Worker configuration
    workers = 3
    worker_class = "sync"
    worker_connections = 1000
    
    # Timeout settings
    timeout = 120
    keepalive = 2
    graceful_timeout = 30
    
    # Request limits
    max_requests = 1000
    max_requests_jitter = 100
    
    # Logging
    accesslog = "-"  # stdout
    errorlog = "-"   # stderr
    loglevel = "info"
    
    # Process naming
    proc_name = "evilpunch"
    
    # Preload app for better performance
    preload_app = True
    
    # User/group (uncomment if running as different user)
    # user = "www-data"
    # group = "www-data"
    
    # Security
    limit_request_line = 4094
    limit_request_fields = 100
    limit_request_field_size = 8190
    
    print(f"[gunicorn] Configuration loaded: {bind}")
    print(f"[gunicorn] Workers: {workers}, Timeout: {timeout}s")
    
except Exception as e:
    print(f"[gunicorn] Error loading config: {e}")
    print("[gunicorn] Using default configuration")
    
    # Fallback defaults
    bind = "127.0.0.1:8000"
    workers = 3
    worker_class = "sync"
    timeout = 120
