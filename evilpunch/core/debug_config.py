"""
Debug Configuration for HTTP Proxy Server

This module provides configuration options for debugging the HTTP proxy server.
You can control debugging behavior by setting environment variables or modifying
the configuration below.
"""

import os
from typing import Dict, Any

# Debug Configuration
DEBUG_CONFIG = {
    # Enable/disable debugging (default: True)
    "enabled": os.getenv("PROXY_DEBUG", "true").lower() == "true",
    
    # Debug level: DEBUG, INFO, WARN, ERROR (default: INFO)
    "level": os.getenv("PROXY_DEBUG_LEVEL", "INFO").upper(),
    
    # Enable detailed SSL debugging
    "ssl_debug": os.getenv("PROXY_SSL_DEBUG", "true").lower() == "true",
    
    # Enable routing table debugging
    "routing_debug": os.getenv("PROXY_ROUTING_DEBUG", "true").lower() == "true",
    
    # Enable request/response debugging
    "request_debug": os.getenv("PROXY_REQUEST_DEBUG", "true").lower() == "true",
    
    # Enable WebSocket debugging
    "websocket_debug": os.getenv("PROXY_WEBSOCKET_DEBUG", "true").lower() == "true",
    
    # Enable certificate debugging
    "cert_debug": os.getenv("PROXY_CERT_DEBUG", "true").lower() == "true",
    
    # Log chunk processing (can be verbose)
    "chunk_debug": os.getenv("PROXY_CHUNK_DEBUG", "false").lower() == "true",
    
    # Log every N chunks (default: 10)
    "chunk_log_interval": int(os.getenv("PROXY_CHUNK_LOG_INTERVAL", "10")),
    
    # Enable traceback logging for errors
    "traceback_debug": os.getenv("PROXY_TRACEBACK_DEBUG", "true").lower() == "true",
    
    # Enable timing information
    "timing_debug": os.getenv("PROXY_TIMING_DEBUG", "false").lower() == "true",
}

def get_debug_config() -> Dict[str, Any]:
    """Get the current debug configuration"""
    return DEBUG_CONFIG.copy()

def is_debug_enabled() -> bool:
    """Check if debugging is enabled"""
    return DEBUG_CONFIG["enabled"]

def get_debug_level() -> str:
    """Get the current debug level"""
    return DEBUG_CONFIG["level"]

def should_debug_ssl() -> bool:
    """Check if SSL debugging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["ssl_debug"]

def should_debug_routing() -> bool:
    """Check if routing debugging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["routing_debug"]

def should_debug_requests() -> bool:
    """Check if request debugging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["request_debug"]

def should_debug_websockets() -> bool:
    """Check if WebSocket debugging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["websocket_debug"]

def should_debug_certs() -> bool:
    """Check if certificate debugging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["cert_debug"]

def should_debug_chunks() -> bool:
    """Check if chunk debugging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["chunk_debug"]

def should_log_tracebacks() -> bool:
    """Check if traceback logging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["traceback_debug"]

def should_debug_timing() -> bool:
    """Check if timing debugging is enabled"""
    return DEBUG_CONFIG["enabled"] and DEBUG_CONFIG["timing_debug"]

def get_chunk_log_interval() -> int:
    """Get the chunk logging interval"""
    return DEBUG_CONFIG["chunk_log_interval"]

# Example usage and configuration
if __name__ == "__main__":
    print("HTTP Proxy Debug Configuration")
    print("==============================")
    print()
    
    print("Environment Variables:")
    print("  PROXY_DEBUG=true|false          - Enable/disable debugging")
    print("  PROXY_DEBUG_LEVEL=DEBUG|INFO|WARN|ERROR - Set debug level")
    print("  PROXY_SSL_DEBUG=true|false      - Enable SSL debugging")
    print("  PROXY_ROUTING_DEBUG=true|false  - Enable routing debugging")
    print("  PROXY_REQUEST_DEBUG=true|false  - Enable request debugging")
    print("  PROXY_WEBSOCKET_DEBUG=true|false - Enable WebSocket debugging")
    print("  PROXY_CERT_DEBUG=true|false     - Enable certificate debugging")
    print("  PROXY_CHUNK_DEBUG=true|false    - Enable chunk debugging")
    print("  PROXY_TRACEBACK_DEBUG=true|false - Enable traceback logging")
    print("  PROXY_TIMING_DEBUG=true|false   - Enable timing debugging")
    print("  PROXY_CHUNK_LOG_INTERVAL=10     - Log every N chunks")
    print()
    
    print("Current Configuration:")
    config = get_debug_config()
    for key, value in config.items():
        print(f"  {key}: {value}")
    print()
    
    print("Debug Features:")
    print(f"  SSL Debugging: {'✓' if should_debug_ssl() else '✗'}")
    print(f"  Routing Debugging: {'✓' if should_debug_routing() else '✗'}")
    print(f"  Request Debugging: {'✓' if should_debug_requests() else '✗'}")
    print(f"  WebSocket Debugging: {'✓' if should_debug_websockets() else '✗'}")
    print(f"  Certificate Debugging: {'✓' if should_debug_certs() else '✗'}")
    print(f"  Chunk Debugging: {'✓' if should_debug_chunks() else '✗'}")
    print(f"  Traceback Logging: {'✓' if should_log_tracebacks() else '✗'}")
    print(f"  Timing Debugging: {'✓' if should_debug_timing() else '✗'}")
