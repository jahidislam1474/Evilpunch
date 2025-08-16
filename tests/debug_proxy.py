#!/usr/bin/env python3
"""
Debug script to test proxy configuration
"""
import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'evilpunch'))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
django.setup()

from core.models import Phishlet, Proxy
from core.http_server import get_proxy_config

def debug_proxy_configuration():
    """Debug the proxy configuration"""
    print("=== DEBUGGING PROXY CONFIGURATION ===\n")
    
    # Get all phishlets with their proxy info
    phishlets = Phishlet.objects.filter(is_active=True).select_related('proxy')
    
    for phishlet in phishlets:
        print(f"Phishlet: {phishlet.name}")
        print(f"  ID: {phishlet.id}")
        print(f"  Active: {phishlet.is_active}")
        print(f"  Proxy assigned: {phishlet.proxy}")
        
        if phishlet.proxy:
            print(f"  Proxy details:")
            print(f"    Name: {phishlet.proxy.name}")
            print(f"    Type: {phishlet.proxy.proxy_type}")
            print(f"    Host: {phishlet.proxy.host}")
            print(f"    Port: {phishlet.proxy.port}")
            print(f"    Username: {phishlet.proxy.username}")
            print(f"    Password: {'***' if phishlet.proxy.password else 'None'}")
            print(f"    Active: {phishlet.proxy.is_active}")
            print(f"    Proxy URL: {phishlet.proxy.get_proxy_url()}")
            
            # Test the proxy config function
            proxy_info = {
                'type': phishlet.proxy.proxy_type,
                'host': phishlet.proxy.host,
                'port': phishlet.proxy.port,
                'username': phishlet.proxy.username,
                'password': phishlet.proxy.password,
                'url': phishlet.proxy.get_proxy_url()
            }
            
            print(f"  Proxy info dict: {proxy_info}")
            
            config = get_proxy_config(proxy_info)
            print(f"  aiohttp config: {config}")
            
            if config:
                print(f"  ✅ Proxy configuration generated successfully")
            else:
                print(f"  ❌ Proxy configuration failed")
        else:
            print(f"  ❌ No proxy assigned")
        
        print()
    
    # Test the get_proxy_config function directly
    print("=== TESTING get_proxy_config FUNCTION ===\n")
    
    # Test with empty dict
    result = get_proxy_config({})
    print(f"Empty dict: {result}")
    
    # Test with None
    result = get_proxy_config(None)
    print(f"None: {result}")
    
    # Test with missing host
    result = get_proxy_config({'type': 'http', 'port': 8080})
    print(f"Missing host: {result}")
    
    # Test with valid HTTP proxy
    result = get_proxy_config({
        'type': 'http',
        'host': 'test.proxy.com',
        'port': 8080,
        'username': '',
        'password': ''
    })
    print(f"Valid HTTP proxy: {result}")
    
    # Test with valid HTTP proxy with auth
    result = get_proxy_config({
        'type': 'http',
        'host': 'test.proxy.com',
        'port': 8080,
        'username': 'user',
        'password': 'pass'
    })
    print(f"Valid HTTP proxy with auth: {result}")

if __name__ == "__main__":
    debug_proxy_configuration()
