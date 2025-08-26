#!/usr/bin/env python3
"""
Test script to verify the replacement map logic for proxy host filtering
"""

import sys
from pathlib import Path

# Add the evilpunch package to the path
sys.path.insert(0, str(Path(__file__).parent / "evilpunch"))

def test_replacement_map():
    """Test the replacement map logic"""
    print("🧪 Testing Replacement Map Logic...")
    
    # Simulate the hosts_to_proxy configuration
    hosts_to_proxy = [
        {
            'host': 'www.rullout.com', 
            'orignal_subdomain': 'www', 
            'proxy_subdomain': 'www', 
            'reverce_filter': True, 
            'auto_filter': True
        }, 
        {
            'host': 'buck.rullout.com', 
            'orignal_subdomain': 'buck', 
            'proxy_subdomain': 'test', 
            'reverce_filter': True, 
            'auto_filter': True
        }, 
        {
            'host': 'rullout.com', 
            'orignal_subdomain': '', 
            'proxy_subdomain': '', 
            'reverce_filter': True, 
            'auto_filter': True
        }
    ]
    
    proxy_host = "xx.in"
    
    print(f"Hosts to proxy: {hosts_to_proxy}")
    print(f"Proxy host: {proxy_host}")
    
    # Build replacement mapping: proxy_hostname -> original_hostname
    replacement_map = {}
    
    for host_entry in hosts_to_proxy:
        if not host_entry.get('reverce_filter', False):
            continue
            
        original_host = host_entry.get('host', '').strip()
        proxy_subdomain = host_entry.get('proxy_subdomain', '').strip()
        original_subdomain = host_entry.get('orignal_subdomain', '').strip()
        
        if not original_host:
            continue
        
        # Build the proxy hostname that should be replaced
        if proxy_subdomain:
            proxy_hostname = f"{proxy_subdomain}.{proxy_host}"
        else:
            proxy_hostname = proxy_host
        
        # Build the original hostname to replace with
        original_hostname = original_host
        
        replacement_map[proxy_hostname] = original_hostname
        
    print(f"\nReplacement map: {replacement_map}")
    
    # Sort by length (longest first) to ensure specific subdomains are processed before base domains
    sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
    print(f"Sorted replacements: {sorted_replacements}")
    
    # Test the replacement logic
    test_headers = {
        'Host': 'www.xx.in',
        'Referer': 'https://www.xx.in/login',
        'Origin': 'https://test.xx.in',
        'X-Forwarded-Host': 'xx.in',
        'Content-Type': 'application/json'
    }
    
    print(f"\nOriginal headers: {test_headers}")
    
    # Apply replacements to headers
    for key, value in test_headers.items():
        if isinstance(value, str):
            modified_value = value
            
            # Use a single-pass replacement with a unique marker approach
            import re
            
            # Create a mapping with unique markers
            marker_map = {}
            marked_value = value
            
            # Step 1: Replace each proxy hostname with a unique marker
            for i, (proxy_hostname, original_hostname) in enumerate(sorted_replacements):
                marker = f"__REVERSE_FILTER_MARKER_{i}__"
                marker_map[marker] = original_hostname
                
                # Escape special regex characters
                escaped_proxy = re.escape(proxy_hostname)
                # Use a pattern that matches the exact hostname with proper boundaries
                pattern = rf'(?<![A-Za-z0-9.-]){escaped_proxy}(?![A-Za-z0-9.-])'
                marked_value = re.sub(pattern, marker, marked_value)
            
            # Step 2: Replace all markers with their original hostnames
            for marker, original_hostname in marker_map.items():
                marked_value = marked_value.replace(marker, original_hostname)
            
            test_headers[key] = marked_value
    
    print(f"Modified headers: {test_headers}")
    
    # Verify the replacements
    expected_replacements = {
        'Host': 'www.rullout.com',
        'Referer': 'https://www.rullout.com/login',
        'Origin': 'https://buck.rullout.com',
        'X-Forwarded-Host': 'rullout.com',
        'Content-Type': 'application/json'
    }
    
    print(f"\nExpected replacements: {expected_replacements}")
    
    # Check if all replacements are correct
    all_correct = True
    for key in test_headers:
        if test_headers[key] != expected_replacements[key]:
            print(f"❌ {key}: Expected '{expected_replacements[key]}', got '{test_headers[key]}'")
            all_correct = False
        else:
            print(f"✅ {key}: '{test_headers[key]}'")
    
    if all_correct:
        print("\n🎉 All replacements are correct!")
        return True
    else:
        print("\n💥 Some replacements are incorrect!")
        return False

if __name__ == "__main__":
    print("🚀 Testing Replacement Map for Proxy Host Filtering")
    print("=" * 60)
    
    success = test_replacement_map()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Replacement map test: {'✅ PASSED' if success else '❌ FAILED'}")
    
    if success:
        print("\n🎉 Replacement map logic is working correctly!")
        sys.exit(0)
    else:
        print("\n💥 Replacement map logic has issues!")
        sys.exit(1)
