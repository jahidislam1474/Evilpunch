#!/usr/bin/env python3
"""
Test script to verify the replacement map logic with real proxy_host scenario
"""

import sys
from pathlib import Path

# Add the evilpunch package to the path
sys.path.insert(0, str(Path(__file__).parent / "evilpunch"))

def test_real_scenario():
    """Test the replacement map logic with real proxy_host values"""
    print("🧪 Testing Real Scenario Replacement Map Logic...")
    
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
    
    # Test with different proxy_host scenarios
    test_cases = [
        "test.xx.in",    # Subdomain + base domain
        "xx.in",         # Base domain only
        "www.xx.in",     # Another subdomain + base domain
        "sub.test.xx.in" # Multiple subdomains
    ]
    
    for proxy_host in test_cases:
        print(f"\n{'='*60}")
        print(f"Testing with proxy_host: {proxy_host}")
        print(f"{'='*60}")
        
        # Extract base domain from proxy_host (e.g., 'test.xx.in' -> 'xx.in')
        base_domain = proxy_host
        if '.' in proxy_host:
            # Split by dots and take the last two parts for the base domain
            parts = proxy_host.split('.')
            if len(parts) >= 2:
                base_domain = '.'.join(parts[-2:])
        
        print(f"Extracted base_domain: {base_domain}")
        
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
                proxy_hostname = f"{proxy_subdomain}.{base_domain}"
            else:
                proxy_hostname = base_domain
            
            # Build the original hostname to replace with
            original_hostname = original_host
            
            replacement_map[proxy_hostname] = original_hostname
            
        print(f"Replacement map: {replacement_map}")
        
        # Sort by length (longest first) to ensure specific subdomains are processed before base domains
        sorted_replacements = sorted(replacement_map.items(), key=lambda x: len(x[0]), reverse=True)
        print(f"Sorted replacements: {sorted_replacements}")
        
        # Test the replacement logic
        test_headers = {
            'Host': f'www.{base_domain}',
            'Referer': f'https://www.{base_domain}/login',
            'Origin': f'https://test.{base_domain}',
            'X-Forwarded-Host': base_domain,
            'Content-Type': 'application/json'
        }
        
        print(f"Test headers: {test_headers}")
        
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
        
        # Check if all replacements are correct
        all_correct = True
        for key in test_headers:
            if test_headers[key] != expected_replacements[key]:
                print(f"❌ {key}: Expected '{expected_replacements[key]}', got '{test_headers[key]}'")
                all_correct = False
            else:
                print(f"✅ {key}: '{test_headers[key]}'")
        
        if all_correct:
            print(f"🎉 All replacements correct for proxy_host: {proxy_host}")
        else:
            print(f"💥 Some replacements incorrect for proxy_host: {proxy_host}")
            return False
    
    return True

if __name__ == "__main__":
    print("🚀 Testing Real Scenario Replacement Map Logic")
    print("=" * 60)
    
    success = test_real_scenario()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Real scenario test: {'✅ PASSED' if success else '❌ FAILED'}")
    
    if success:
        print("\n🎉 All real scenario tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some real scenario tests failed!")
        sys.exit(1)
