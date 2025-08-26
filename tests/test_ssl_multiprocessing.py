#!/usr/bin/env python3
"""
Test script to verify SSL multiprocessing functionality
"""

import os
import sys
import time
from pathlib import Path

# Add the evilpunch package to the path
sys.path.insert(0, str(Path(__file__).parent / "evilpunch"))

def test_ssl_multiprocessing():
    """Test multiprocessing server with SSL context"""
    print("🔒 Testing SSL Multiprocessing...")
    
    try:
        from core.http_server import (
            start_proxy_server, 
            stop_proxy_server, 
            get_proxy_status,
            MULTIPROCESSING_ENABLED,
            WORKER_PROCESSES
        )
        
        print(f"✅ Multiprocessing enabled: {MULTIPROCESSING_ENABLED}")
        print(f"✅ Worker processes: {WORKER_PROCESSES}")
        
        # Test 1: Start the proxy server with SSL
        print("\n1. Starting proxy server with SSL...")
        result = start_proxy_server(port=8082)
        print(f"Start result: {result}")
        
        if not result.get("ok"):
            print("❌ Failed to start proxy server")
            return False
        
        # Wait for server to start
        print("Waiting for server to start...")
        time.sleep(3)
        
        # Test 2: Check server status
        print("\n2. Checking server status...")
        status = get_proxy_status()
        print(f"Server status: {status}")
        
        if not status.get("running"):
            print("❌ Server is not running")
            return False
        
        print(f"✅ Server mode: {status.get('mode')}")
        print(f"✅ Server scheme: {status.get('scheme')}")
        print(f"✅ Active workers: {status.get('active_workers')}")
        
        # Test 3: Stop the proxy server
        print("\n3. Stopping proxy server...")
        result = stop_proxy_server()
        print(f"Stop result: {result}")
        
        # Wait for server to stop
        time.sleep(2)
        
        # Test 4: Final status check
        print("\n4. Final status check...")
        status = get_proxy_status()
        print(f"Final status: {status}")
        
        if not status.get("running"):
            print("✅ SSL multiprocessing test completed successfully!")
            return True
        else:
            print("❌ Server is still running after stop command")
            return False
            
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_http_multiprocessing():
    """Test multiprocessing server with HTTP (no SSL)"""
    print("\n🌐 Testing HTTP Multiprocessing...")
    
    try:
        from core.http_server import (
            start_proxy_server, 
            stop_proxy_server, 
            get_proxy_status
        )
        
        # Test 1: Start the proxy server with HTTP
        print("\n1. Starting proxy server with HTTP...")
        result = start_proxy_server(port=8083)
        print(f"Start result: {result}")
        
        if not result.get("ok"):
            print("❌ Failed to start proxy server")
            return False
        
        # Wait for server to start
        print("Waiting for server to start...")
        time.sleep(3)
        
        # Test 2: Check server status
        print("\n2. Checking server status...")
        status = get_proxy_status()
        print(f"Server status: {status}")
        
        if not status.get("running"):
            print("❌ Server is not running")
            return False
        
        print(f"✅ Server mode: {status.get('mode')}")
        print(f"✅ Server scheme: {status.get('scheme')}")
        print(f"✅ Active workers: {status.get('active_workers')}")
        
        # Test 3: Stop the proxy server
        print("\n3. Stopping proxy server...")
        result = stop_proxy_server()
        print(f"Stop result: {result}")
        
        # Wait for server to stop
        time.sleep(2)
        
        # Test 4: Final status check
        print("\n4. Final status check...")
        status = get_proxy_status()
        print(f"Final status: {status}")
        
        if not status.get("running"):
            print("✅ HTTP multiprocessing test completed successfully!")
            return True
        else:
            print("❌ Server is still running after stop command")
            return False
            
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 Testing SSL/HTTP Multiprocessing")
    print("=" * 50)
    
    # Test HTTP multiprocessing
    http_test = test_http_multiprocessing()
    
    # Test SSL multiprocessing
    ssl_test = test_ssl_multiprocessing()
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    print(f"HTTP multiprocessing: {'✅ PASSED' if http_test else '❌ FAILED'}")
    print(f"SSL multiprocessing: {'✅ PASSED' if ssl_test else '❌ FAILED'}")
    
    if http_test and ssl_test:
        print("\n🎉 All SSL/HTTP tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)
