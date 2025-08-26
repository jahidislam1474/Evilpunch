#!/usr/bin/env python3
"""
Test script to verify that the signal handler error is fixed
"""

import os
import sys
import time
from pathlib import Path

# Add the evilpunch package to the path
sys.path.insert(0, str(Path(__file__).parent / "evilpunch"))

def test_multiprocessing_startup():
    """Test that multiprocessing server can start without signal handler errors"""
    print("🧪 Testing multiprocessing server startup...")
    
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
        
        # Test 1: Start the proxy server
        print("\n1. Starting proxy server...")
        result = start_proxy_server(port=8081)  # Use different port
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
            print("✅ Test completed successfully!")
            return True
        else:
            print("❌ Server is still running after stop command")
            return False
            
    except Exception as e:
        print(f"❌ Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_signal_handler_setup():
    """Test that signal handler setup works correctly"""
    print("\n🔧 Testing signal handler setup...")
    
    try:
        from core.http_server import _setup_multiprocessing
        import multiprocessing
        
        print(f"Current process: {multiprocessing.current_process().name}")
        
        # Test signal handler setup
        _setup_multiprocessing()
        print("✅ Signal handler setup completed without errors")
        
        return True
        
    except Exception as e:
        print(f"❌ Signal handler setup error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 Testing Signal Handler Fix")
    print("=" * 40)
    
    # Test signal handler setup
    signal_test = test_signal_handler_setup()
    
    # Test multiprocessing startup
    startup_test = test_multiprocessing_startup()
    
    # Summary
    print("\n" + "=" * 40)
    print("TEST SUMMARY")
    print("=" * 40)
    print(f"Signal handler setup: {'✅ PASSED' if signal_test else '❌ FAILED'}")
    print(f"Multiprocessing startup: {'✅ PASSED' if startup_test else '❌ FAILED'}")
    
    if signal_test and startup_test:
        print("\n🎉 All tests passed! Signal handler error is fixed.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)
