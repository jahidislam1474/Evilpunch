#!/usr/bin/env python3
"""
Test script for multiprocessing HTTP proxy server
"""

import os
import sys
import time
import requests
import subprocess
from pathlib import Path

# Add the evilpunch package to the path
sys.path.insert(0, str(Path(__file__).parent / "evilpunch"))

def test_multiprocessing_proxy():
    """Test the multiprocessing proxy server"""
    print("=== Testing Multiprocessing HTTP Proxy Server ===")
    
    try:
        # Import the proxy server module
        from core.http_server import (
            start_proxy_server, 
            stop_proxy_server, 
            get_proxy_status,
            get_multiprocessing_stats,
            WORKER_PROCESSES,
            MULTIPROCESSING_ENABLED,
            MULTIPROCESSING_MODE
        )
        
        print(f"Multiprocessing enabled: {MULTIPROCESSING_ENABLED}")
        print(f"Multiprocessing mode: {MULTIPROCESSING_MODE}")
        print(f"Worker processes: {WORKER_PROCESSES}")
        
        # Test 1: Start the proxy server
        print("\n1. Starting proxy server...")
        result = start_proxy_server(port=8080)
        print(f"Start result: {result}")
        
        if not result.get("ok"):
            print("Failed to start proxy server")
            return False
        
        # Wait for server to start
        time.sleep(2)
        
        # Test 2: Check server status
        print("\n2. Checking server status...")
        status = get_proxy_status()
        print(f"Server status: {status}")
        
        if not status.get("running"):
            print("Server is not running")
            return False
        
        # Test 3: Check multiprocessing stats
        print("\n3. Checking multiprocessing stats...")
        try:
            stats = get_multiprocessing_stats()
            print(f"Multiprocessing stats: {stats}")
        except Exception as e:
            print(f"Error getting multiprocessing stats: {e}")
        
        # Test 4: Test HTTP endpoints
        print("\n4. Testing HTTP endpoints...")
        try:
            # Test multiprocessing stats endpoint
            response = requests.get("http://localhost:8080/_multiprocessing/stats", timeout=5)
            print(f"Multiprocessing stats endpoint: {response.status_code}")
            if response.status_code == 200:
                print(f"Response: {response.json()}")
            
            # Test cache stats endpoint
            response = requests.get("http://localhost:8080/_cache/stats", timeout=5)
            print(f"Cache stats endpoint: {response.status_code}")
            
        except requests.exceptions.RequestException as e:
            print(f"Error testing HTTP endpoints: {e}")
        
        # Test 5: Stop the proxy server
        print("\n5. Stopping proxy server...")
        result = stop_proxy_server()
        print(f"Stop result: {result}")
        
        # Wait for server to stop
        time.sleep(2)
        
        # Test 6: Final status check
        print("\n6. Final status check...")
        status = get_proxy_status()
        print(f"Final status: {status}")
        
        if not status.get("running"):
            print("✅ Test completed successfully!")
            return True
        else:
            print("❌ Server is still running after stop command")
            return False
            
    except ImportError as e:
        print(f"Import error: {e}")
        return False
    except Exception as e:
        print(f"Test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_environment_variables():
    """Test environment variable configuration"""
    print("\n=== Testing Environment Variables ===")
    
    # Test different configurations
    configs = [
        {"PROXY_MULTIPROCESSING_ENABLED": "true", "PROXY_WORKER_PROCESSES": "4"},
        {"PROXY_MULTIPROCESSING_ENABLED": "false"},
        {"PROXY_MULTIPROCESSING_MODE": "thread"},
    ]
    
    for config in configs:
        print(f"\nTesting config: {config}")
        
        # Set environment variables
        for key, value in config.items():
            os.environ[key] = value
        
        try:
            # Import and check configuration
            from core.http_server import (
                MULTIPROCESSING_ENABLED,
                MULTIPROCESSING_MODE,
                WORKER_PROCESSES
            )
            
            print(f"  Multiprocessing enabled: {MULTIPROCESSING_ENABLED}")
            print(f"  Multiprocessing mode: {MULTIPROCESSING_MODE}")
            print(f"  Worker processes: {WORKER_PROCESSES}")
            
        except Exception as e:
            print(f"  Error: {e}")
        
        # Clean up environment variables
        for key in config:
            if key in os.environ:
                del os.environ[key]

if __name__ == "__main__":
    print("Starting multiprocessing proxy tests...")
    
    # Test environment variables
    test_environment_variables()
    
    # Test the actual proxy server
    success = test_multiprocessing_proxy()
    
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)
