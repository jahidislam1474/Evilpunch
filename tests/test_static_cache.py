#!/usr/bin/env python3
"""
Test script for static file caching functionality.
This script demonstrates how the caching system works.
"""

import os
import sys
import time
import requests
import json

# Add the parent directory to the path so we can import from evilpunch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_cache_endpoints(base_url="http://localhost:8080"):
    """
    Test the cache management endpoints.
    """
    print("🧪 Testing Cache Management Endpoints")
    print("=" * 50)
    
    # Test cache configuration
    try:
        response = requests.get(f"{base_url}/_cache/config")
        if response.status_code == 200:
            config = response.json()
            print("✅ Cache Configuration:")
            print(f"   Enabled: {config.get('enabled')}")
            print(f"   Cache Folder: {config.get('cache_folder')}")
            print(f"   Max Size: {config.get('max_size_mb')}MB")
            print(f"   Max Age: {config.get('max_age_hours')} hours")
        else:
            print(f"❌ Failed to get cache config: {response.status_code}")
    except Exception as e:
        print(f"❌ Error getting cache config: {e}")
    
    print()
    
    # Test cache statistics
    try:
        response = requests.get(f"{base_url}/_cache/stats")
        if response.status_code == 200:
            stats = response.json()
            print("✅ Cache Statistics:")
            print(f"   Hits: {stats.get('hits')}")
            print(f"   Misses: {stats.get('misses')}")
            print(f"   Writes: {stats.get('writes')}")
            print(f"   Hit Rate: {stats.get('hit_rate_percent')}%")
            print(f"   Total Size: {stats.get('total_size_mb')}MB")
            print(f"   Actual Size: {stats.get('cache_info', {}).get('actual_size_mb', 'N/A')}MB")
            print(f"   Cached Files: {stats.get('cache_info', {}).get('total_cached_files', 'N/A')}")
        else:
            print(f"❌ Failed to get cache stats: {response.status_code}")
    except Exception as e:
        print(f"❌ Error getting cache stats: {e}")
    
    print()
    
    # Test cache directory info
    try:
        response = requests.get(f"{base_url}/_cache/directory")
        if response.status_code == 200:
            directory_info = response.json()
            print("✅ Cache Directory Info:")
            print(f"   Cache Folder: {directory_info.get('cache_folder')}")
            print(f"   Phishlet Directories: {len(directory_info.get('phishlets', {}))}")
            
            for phishlet_name, phishlet_info in directory_info.get('phishlets', {}).items():
                print(f"   📁 {phishlet_name}:")
                print(f"      Cache Files: {phishlet_info.get('cache_files')}")
                print(f"      Metadata Files: {phishlet_info.get('metadata_files')}")
                print(f"      Total Size: {phishlet_info.get('total_size_mb')}MB")
        else:
            print(f"❌ Failed to get cache directory info: {response.status_code}")
    except Exception as e:
        print(f"❌ Error getting cache directory info: {e}")

def test_cache_operations(base_url="http://localhost:8080"):
    """
    Test cache operations like cleanup and clear.
    """
    print("\n🧪 Testing Cache Operations")
    print("=" * 50)
    
    # Test cache cleanup
    try:
        response = requests.post(f"{base_url}/_cache/cleanup")
        if response.status_code == 200:
            result = response.json()
            print("✅ Cache Cleanup:")
            print(f"   Success: {result.get('success')}")
            print(f"   Message: {result.get('message')}")
        else:
            print(f"❌ Failed to run cache cleanup: {response.status_code}")
    except Exception as e:
        print(f"❌ Error running cache cleanup: {e}")
    
    print()
    
    # Test cache clear (commented out to avoid clearing cache during testing)
    print("⚠️  Cache Clear test skipped (to avoid clearing cache during testing)")
    print("   Use: POST /_cache/clear to manually clear cache")

def show_cache_folder_structure():
    """
    Show the actual cache folder structure on disk.
    """
    print("\n📁 Cache Folder Structure")
    print("=" * 50)
    
    cache_folder = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cache_folder")
    
    if not os.path.exists(cache_folder):
        print(f"❌ Cache folder does not exist: {cache_folder}")
        return
    
    print(f"Cache folder: {cache_folder}")
    
    for root, dirs, files in os.walk(cache_folder):
        level = root.replace(cache_folder, '').count(os.sep)
        indent = ' ' * 2 * level
        print(f"{indent}{os.path.basename(root)}/")
        subindent = ' ' * 2 * (level + 1)
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_size = os.path.getsize(file_path)
                size_str = f"{file_size} bytes"
                if file_size > 1024:
                    size_str = f"{file_size/1024:.1f} KB"
                if file_size > 1024*1024:
                    size_str = f"{file_size/(1024*1024):.1f} MB"
                print(f"{subindent}{file} ({size_str})")
            except:
                print(f"{subindent}{file}")

def main():
    """
    Main test function.
    """
    print("🚀 Static File Cache Testing")
    print("=" * 60)
    
    # Check if server is running
    base_url = "http://localhost:8080"
    
    try:
        response = requests.get(f"{base_url}/_cache/config", timeout=5)
        if response.status_code == 200:
            print(f"✅ Server is running at {base_url}")
        else:
            print(f"⚠️  Server responded with status {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to server at {base_url}")
        print("   Make sure the HTTP server is running")
        return
    except Exception as e:
        print(f"❌ Error connecting to server: {e}")
        return
    
    print()
    
    # Run tests
    test_cache_endpoints(base_url)
    test_cache_operations(base_url)
    show_cache_folder_structure()
    
    print("\n✅ Testing complete!")
    print("\n💡 Tips:")
    print("   - Cache is automatically managed based on file age and size limits")
    print("   - Static files are cached per phishlet in separate directories")
    print("   - Use the /_cache/* endpoints to monitor and manage cache")
    print("   - Cache configuration can be controlled via environment variables")

if __name__ == "__main__":
    main()
