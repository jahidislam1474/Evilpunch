#!/usr/bin/env python3
"""
Test script for the clear cache functionality.
This script tests the new clear cache button and functionality.
"""

import os
import sys
import django

# Add the parent directory to the path so we can import from evilpunch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
django.setup()

from core.models import Phishlet
from pathlib import Path

def test_clear_cache_functionality():
    """
    Test the clear cache functionality.
    """
    print("🧪 Testing Clear Cache Functionality")
    print("=" * 50)
    
    try:
        # Get all phishlets
        phishlets = Phishlet.objects.all()
        print(f"Found {phishlets.count()} phishlets")
        
        if phishlets.count() == 0:
            print("⚠️  No phishlets found. Please create some phishlets first.")
            return
        
        print("\n📋 Current Phishlets:")
        print("-" * 30)
        
        for phishlet in phishlets:
            cache_enabled = getattr(phishlet, 'is_cache_enabled', True)
            status = "✅ ENABLED" if cache_enabled else "❌ DISABLED"
            print(f"  {phishlet.name}: {status}")
        
        print("\n🔧 Testing Cache Directory Structure:")
        print("-" * 30)
        
        # Check if cache folder exists
        cache_folder = Path('cache_folder')
        if cache_folder.exists():
            print(f"  Cache folder found: {cache_folder}")
            
            # Check phishlet-specific cache directories
            for phishlet_dir in cache_folder.iterdir():
                if phishlet_dir.is_dir():
                    cache_files = list(phishlet_dir.glob('*'))
                    meta_files = list(phishlet_dir.glob('*.meta'))
                    content_files = [f for f in cache_files if f.suffix != '.meta']
                    
                    print(f"    {phishlet_dir.name}: {len(content_files)} cache files, {len(meta_files)} meta files")
                    
                    # Show some file details
                    for cache_file in content_files[:3]:  # Show first 3 files
                        try:
                            size = cache_file.stat().st_size
                            print(f"      - {cache_file.name}: {size} bytes")
                        except:
                            print(f"      - {cache_file.name}: error reading size")
                    
                    if len(content_files) > 3:
                        print(f"      ... and {len(content_files) - 3} more files")
        else:
            print("  Cache folder not found. Creating test structure...")
            cache_folder.mkdir(exist_ok=True)
            
            # Create test cache structure
            test_phishlet_dir = cache_folder / "test_phishlet"
            test_phishlet_dir.mkdir(exist_ok=True)
            
            # Create test cache files
            test_files = [
                ("test1.js", "console.log('test1');"),
                ("test2.css", "body { color: red; }"),
                ("test3.png", b"fake_png_data"),
            ]
            
            for filename, content in test_files:
                file_path = test_phishlet_dir / filename
                if isinstance(content, str):
                    file_path.write_text(content)
                else:
                    file_path.write_bytes(content)
                
                # Create metadata file
                meta_path = test_phishlet_dir / f"{filename}.meta"
                import json
                metadata = {
                    'url_path': f'/static/{filename}',
                    'target_host': 'example.com',
                    'content_type': 'text/plain',
                    'cache_time': 1234567890,
                    'file_size': len(content) if isinstance(content, str) else len(content),
                    'cache_file_path': str(file_path)
                }
                meta_path.write_text(json.dumps(metadata, indent=2))
            
            print(f"  Created test cache structure in {test_phishlet_dir}")
        
        print("\n🔧 Testing URL Patterns:")
        print("-" * 30)
        
        try:
            from django.urls import reverse, NoReverseMatch
            
            # Test the clear cache URL
            first_phishlet = phishlets.first()
            if first_phishlet:
                url = reverse('phishlet_clear_cache', kwargs={'pk': first_phishlet.id})
                print(f"  ✅ Clear cache URL pattern works: {url}")
            else:
                print("  ⚠️  No phishlets available to test URL pattern")
                
        except NoReverseMatch as e:
            print(f"  ❌ Clear cache URL pattern failed: {e}")
            
        print("\n🔧 Testing View Function:")
        print("-" * 30)
        
        try:
            from core.views import phishlet_clear_cache_view
            print("  ✅ Clear cache view function imported successfully")
            
            # Check function signature
            import inspect
            sig = inspect.signature(phishlet_clear_cache_view)
            print(f"  ✅ Function signature: {sig}")
            
        except Exception as e:
            print(f"  ❌ Error importing clear cache view: {e}")
        
        print("\n💡 Usage Instructions:")
        print("-" * 30)
        print("  1. Navigate to the phishlet list page")
        print("  2. Find the 'Clear Cache' button for each phishlet")
        print("  3. Click to clear all cached files for that specific phishlet")
        print("  4. Confirm the action in the dialog")
        print("  5. See success/error feedback via toast notifications")
        
        print("\n✅ Testing complete!")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

def test_cache_folder_operations():
    """
    Test cache folder operations.
    """
    print("\n🔧 Testing Cache Folder Operations:")
    print("-" * 30)
    
    try:
        cache_folder = Path('cache_folder')
        
        if cache_folder.exists():
            print(f"  Cache folder exists: {cache_folder}")
            
            # Count total files and size
            total_files = 0
            total_size = 0
            
            for phishlet_dir in cache_folder.iterdir():
                if phishlet_dir.is_dir():
                    for cache_file in phishlet_dir.iterdir():
                        if cache_file.is_file():
                            total_files += 1
                            try:
                                total_size += cache_file.stat().st_size
                            except:
                                pass
            
            print(f"  Total cache files: {total_files}")
            print(f"  Total cache size: {total_size / (1024*1024):.2f} MB")
            
        else:
            print("  Cache folder does not exist")
            
    except Exception as e:
        print(f"  ❌ Error checking cache folder: {e}")

def main():
    """
    Main test function.
    """
    print("🚀 Clear Cache Functionality Testing")
    print("=" * 60)
    
    # Test the clear cache functionality
    test_clear_cache_functionality()
    
    # Test cache folder operations
    test_cache_folder_operations()
    
    print("\n💡 Tips:")
    print("   - Use the clear cache button in the phishlet list")
    print("   - Each phishlet has its own cache directory")
    print("   - Clearing cache is irreversible")
    print("   - Check the cache folder structure for verification")

if __name__ == "__main__":
    main()
