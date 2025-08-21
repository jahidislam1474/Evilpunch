#!/usr/bin/env python3
"""
Test script for the cache toggle UI functionality.
This script tests the new cache toggle buttons and functionality.
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

def test_cache_toggle_functionality():
    """
    Test the cache toggle functionality.
    """
    print("🧪 Testing Cache Toggle Functionality")
    print("=" * 50)
    
    try:
        # Get all phishlets
        phishlets = Phishlet.objects.all()
        print(f"Found {phishlets.count()} phishlets")
        
        if phishlets.count() == 0:
            print("⚠️  No phishlets found. Please create some phishlets first.")
            return
        
        print("\n📋 Current Cache Settings:")
        print("-" * 30)
        
        for phishlet in phishlets:
            cache_enabled = getattr(phishlet, 'is_cache_enabled', True)
            status = "✅ ENABLED" if cache_enabled else "❌ DISABLED"
            print(f"  {phishlet.name}: {status}")
        
        print("\n🔧 Testing Cache Toggle:")
        print("-" * 30)
        
        # Test toggling cache for first phishlet
        first_phishlet = phishlets.first()
        if first_phishlet:
            original_value = getattr(first_phishlet, 'is_cache_enabled', True)
            print(f"  Original cache setting for '{first_phishlet.name}': {original_value}")
            
            # Toggle the cache setting
            new_value = not original_value
            setattr(first_phishlet, 'is_cache_enabled', new_value)
            first_phishlet.save()
            
            # Verify the change
            first_phishlet.refresh_from_db()
            updated_value = getattr(first_phishlet, 'is_cache_enabled', True)
            print(f"  Updated cache setting for '{first_phishlet.name}': {updated_value}")
            
            if updated_value == new_value:
                print("  ✅ Cache toggle successful")
            else:
                print("  ❌ Cache toggle failed")
            
            # Restore original value
            setattr(first_phishlet, 'is_cache_enabled', original_value)
            first_phishlet.save()
            print(f"  Restored original cache setting: {original_value}")
        
        print("\n📊 Cache Settings Summary:")
        print("-" * 30)
        
        enabled_count = sum(1 for p in phishlets if getattr(p, 'is_cache_enabled', True))
        disabled_count = len(phishlets) - enabled_count
        
        print(f"  Total phishlets: {len(phishlets)}")
        print(f"  Cache enabled: {enabled_count}")
        print(f"  Cache disabled: {disabled_count}")
        
        print("\n✅ Testing complete!")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

def test_admin_integration():
    """
    Test that the cache field is properly integrated in admin.
    """
    print("\n🔧 Testing Admin Integration:")
    print("-" * 30)
    
    try:
        from django.contrib import admin
        from core.admin import PhishletAdmin
        
        # Check if field is in list_display
        if 'is_cache_enabled' in PhishletAdmin.list_display:
            print("  ✅ Field in list_display")
        else:
            print("  ❌ Field not in list_display")
        
        # Check if field is in list_filter
        if 'is_cache_enabled' in PhishletAdmin.list_filter:
            print("  ✅ Field in list_filter")
        else:
            print("  ❌ Field not in list_filter")
        
        # Check if field is in fieldsets
        field_in_fieldsets = False
        for fieldset_name, fieldset_options in PhishletAdmin.fieldsets:
            if 'is_cache_enabled' in fieldset_options.get('fields', []):
                field_in_fieldsets = True
                break
        
        if field_in_fieldsets:
            print("  ✅ Field in fieldsets")
        else:
            print("  ❌ Field not in fieldsets")
            
    except Exception as e:
        print(f"  ❌ Error checking admin config: {e}")

def test_url_patterns():
    """
    Test that the URL patterns are properly configured.
    """
    print("\n🔧 Testing URL Patterns:")
    print("-" * 30)
    
    try:
        from django.urls import reverse, NoReverseMatch
        
        # Test the cache toggle URL
        try:
            # Get a phishlet to test with
            phishlet = Phishlet.objects.first()
            if phishlet:
                url = reverse('phishlet_toggle_cache', kwargs={'pk': phishlet.id})
                print(f"  ✅ Cache toggle URL pattern works: {url}")
            else:
                print("  ⚠️  No phishlets available to test URL pattern")
        except NoReverseMatch as e:
            print(f"  ❌ Cache toggle URL pattern failed: {e}")
            
    except Exception as e:
        print(f"  ❌ Error checking URL patterns: {e}")

def main():
    """
    Main test function.
    """
    print("🚀 Cache Toggle UI Testing")
    print("=" * 60)
    
    # Test the field functionality
    test_cache_toggle_functionality()
    
    # Test admin configuration
    test_admin_integration()
    
    # Test URL patterns
    test_url_patterns()
    
    print("\n💡 Tips:")
    print("   - Use the cache toggle buttons in the phishlet list")
    print("   - Changes take effect immediately")
    print("   - Cache settings are per-phishlet")
    print("   - Use Django admin for bulk operations")

if __name__ == "__main__":
    main()
