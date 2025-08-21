#!/usr/bin/env python3
"""
Test script for the new is_cache_enabled field in Phishlet model.
This script tests the caching behavior based on the phishlet-specific cache setting.
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

def test_phishlet_cache_field():
    """
    Test the is_cache_enabled field functionality.
    """
    print("🧪 Testing Phishlet Cache Field")
    print("=" * 50)
    
    try:
        # Get all phishlets
        phishlets = Phishlet.objects.all()
        print(f"Found {phishlets.count()} phishlets")
        
        if phishlets.count() == 0:
            print("⚠️  No phishlets found. Please create some phishlets first.")
            return
        
        print("\n📋 Phishlet Cache Settings:")
        print("-" * 30)
        
        for phishlet in phishlets:
            cache_enabled = getattr(phishlet, 'is_cache_enabled', True)
            status = "✅ ENABLED" if cache_enabled else "❌ DISABLED"
            print(f"  {phishlet.name}: {status}")
            
            if hasattr(phishlet, 'is_cache_enabled'):
                print(f"    Field exists: ✅")
                print(f"    Field value: {phishlet.is_cache_enabled}")
                print(f"    Field type: {type(phishlet.is_cache_enabled)}")
            else:
                print(f"    Field exists: ❌")
        
        print("\n🔧 Testing Field Modification:")
        print("-" * 30)
        
        # Test modifying the cache field
        first_phishlet = phishlets.first()
        if first_phishlet:
            original_value = getattr(first_phishlet, 'is_cache_enabled', True)
            print(f"  Original value for '{first_phishlet.name}': {original_value}")
            
            # Toggle the value
            new_value = not original_value
            setattr(first_phishlet, 'is_cache_enabled', new_value)
            first_phishlet.save()
            
            # Verify the change
            first_phishlet.refresh_from_db()
            updated_value = getattr(first_phishlet, 'is_cache_enabled', True)
            print(f"  Updated value for '{first_phishlet.name}': {updated_value}")
            
            if updated_value == new_value:
                print("  ✅ Field modification successful")
            else:
                print("  ❌ Field modification failed")
            
            # Restore original value
            setattr(first_phishlet, 'is_cache_enabled', original_value)
            first_phishlet.save()
            print(f"  Restored original value: {original_value}")
        
        print("\n📊 Cache Field Statistics:")
        print("-" * 30)
        
        enabled_count = sum(1 for p in phishlets if getattr(p, 'is_cache_enabled', True))
        disabled_count = len(phishlets) - enabled_count
        
        print(f"  Total phishlets: {len(phishlets)}")
        print(f"  Cache enabled: {enabled_count}")
        print(f"  Cache disabled: {disabled_count}")
        print(f"  Default behavior: {'Enabled' if enabled_count > disabled_count else 'Disabled'}")
        
        print("\n✅ Testing complete!")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

def test_cache_field_in_admin():
    """
    Test that the field is properly configured in admin.
    """
    print("\n🔧 Testing Admin Configuration:")
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

if __name__ == "__main__":
    print("🚀 Phishlet Cache Field Testing")
    print("=" * 60)
    
    # Test the field functionality
    test_phishlet_cache_field()
    
    # Test admin configuration
    test_cache_field_in_admin()
    
    print("\n💡 Tips:")
    print("   - Use Django admin to toggle cache settings per phishlet")
    print("   - Cache settings are per-phishlet, not global")
    print("   - Default value is True (enabled)")
    print("   - Changes take effect immediately")
