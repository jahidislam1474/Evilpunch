#!/usr/bin/env python3
"""
Test script to verify proxy functionality
"""
import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
django.setup()

from core.models import Proxy, Phishlet

def test_proxy_creation():
    """Test creating a proxy"""
    print("Testing proxy creation...")
    
    # Create a test proxy
    proxy = Proxy.objects.create(
        name="Test HTTP Proxy",
        proxy_type="http",
        host="proxy.example.com",
        port=8080,
        username="testuser",
        password="testpass",
        is_active=True
    )
    
    print(f"Created proxy: {proxy}")
    print(f"Proxy URL: {proxy.get_proxy_url()}")
    print(f"Proxy type display: {proxy.get_proxy_type_display()}")
    
    return proxy

def test_phishlet_proxy_assignment():
    """Test assigning a proxy to a phishlet"""
    print("\nTesting phishlet proxy assignment...")
    
    # Get or create a test phishlet
    phishlet, created = Phishlet.objects.get_or_create(
        name="test-phishlet",
        defaults={
            "data": {"name": "Test Phishlet", "hosts_to_proxy": ["example.com"]},
            "is_active": True
        }
    )
    
    if created:
        print(f"Created test phishlet: {phishlet}")
    else:
        print(f"Using existing phishlet: {phishlet}")
    
    # Get the proxy we created
    proxy = Proxy.objects.filter(name="Test HTTP Proxy").first()
    if not proxy:
        print("No proxy found, creating one...")
        proxy = test_proxy_creation()
    
    # Assign proxy to phishlet
    phishlet.proxy = proxy
    phishlet.save()
    
    print(f"Assigned proxy {proxy.name} to phishlet {phishlet.name}")
    print(f"Phishlet proxy: {phishlet.proxy}")
    
    # Test the reverse relationship
    print(f"Phishlets using this proxy: {proxy.phishlets.all()}")
    
    return phishlet, proxy

def test_proxy_validation():
    """Test proxy validation"""
    print("\nTesting proxy validation...")
    
    try:
        # Try to create a proxy with invalid port
        invalid_proxy = Proxy(
            name="Invalid Proxy",
            proxy_type="http",
            host="test.com",
            port=70000,  # Invalid port
            is_active=True
        )
        invalid_proxy.full_clean()
        invalid_proxy.save()
        print("ERROR: Should have failed validation for invalid port")
    except Exception as e:
        print(f"Correctly caught validation error: {e}")
    
    try:
        # Try to create a proxy with valid port
        valid_proxy = Proxy(
            name="Valid Proxy",
            proxy_type="https",
            host="test.com",
            port=8443,  # Valid port
            is_active=True
        )
        valid_proxy.full_clean()
        valid_proxy.save()
        print(f"Successfully created valid proxy: {valid_proxy}")
        
        # Clean up
        valid_proxy.delete()
    except Exception as e:
        print(f"Unexpected error creating valid proxy: {e}")

def cleanup_test_data():
    """Clean up test data"""
    print("\nCleaning up test data...")
    
    # Delete test proxy
    Proxy.objects.filter(name="Test HTTP Proxy").delete()
    print("Deleted test proxy")
    
    # Delete test phishlet
    Phishlet.objects.filter(name="test-phishlet").delete()
    print("Deleted test phishlet")

def main():
    """Main test function"""
    print("=== Proxy Functionality Test ===\n")
    
    try:
        # Test proxy creation
        proxy = test_proxy_creation()
        
        # Test phishlet proxy assignment
        phishlet, proxy = test_phishlet_proxy_assignment()
        
        # Test proxy validation
        test_proxy_validation()
        
        print("\n=== All tests passed! ===")
        
    except Exception as e:
        print(f"\nERROR: Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        cleanup_test_data()

if __name__ == "__main__":
    main()
