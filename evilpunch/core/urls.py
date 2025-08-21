from django.urls import path
from . import views


urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('warning/', views.warning_view, name='warning'),
    path('help/', views.help_view, name='help'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('phishlets/', views.phishlet_list_view, name='phishlet_list'),
    path('phishlets/new/', views.phishlet_create_view, name='phishlet_create'),
    path('phishlets/<uuid:pk>/edit/', views.phishlet_edit_view, name='phishlet_edit'),
    path('phishlets/<uuid:pk>/download/', views.phishlet_download_view, name='phishlet_download'),
    path('phishlets/<uuid:pk>/toggle/', views.phishlet_toggle_view, name='phishlet_toggle'),
    path('phishlets/<uuid:pk>/toggle-cache/', views.phishlet_toggle_cache_view, name='phishlet_toggle_cache'),
    path('phishlets/<uuid:pk>/clear-cache/', views.phishlet_clear_cache_view, name='phishlet_clear_cache'),
    path('phishlets/<uuid:pk>/local-hosts/', views.phishlet_get_local_hosts_view, name='phishlet_get_local_hosts'),
    # Proxy management
    path('proxies/', views.proxy_list_view, name='proxy_list'),
    path('proxies/new/', views.proxy_create_view, name='proxy_create'),
    path('proxies/<uuid:pk>/edit/', views.proxy_edit_view, name='proxy_edit'),
    path('proxies/<uuid:pk>/delete/', views.proxy_delete_view, name='proxy_delete'),
    path('proxies/<uuid:pk>/toggle/', views.proxy_toggle_view, name='proxy_toggle'),
    path('proxies/test/', views.test_proxy_view, name='test_proxy'),
    # Proxy Domains management
    path('proxy-domains/', views.proxy_domains_view, name='proxy_domains'),
    path('proxy-domains/add/', views.proxy_domain_add_view, name='proxy_domain_add'),
    path('proxy-domains/<uuid:pk>/toggle/', views.proxy_domain_toggle_view, name='proxy_domain_toggle'),
    path('proxy-domains/<uuid:pk>/cert/add/', views.proxy_domain_cert_add_view, name='proxy_domain_cert_add'),
    path('proxy-domains/<uuid:pk>/cert/get/', views.proxy_domain_cert_get_view, name='proxy_domain_cert_get'),
    path('proxy-domains/<uuid:pk>/generate-ssl/', views.proxy_domain_generate_ssl_view, name='proxy_domain_generate_ssl'),

    path('servers/', views.servers_view, name='servers'),
    path('proxy-server/', views.proxy_server_view, name='proxy_server'),
    path('dns-server/', views.dns_server_view, name='dns_server'),
    path('dns-server/start/', views.dns_start_view, name='dns_start'),
    path('dns-server/stop/', views.dns_stop_view, name='dns_stop'),
    path('dns-server/restart/', views.dns_restart_view, name='dns_restart'),
    path('dns-server/status/', views.dns_status_view, name='dns_status'),
    # Proxy server controls
    path('proxy-server/start/', views.proxy_start_view, name='proxy_start'),
    path('proxy-server/stop/', views.proxy_stop_view, name='proxy_stop'),
    path('proxy-server/restart/', views.proxy_restart_view, name='proxy_restart'),
    path('proxy-server/status/', views.proxy_status_view, name='proxy_status'),
    path('error-logs/', views.error_logs_view, name='error_logs'),
    path('sessions/', views.sessions_view, name='sessions'),
    path('sessions/<uuid:session_id>/toggle/', views.toggle_session_status_view, name='toggle_session_status'),
    path('sessions/<uuid:session_id>/details/', views.get_session_details_view, name='get_session_details'),
    path('sessions/<uuid:session_id>/delete/', views.delete_session_view, name='delete_session'),
    path('sessions/<uuid:session_id>/update/', views.update_session_data_view, name='update_session_data'),
    # Notification management
    path('notifications/', views.notification_settings_view, name='notification_settings'),
    path('notifications/test/', views.test_notification_view, name='test_notification'),
]


