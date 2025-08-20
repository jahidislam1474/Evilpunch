from django.apps import AppConfig
import os
import sys
import threading
import asyncio

_background_servers_started = False
_signals_registered = False


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        # Notifications removed: do not register any signals
        global _background_servers_started
        
        # Only start when using runserver autoreload child process
        if _background_servers_started:
            return
        if os.environ.get('RUN_MAIN') != 'true':
            return
        if 'runserver' not in sys.argv:
            return

        # Disable auto-start of background servers; they are now controlled via UI
        # Leave this method as a no-op so Django app initializes quickly.
        _background_servers_started = True
        print('[core] Background servers auto-start disabled; use the UI to control them.')

    def setup_admin_user(self):
        """Setup admin user from configuration. Called from management commands or startup."""
        try:
            from django.contrib.auth import get_user_model
            from core.config import get_config
            
            cfg = get_config()
            username = cfg.get("dashboard_username")
            password = cfg.get("dashboard_password")
            
            if username and password:
                User = get_user_model()
                user, created = User.objects.get_or_create(
                    username=username,
                    defaults={
                        "is_staff": True,
                        "is_superuser": True,
                        "email": "",
                    },
                )
                # Update password each run
                user.set_password(password)
                # Ensure admin flags are set
                if not user.is_staff:
                    user.is_staff = True
                if not user.is_superuser:
                    user.is_superuser = True
                user.save()
                
                if created:
                    print(f"[admin] Created admin user '{username}' with password from config.")
                else:
                    print(f"[admin] Updated admin user '{username}' password from config.")
                return True
            else:
                print(f"[admin] Skipped admin setup: 'dashboard_username' or 'dashboard_password' missing in config.")
                return False
        except Exception as e:
            print(f"[admin] Admin setup error: {e}")
            return False
