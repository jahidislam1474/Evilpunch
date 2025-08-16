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
