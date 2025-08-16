try:
    # Prefer staticfiles' runserver to preserve static file serving in dev
    from django.contrib.staticfiles.management.commands.runserver import Command as BaseRunserverCommand
except Exception:  # pragma: no cover - fallback if staticfiles isn't installed
    from django.core.management.commands.runserver import Command as BaseRunserverCommand


ANSI_GREEN = "\033[92m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"


class Command(BaseRunserverCommand):
    help = "Runs the server with a customized startup banner."

    def handle(self, *args, **options):
        # If no addr:port provided explicitly, default to config values
        try:
            addrport = options.get("addrport")
            if not addrport:
                from core.config import get_config  # type: ignore
                cfg = get_config()
                host = str(cfg.get("dashboard_host") or "127.0.0.1")
                port = str(cfg.get("dashboard_port") or "8000")
                options["addrport"] = f"{host}:{port}"
        except Exception:
            # Fall back to Django defaults if config is unavailable
            pass

        return super().handle(*args, **options)

    def inner_run(self, *args, **options):
        # Suppress Django's default banner lines and show our own
        original_write = self.stdout.write
        original_stderr_write = self.stderr.write

        def filtered_write(msg="", style_func=None, ending="\n"):
            text = str(msg)
            if text.startswith("Starting development server at "):
                return  # suppress default banner
            if text.startswith("Quit the server with CONTROL-C."):
                return  # suppress default quit hint (we'll print our own)
            return original_write(msg, style_func=style_func, ending=ending)

        def filtered_stderr_write(msg="", style_func=None, ending="\n"):
            # Pass through errors unchanged
            return original_stderr_write(msg, style_func=style_func, ending=ending)

        self.stdout.write = filtered_write
        self.stderr.write = filtered_stderr_write

        # Compute address/port set by parent handle() before starting
        addr = self.addr or "127.0.0.1"
        port = self.port or "8000"
        scheme = "http"

        # Before printing banner, ensure admin user from config exists/updated
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
                # If user existed but username in config differs from an existing admin user,
                # we only manage the user with the configured username. Update password each run.
                user.set_password(password)
                # Ensure admin flags are set
                if not user.is_staff:
                    user.is_staff = True
                if not user.is_superuser:
                    user.is_superuser = True
                user.save()
                print(f"{ANSI_CYAN}[admin]{ANSI_RESET} Ensured admin user '{username}' exists and password is set.")
            else:
                print(f"{ANSI_CYAN}[admin]{ANSI_RESET} Skipped admin setup: 'dashboard_username' or 'dashboard_password' missing in config.")
        except Exception as e:
            print(f"{ANSI_CYAN}[admin]{ANSI_RESET} Admin setup error: {e}")

        # Print our banner BEFORE starting the server
        print("=" * 60)
        print(f"{ANSI_GREEN}[dev]{ANSI_RESET} {scheme.upper()} server starting at {ANSI_CYAN}{scheme}://{addr}:{port}/{ANSI_RESET}")
        print(f"{ANSI_CYAN}Quit the server with CONTROL-C.{ANSI_RESET}")
        print("=" * 60)

        try:
            result = super().inner_run(*args, **options)
            return result
        finally:
            # Restore writers no matter what
            self.stdout.write = original_write
            self.stderr.write = original_stderr_write


