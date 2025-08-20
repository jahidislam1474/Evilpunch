from django.core.management.base import BaseCommand
from django.apps import apps


class Command(BaseCommand):
    help = "Ensures admin user exists based on configuration"

    def handle(self, *args, **options):
        self.stdout.write("Setting up admin user...")
        
        try:
            # Get the core app config
            core_config = apps.get_app_config('core')
            
            # Call the setup_admin_user method
            if hasattr(core_config, 'setup_admin_user'):
                success = core_config.setup_admin_user()
                if success:
                    self.stdout.write(
                        self.style.SUCCESS("Admin user setup completed successfully!")
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING("Admin user setup completed with warnings.")
                    )
            else:
                self.stdout.write(
                    self.style.ERROR("setup_admin_user method not found in core app config.")
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error setting up admin user: {e}")
            )
