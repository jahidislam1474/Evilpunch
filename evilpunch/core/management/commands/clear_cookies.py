from django.core.management.base import BaseCommand
from django.db import transaction
from core.models import Session


class Command(BaseCommand):
    help = 'Clear cookie data from existing sessions to prepare for new format'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be cleared without actually clearing',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force clearing without confirmation',
        )
        parser.add_argument(
            '--older-than',
            type=int,
            default=0,
            help='Only clear cookies from sessions older than N days (default: 0 = all)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        force = options['force']
        older_than_days = options['older_than']

        self.stdout.write(
            self.style.WARNING(
                f'🔍 Scanning for sessions with cookie data...'
            )
        )

        try:
            from django.utils import timezone
            from datetime import timedelta
            
            # Build query
            query = Session.objects.filter(captured_cookies__isnull=False)
            
            if older_than_days > 0:
                cutoff_date = timezone.now() - timedelta(days=older_than_days)
                query = query.filter(created__lt=cutoff_date)
                self.stdout.write(
                    f'📅 Only processing sessions older than {older_than_days} days'
                )
            
            # Count sessions with cookies
            sessions_with_cookies = query.count()
            total_sessions = Session.objects.count()
            
            if sessions_with_cookies == 0:
                self.stdout.write(
                    self.style.SUCCESS('✅ No sessions with cookie data found!')
                )
                return

            self.stdout.write(
                self.style.WARNING(
                    f'⚠️  Found {sessions_with_cookies} sessions with cookie data out of {total_sessions} total sessions'
                )
            )

            # Show sample of what will be cleared
            sample_sessions = query[:5]
            self.stdout.write('\n📋 Sample sessions that will be affected:')
            for i, session in enumerate(sample_sessions, 1):
                cookie_count = len(session.captured_cookies) if session.captured_cookies else 0
                self.stdout.write(
                    f'  {i}. Session {session.session_cookie[:8]}... '
                    f'({session.proxy_domain}) - {cookie_count} cookies'
                )
                self.stdout.write(
                    f'     Created: {session.created.strftime("%Y-%m-%d %H:%M:%S")}'
                )
                if cookie_count > 0:
                    sample_cookies = list(session.captured_cookies.keys())[:3]
                    self.stdout.write(
                        f'     Sample cookies: {", ".join(sample_cookies)}'
                    )
                self.stdout.write('')

            if dry_run:
                self.stdout.write(
                    self.style.SUCCESS('🔍 Dry run completed. No cookie data was cleared.')
                )
                return

            # Confirmation
            if not force:
                confirm = input(
                    f'\n⚠️  Are you sure you want to clear cookie data from {sessions_with_cookies} sessions? (yes/no): '
                )
                if confirm.lower() not in ['yes', 'y']:
                    self.stdout.write(
                        self.style.WARNING('❌ Operation cancelled.')
                    )
                    return

            # Clear cookie data
            try:
                with transaction.atomic():
                    updated_count = 0
                    for session in query:
                        try:
                            # Clear cookies but keep other data
                            session.captured_cookies = {}
                            session.save(update_fields=['captured_cookies'])
                            updated_count += 1
                            
                            if updated_count <= 10:  # Show first 10 updates
                                self.stdout.write(
                                    f'🧹 Cleared cookies from session {session.session_cookie[:8]}...'
                                )
                            elif updated_count == 11:
                                self.stdout.write('   ... (showing first 10, then silent)')
                                
                        except Exception as e:
                            self.stdout.write(
                                self.style.ERROR(f'❌ Failed to clear cookies from session {session.session_cookie[:8]}...: {e}')
                            )

                    self.stdout.write(
                        self.style.SUCCESS(
                            f'✅ Successfully cleared cookies from {updated_count} out of {sessions_with_cookies} sessions'
                        )
                    )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'❌ Error during cookie clearing: {e}')
                )
                return

            # Show final stats
            remaining_sessions_with_cookies = Session.objects.filter(
                captured_cookies__isnull=False
            ).exclude(captured_cookies={}).count()
            
            self.stdout.write(
                f'📊 Final count: {remaining_sessions_with_cookies} sessions still have cookie data'
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error scanning sessions: {e}')
            )
            return
