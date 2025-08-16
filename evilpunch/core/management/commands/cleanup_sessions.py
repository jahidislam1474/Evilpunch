from django.core.management.base import BaseCommand
from django.db import transaction
from core.models import Session
import json


class Command(BaseCommand):
    help = 'Clean up sessions with improperly formatted cookie data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force deletion without confirmation',
        )
        parser.add_argument(
            '--older-than',
            type=int,
            default=7,
            help='Delete sessions older than N days (default: 7)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        force = options['force']
        older_than_days = options['older_than']

        self.stdout.write(
            self.style.WARNING(
                f'🔍 Scanning for sessions with improperly formatted cookie data...'
            )
        )

        # Find sessions with old cookie format
        problematic_sessions = []
        
        try:
            from django.utils import timezone
            from datetime import timedelta
            
            # Get cutoff date
            cutoff_date = timezone.now() - timedelta(days=older_than_days)
            
            # Find sessions that might have old cookie format
            sessions = Session.objects.filter(
                created__lt=cutoff_date,
                captured_cookies__isnull=False
            ).exclude(captured_cookies={})
            
            for session in sessions:
                cookies = session.captured_cookies
                
                # Check if cookies are in old format (simple dict) vs new format (list of objects)
                if isinstance(cookies, dict) and cookies:
                    # Old format: {"cookie_name": "cookie_value"}
                    problematic_sessions.append({
                        'session': session,
                        'reason': 'Old cookie format (dict)',
                        'cookie_count': len(cookies),
                        'sample': str(list(cookies.items())[:3])
                    })
                elif isinstance(cookies, list) and cookies:
                    # Check if new format is properly structured
                    for cookie in cookies:
                        if not isinstance(cookie, dict) or 'name' not in cookie or 'value' not in cookie:
                            problematic_sessions.append({
                                'session': session,
                                'reason': 'Malformed cookie structure',
                                'cookie_count': len(cookies),
                                'sample': str(cookies[:3])
                            })
                            break
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error scanning sessions: {e}')
            )
            return

        if not problematic_sessions:
            self.stdout.write(
                self.style.SUCCESS('✅ No problematic sessions found!')
            )
            return

        # Display problematic sessions
        self.stdout.write(
            self.style.WARNING(
                f'⚠️  Found {len(problematic_sessions)} sessions with problematic cookie data:'
            )
        )
        
        for i, problem in enumerate(problematic_sessions[:10], 1):  # Show first 10
            session = problem['session']
            self.stdout.write(
                f'  {i}. Session {session.session_cookie[:8]}... '
                f'({session.proxy_domain}) - {problem["reason"]}'
            )
            self.stdout.write(
                f'     Cookies: {problem["cookie_count"]}, Sample: {problem["sample"]}'
            )
            self.stdout.write(
                f'     Created: {session.created.strftime("%Y-%m-%d %H:%M:%S")}'
            )
            self.stdout.write('')

        if len(problematic_sessions) > 10:
            self.stdout.write(
                f'  ... and {len(problematic_sessions) - 10} more sessions'
            )

        # Show summary
        total_sessions = Session.objects.count()
        self.stdout.write(
            self.style.WARNING(
                f'📊 Summary: {len(problematic_sessions)} problematic sessions out of {total_sessions} total sessions'
            )
        )

        if dry_run:
            self.stdout.write(
                self.style.SUCCESS('🔍 Dry run completed. No sessions were deleted.')
            )
            return

        # Confirmation
        if not force:
            confirm = input(
                f'\n⚠️  Are you sure you want to delete {len(problematic_sessions)} sessions? (yes/no): '
            )
            if confirm.lower() not in ['yes', 'y']:
                self.stdout.write(
                    self.style.WARNING('❌ Operation cancelled.')
                )
                return

        # Delete problematic sessions
        try:
            with transaction.atomic():
                deleted_count = 0
                for problem in problematic_sessions:
                    session = problem['session']
                    session_id = session.session_cookie[:8]
                    
                    try:
                        session.delete()
                        deleted_count += 1
                        self.stdout.write(
                            f'🗑️  Deleted session {session_id}... ({problem["reason"]})'
                        )
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(f'❌ Failed to delete session {session_id}...: {e}')
                        )

                self.stdout.write(
                    self.style.SUCCESS(
                        f'✅ Successfully deleted {deleted_count} out of {len(problematic_sessions)} problematic sessions'
                    )
                )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error during deletion: {e}')
            )
            return

        # Show final stats
        remaining_sessions = Session.objects.count()
        self.stdout.write(
            f'📊 Final count: {remaining_sessions} sessions remaining'
        )
