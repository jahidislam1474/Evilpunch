#!/usr/bin/env python3
"""
Test: Send a file message to Telegram, then edit the SAME message (replace media + caption)

Requirements:
- Active `NotificationSettings` row with valid `telegram_bot_token` and `telegram_chat_id`.
- Network connectivity.
"""

import os
import sys
import time
import tempfile


def setup_django():
    # Ensure both project root and inner `evilpunch/` dir are importable.
    # This enables namespace-style imports: `evilpunch.core` and `evilpunch.settings`.
    repo_root = os.path.dirname(os.path.abspath(__file__))
    inner = os.path.join(repo_root, 'evilpunch')
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    if inner not in sys.path:
        sys.path.insert(0, inner)

    # Configure Django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
    import django
    django.setup()


def check_notification_settings():
    from core.models import NotificationSettings

    settings = NotificationSettings.objects.filter(is_active=True).first()
    if not settings:
        print('⚠️  No active NotificationSettings found. Will use MOCK mode for testing.')
        return False

    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        print('❌ NotificationSettings found, but Telegram bot token or chat id is missing.')
        return False

    print('✅ Notification settings present and active')
    return True


def create_temp_text_file(text: str) -> str:
    temp = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    temp.write(text)
    temp.close()
    return temp.name


def enable_mock_mode():
    """Enable mock mode by stubbing requests.post and injecting fake settings."""
    import types
    import requests
    from core.notify import notification_manager

    # Inject fake settings
    FakeSettings = types.SimpleNamespace(
        telegram_bot_token='mock-token',
        telegram_chat_id='123456',
        is_active=True
    )
    notification_manager.settings = FakeSettings

    # Stub requests.post
    class FakeResponse:
        def __init__(self, message_id=1111, ok=True):
            self._message_id = message_id
            self._ok = ok
            self.status_code = 200 if ok else 400
            self.text = '{"ok": true}' if ok else '{"ok": false}'

        def raise_for_status(self):
            if not self._ok:
                raise Exception('HTTP error (mock)')

        def json(self):
            # Emulate Telegram API structure
            if self._ok:
                return {"ok": True, "result": {"message_id": self._message_id}}
            return {"ok": False}

    def fake_post(url, data=None, files=None, timeout=None):
        # Return a deterministic but different message_id for edits vs sends
        if 'sendDocument' in url or 'sendMessage' in url:
            return FakeResponse(message_id=2222, ok=True)
        if 'editMessageMedia' in url or 'editMessageText' in url:
            return FakeResponse(message_id=2222, ok=True)
        return FakeResponse(ok=True)

    requests.post = fake_post
    print('🧪 MOCK mode enabled: Telegram API calls are stubbed.')


def run_test():
    from core.notify import notification_manager

    print('🧪 Test: send file, then edit same message')

    # 1) Create initial file and send
    initial_text = 'Initial sample content for Telegram document test.'
    initial_file_path = create_temp_text_file(initial_text)
    initial_caption = '📎 Initial caption: sample text file'

    print(f'→ Sending file: {initial_file_path}')
    message_id = notification_manager.send_telegram_file(initial_file_path, initial_caption)

    # Clean up initial temp file on disk regardless of success
    try:
        os.unlink(initial_file_path)
    except Exception:
        pass

    if not message_id:
        print('❌ Failed to send initial file message. Aborting test.')
        return False

    print(f'✅ Sent. Message ID: {message_id}')

    # 2) Wait a moment, then edit message media with a new file and caption
    time.sleep(2)

    updated_text = 'Updated content for the same Telegram message (media replaced).'
    updated_file_path = create_temp_text_file(updated_text)
    updated_caption = '✏️ Updated caption: replaced the attached document'

    print(f'→ Editing message {message_id} with new file: {updated_file_path}')
    success = notification_manager.edit_telegram_message_media(message_id, updated_file_path, updated_caption)

    # Clean up updated temp file
    try:
        os.unlink(updated_file_path)
    except Exception:
        pass

    if not success:
        print('❌ Failed to edit message media')
        return False

    print('✅ Edited message media successfully')
    return True


if __name__ == '__main__':
    setup_django()

    if not check_notification_settings():
        enable_mock_mode()

    ok = run_test()
    sys.exit(0 if ok else 1)


