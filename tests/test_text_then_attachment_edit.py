#!/usr/bin/env python3
"""
Live test flow:
1) Send a text message
2) Attempt to modify the SAME message to add a file (Telegram limitation → expect fail). As a workaround, send the file as a reply to the original message and capture its message_id.
3) Modify both: edit original text, and replace the file + caption on the document message.
"""

import os
import sys
import tempfile
import time


def setup_django():
    # Ensure project root is importable
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # Also ensure inner project dir is importable for `evilpunch.settings`
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'evilpunch'))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evilpunch.settings')
    import django
    django.setup()


def get_active_settings():
    from core.models import NotificationSettings
    settings = NotificationSettings.objects.filter(is_active=True).first()
    return settings


def create_temp_file(text: str) -> str:
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    f.write(text)
    f.close()
    return f.name


def send_document_direct(token: str, chat_id: str, file_path: str, caption: str, reply_to_message_id: int = None) -> int:
    import requests
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    with open(file_path, 'rb') as doc:
        files = {'document': doc}
        data = {
            'chat_id': chat_id,
            'caption': caption,
        }
        if reply_to_message_id:
            data['reply_to_message_id'] = reply_to_message_id
            data['allow_sending_without_reply'] = True
        r = requests.post(url, data=data, files=files, timeout=30)
        r.raise_for_status()
        j = r.json()
        if not j.get('ok'):
            raise RuntimeError(f"Telegram sendDocument error: {j}")
        return j['result']['message_id']


def run():
    from core.notify import notification_manager

    s = get_active_settings()
    if not s or not s.telegram_bot_token or not s.telegram_chat_id:
        print('❌ No active Telegram settings. Aborting.')
        return False

    print('✅ Using active Telegram settings')

    # 1) Send a text message
    text1 = "Step 1: Initial text message"
    msg_id = notification_manager.send_telegram_message(text1)
    if not msg_id:
        print('❌ Failed to send initial text')
        return False
    print(f'✅ Sent text message id={msg_id}')

    # 2) Try to modify same message to add file (expected to fail per Telegram API)
    file1 = create_temp_file('Attachment v1 for the same message (expected workaround)')
    try:
        print('→ Attempting to edit text message to add file (should fail)...')
        ok = notification_manager.edit_telegram_message_media(msg_id, file1, 'Attachment added (expected fail)')
        if ok:
            print('⚠️ Unexpected: Telegram allowed editing a text-only message into media')
            media_msg_id = msg_id
        else:
            print('✅ Expected failure. Sending document as a reply to original message...')
            media_msg_id = send_document_direct(
                s.telegram_bot_token,
                s.telegram_chat_id,
                file1,
                'Reply attachment v1 (workaround)',
                reply_to_message_id=msg_id,
            )
            print(f'✅ Sent document reply message id={media_msg_id}')
    finally:
        try:
            os.unlink(file1)
        except Exception:
            pass

    time.sleep(2)

    # 3) Modify message + attachment
    print('→ Editing original text message...')
    ok_text = notification_manager.edit_telegram_message(msg_id, 'Step 3: Original text updated')
    print(f'   Text edit result: {ok_text}')

    file2 = create_temp_file('Attachment v2 replacing previous file')
    try:
        print('→ Editing attachment message (replace media + caption)...')
        ok_media = notification_manager.edit_telegram_message_media(media_msg_id, file2, 'Reply attachment v2 (replaced)')
        print(f'   Media edit result: {ok_media}')
    finally:
        try:
            os.unlink(file2)
        except Exception:
            pass

    return True


if __name__ == '__main__':
    setup_django()
    ok = run()
    sys.exit(0 if ok else 1)


