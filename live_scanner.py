"""Reliable IMAP mailbox browsing and raw-message retrieval for SIH26106.

Supports Gmail, Yahoo Mail and Outlook/Microsoft 365 IMAP endpoints.
The scanner is read-only: it never marks mail as read or deletes/moves mail.
"""

from __future__ import annotations

import base64
import email
import imaplib
import re
import socket
import ssl
from email.header import decode_header
from email.utils import parsedate_to_datetime


PROVIDERS = {
    "Gmail": {"host": "imap.gmail.com", "port": 993},
    "Yahoo": {"host": "imap.mail.yahoo.com", "port": 993},
    "Outlook / Microsoft 365": {"host": "outlook.office365.com", "port": 993},
    "Custom IMAP": {"host": "", "port": 993},
}


def _decode_header_value(value, default=""):
    if not value:
        return default
    try:
        parts = decode_header(str(value))
        out = []
        for part, charset in parts:
            if isinstance(part, bytes):
                out.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                out.append(str(part))
        text = "".join(out).strip()
        return text or default
    except Exception:
        return str(value) or default


def _parse_date(value):
    try:
        if not value:
            return None
        dt = parsedate_to_datetime(str(value))
        if dt is not None and dt.tzinfo is None:
            from datetime import timezone
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _connect(host, port=993, timeout=20):
    """Create a TLS IMAP connection with bounded socket timeout."""
    context = ssl.create_default_context()
    return imaplib.IMAP4_SSL(host, int(port), ssl_context=context, timeout=timeout)


def _authenticate(mail, username, credential, auth_mode="App Password / Password"):
    if auth_mode == "OAuth2 Access Token":
        # RFC 7628 / XOAUTH2. Required for many modern Microsoft 365 tenants.
        auth_string = f"user={username}\x01auth=Bearer {credential}\x01\x01"
        # imaplib base64-encodes whatever this callback returns, so hand it
        # the raw bytes here -- do NOT base64-encode it ourselves, or the
        # server ends up decoding a base64 string instead of the real
        # "user=...auth=Bearer..." payload and authentication always fails.
        typ, data = mail.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))
        if typ != "OK":
            raise imaplib.IMAP4.error("XOAUTH2 authentication failed")
    else:
        typ, data = mail.login(username, credential)
        if typ != "OK":
            raise imaplib.IMAP4.error("IMAP login failed")


def _select_folder(mail, folder):
    folder = (folder or "INBOX").strip() or "INBOX"
    typ, data = mail.select(f'"{folder.replace(chr(34), "")}"', readonly=True)
    if typ != "OK":
        raise imaplib.IMAP4.error(f"Cannot open mailbox folder: {folder}")
    return folder, data


def _uid_search_all(mail):
    typ, data = mail.uid("SEARCH", None, "ALL")
    if typ != "OK":
        raise imaplib.IMAP4.error("Mailbox search failed")
    if not data or not data[0]:
        return []
    return data[0].split()


_UID_TOKEN_RE = re.compile(rb"UID\s+(\d+)")

# IMAP servers handle a FETCH command that lists many UIDs at once just
# fine (this is how real mail clients sync a mailbox), but the request is
# still chunked at a generous size so an unusually large browse window
# can't build one unbounded command line.
_FETCH_BATCH_SIZE = 150


def _chunked(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def fetch_mailbox_messages(
    imap_server,
    email_user,
    credential,
    max_messages=25,
    folder="INBOX",
    port=993,
    auth_mode="App Password / Password",
):
    """Return recent message metadata without downloading full bodies.

    Headers for every selected UID are fetched with as few IMAP FETCH
    commands as possible -- one, unless the batch is large enough to need
    chunking -- instead of the previous one-command-per-message loop. Over
    a mail server reached across the internet, round-trip latency (not
    bandwidth) is what makes browsing a mailbox feel slow, so this turns
    what used to be up to `max_messages` sequential round trips into 1-2.
    """
    max_messages = max(1, min(int(max_messages), 100))
    mail = None
    try:
        mail = _connect(imap_server, port)
        _authenticate(mail, email_user, credential, auth_mode)
        selected_folder, _ = _select_folder(mail, folder)
        uids = _uid_search_all(mail)
        wanted = list(reversed(uids[-max_messages:]))
        if not wanted:
            return []

        by_uid = {}
        for batch in _chunked(wanted, _FETCH_BATCH_SIZE):
            try:
                typ, data = mail.uid(
                    "FETCH",
                    b",".join(batch),
                    "(UID BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT MESSAGE-ID)])",
                )
            except Exception as exc:
                print(f"Skipping IMAP header batch: {exc}")
                continue
            if typ != "OK":
                continue
            for item in data or []:
                if not (isinstance(item, tuple) and len(item) >= 2):
                    continue
                meta, header_bytes = item[0], item[1]
                if not isinstance(header_bytes, (bytes, bytearray)):
                    continue
                uid_match = _UID_TOKEN_RE.search(meta or b"")
                if not uid_match:
                    continue
                uid_bytes = uid_match.group(1)
                try:
                    msg = email.message_from_bytes(bytes(header_bytes))
                    by_uid[uid_bytes] = {
                        "uid": uid_bytes.decode("ascii", errors="ignore"),
                        "subject": _decode_header_value(msg.get("Subject"), "No Subject"),
                        "from": _decode_header_value(msg.get("From"), "Unknown sender"),
                        "date": msg.get("Date") or "Unknown",
                        "date_dt": _parse_date(msg.get("Date")),
                        "message_id": _decode_header_value(msg.get("Message-ID"), ""),
                        "folder": selected_folder,
                    }
                except Exception as exc:
                    print(f"Skipping IMAP header UID {uid_bytes!r}: {exc}")

        # Keep the requested newest-first order for whatever UIDs the
        # server actually returned, then apply the existing date sort.
        messages = [by_uid[u] for u in wanted if u in by_uid]
        messages.sort(
            key=lambda x: (x.get("date_dt") is not None, x.get("date_dt")),
            reverse=True,
        )
        return messages
    except (socket.timeout, TimeoutError) as exc:
        raise RuntimeError("IMAP connection timed out. Check the server and network.") from exc
    except ssl.SSLError as exc:
        raise RuntimeError(f"TLS/SSL connection failed: {exc}") from exc
    except imaplib.IMAP4.error as exc:
        raise RuntimeError(f"IMAP error: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"IMAP connection failed: {exc}") from exc
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass


def fetch_message_by_uid(
    imap_server,
    email_user,
    credential,
    uid,
    folder="INBOX",
    port=993,
    auth_mode="App Password / Password",
    retries=2,
):
    """Fetch one complete RFC-5322 message by stable IMAP UID."""
    last_error = None
    for attempt in range(max(1, retries + 1)):
        mail = None
        try:
            mail = _connect(imap_server, port)
            _authenticate(mail, email_user, credential, auth_mode)
            _select_folder(mail, folder)
            typ, data = mail.uid("FETCH", str(uid).encode("ascii"), "(RFC822)")
            if typ != "OK" or not data:
                raise RuntimeError("The mail server did not return the requested message.")
            for item in data:
                if isinstance(item, tuple) and len(item) >= 2:
                    raw = item[1]
                    if isinstance(raw, (bytes, bytearray)) and raw:
                        return bytes(raw)
            raise RuntimeError("The mail server returned an empty message payload.")
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                import time
                time.sleep(0.7 * (attempt + 1))
        finally:
            if mail is not None:
                try:
                    mail.logout()
                except Exception:
                    pass
    raise RuntimeError(str(last_error) if last_error else "Unable to fetch message.")


def fetch_messages_by_uids(
    imap_server,
    email_user,
    credential,
    uids,
    folder="INBOX",
    port=993,
    auth_mode="App Password / Password",
    retries=2,
):
    """Fetch several complete RFC-5322 messages in ONE IMAP session.

    fetch_message_by_uid() connects, authenticates, and selects the folder
    fresh for every call -- correct for retrieving a single message, but
    it means pulling N messages one at a time (as callers used to do)
    pays the full TLS-handshake-plus-login cost N times over. Gmail/
    Outlook-style login round trips are typically the slowest single step
    in the whole flow, so this reuses one connection for the entire batch:
    that cost is paid once no matter how many messages are requested.

    Returns {uid_str: raw_bytes}. A UID the server can't return is simply
    missing from the result instead of failing the whole batch.
    """
    uids = [str(u) for u in uids]
    if not uids:
        return {}

    last_error = None
    for attempt in range(max(1, retries + 1)):
        mail = None
        try:
            mail = _connect(imap_server, port)
            _authenticate(mail, email_user, credential, auth_mode)
            _select_folder(mail, folder)
            out = {}
            for uid in uids:
                try:
                    typ, data = mail.uid("FETCH", uid.encode("ascii"), "(RFC822)")
                    if typ != "OK" or not data:
                        continue
                    for item in data:
                        if isinstance(item, tuple) and len(item) >= 2:
                            raw = item[1]
                            if isinstance(raw, (bytes, bytearray)) and raw:
                                out[uid] = bytes(raw)
                                break
                except Exception as exc:
                    print(f"Skipping message UID {uid!r}: {exc}")
            return out
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                import time
                time.sleep(0.7 * (attempt + 1))
        finally:
            if mail is not None:
                try:
                    mail.logout()
                except Exception:
                    pass
    raise RuntimeError(str(last_error) if last_error else "Unable to fetch messages.")


def fetch_live_emails(
    imap_server,
    email_user,
    email_pass,
    max_emails=5,
    folder="INBOX",
    port=993,
    auth_mode="App Password / Password",
):
    """Backward-compatible helper: return recent complete messages."""
    metadata = fetch_mailbox_messages(
        imap_server,
        email_user,
        email_pass,
        max_messages=max_emails,
        folder=folder,
        port=port,
        auth_mode=auth_mode,
    )
    if not metadata:
        return []
    try:
        raw_by_uid = fetch_messages_by_uids(
            imap_server,
            email_user,
            email_pass,
            [item["uid"] for item in metadata],
            folder=folder,
            port=port,
            auth_mode=auth_mode,
        )
    except Exception as exc:
        print(f"Could not fetch message bodies: {exc}")
        return []
    out = []
    for item in metadata:
        raw = raw_by_uid.get(str(item["uid"]))
        if raw is None:
            print(f"Skipping message {item.get('uid')}: not returned by server")
            continue
        item = dict(item)
        item["raw_bytes"] = raw
        out.append(item)
    return out