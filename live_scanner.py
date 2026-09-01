import imaplib
import email
from email.header import decode_header

def fetch_live_emails(imap_server, email_user, email_pass, max_emails=5):
    """Fetches recent emails using direct message counts to bypass search limits."""
    extracted_messages = []
    try:
        print(f"Connecting to {imap_server}...")
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_user, email_pass)
        
        # Select INBOX and get total message count
        resp, count_data = mail.select("INBOX")
        if resp != 'OK':
            mail.select("[Gmail]/All Mail")
            
        # Extract total count from mailbox response
        total_msgs = 0
        for response in count_data:
            if response.isdigit():
                total_msgs = int(response)
                
        print(f"Total messages in inbox: {total_msgs}")
        if total_msgs == 0:
            mail.logout()
            return []

        # Generate message ID range for the last N emails
        start_id = max(1, total_msgs - max_emails + 1)
        email_ids = [str(i).encode('ascii') for i in range(start_id, total_msgs + 1)]

        for e_id in email_ids:
            res, msg_data = mail.fetch(e_id, '(BODY.PEEK[])')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    raw_bytes = response_part[1]
                    msg = email.message_from_bytes(raw_bytes)
                    
                    subject = "No Subject"
                    if msg["Subject"]:
                        try:
                            decoded_header = decode_header(msg["Subject"])[0]
                            if isinstance(decoded_header[0], bytes):
                                subject = decoded_header[0].decode(decoded_header[1] or "utf-8", errors="ignore")
                            else:
                                subject = decoded_header[0]
                        except Exception:
                            subject = str(msg["Subject"])
                    
                    extracted_messages.append({
                        "id": e_id,
                        "subject": subject,
                        "from": msg.get("From"),
                        "raw_bytes": raw_bytes
                    })
                    
        mail.logout()
        return list(reversed(extracted_messages)) # Show newest messages first
    except Exception as e:
        print(f"IMAP Connection Error: {e}")
        return []