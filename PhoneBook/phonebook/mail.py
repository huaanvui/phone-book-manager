import os
import smtplib
from email.message import EmailMessage


class SMTPMailer:
    def send_reset_code(self, recipient: str, code: str):
        host = os.environ.get('SMTP_HOST', '').strip()
        sender = os.environ.get('SMTP_FROM', os.environ.get('SMTP_USER', '')).strip()
        if not host or not sender:
            raise RuntimeError('Email recovery requires SMTP_HOST and SMTP_FROM in .env; see README.')
        port = int(os.environ.get('SMTP_PORT', '587'))
        user, password = os.environ.get('SMTP_USER', ''), os.environ.get('SMTP_PASSWORD', '')
        message = EmailMessage()
        message['From'] = sender
        message['To'] = recipient
        message['Subject'] = 'Phone Book - password recovery code'
        message.set_content(f'Your Phone Book verification code is: {code}\n\nThis code expires in 10 minutes. If you did not request it, ignore this email.')
        use_ssl = os.environ.get('SMTP_SSL', 'false').lower() in ('yes','true','1')
        if use_ssl:
            client = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            client = smtplib.SMTP(host, port, timeout=12)
        with client:
            if not use_ssl and os.environ.get('SMTP_STARTTLS', 'true').lower() in ('true','yes','1'):
                client.starttls()
            if user:
                client.login(user, password)
            client.send_message(message)