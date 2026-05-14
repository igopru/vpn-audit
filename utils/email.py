import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config

logger = logging.getLogger(__name__)

def send_email(to_addr: str, subject: str, body_text: str, body_html: str = None, cc: str = None):
    if not Config.EMAIL_ENABLED:
        logger.info(f"[EMAIL DISABLED] To: {to_addr} | Subject: {subject}")
        return True
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"{Config.EMAIL_SUBJECT_PREFIX} {subject}"
        msg['From'] = f"{Config.EMAIL_FROM_NAME} <{Config.EMAIL_FROM}>"
        msg['To'] = to_addr
        if cc:
            msg['Cc'] = cc
        
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
        if body_html:
            msg.attach(MIMEText(body_html, 'html', 'utf-8'))
        
        # Подключение к SMTP
        if Config.SMTP_USER and Config.SMTP_PASSWORD:
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT)
            if Config.SMTP_USE_TLS:
                server.starttls()
            server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
        else:
            # Анонимный relay
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT)
        
        recipients = [to_addr]
        if cc:
            recipients += [c.strip() for c in cc.split(',') if c.strip()]
        
        server.sendmail(Config.EMAIL_FROM, recipients, msg.as_string())
        server.quit()
        logger.info(f"Email sent: {to_addr} | {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False
