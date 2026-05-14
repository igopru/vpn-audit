import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "480"))

    # DB
    MYSQL_CONFIG = {
        "host": os.getenv("DB_HOST", "127.0.0.1"),
        "port": int(os.getenv("DB_PORT", "3306")),
        "user": os.getenv("DB_USER", "vpn_audit"),
        "password": os.getenv("DB_PASSWORD"),
        "database": os.getenv("DB_NAME", "vpn_audit"),
        "charset": "utf8mb4",
        "cursorclass": "DictCursor"
    }

    # LDAP
    LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://dc1.example.com")
    LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
    LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
    LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "DC=example,DC=com")
    LDAP_GROUP_DN = os.getenv("LDAP_GROUP_DN")

    # Email
    EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "1") == "1"
    EMAIL_FROM = os.getenv("EMAIL_FROM", "noreply@example.com")
    EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "VPN Audit")
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "1") == "1"
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    EMAIL_TEST_OVERRIDE = os.getenv("EMAIL_TEST_OVERRIDE")

    # Logic
    VPN_INACTIVE_DAYS = int(os.getenv("VPN_INACTIVE_DAYS", "31"))
    VPN_WHITELIST = set(u for u in os.getenv("VPN_WHITELIST", "").split(",") if u)
    ADMIN_USERNAME_PATTERN = os.getenv("ADMIN_USERNAME_PATTERN", r"^sysadmin\d+$")
    DRY_RUN = os.getenv("VPN_DRY_RUN", "1").lower() == "1"
    LOG_DIR = os.getenv("LOG_DIR", "/opt/vpn-audit/logs")
    TIMEZONE = os.getenv("TIMEZONE", "UTC")
