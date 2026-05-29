#!/usr/bin/env python3
"""
Конфигурация VPN Audit System.
Все секреты вынесены в .env, здесь — только логика чтения и безопасные дефолты.
"""
import os
from dotenv import load_dotenv
from datetime import timedelta

# 🔹 Загружаем переменные из .env (явный путь для cron-среды)
load_dotenv('/opt/vpn-audit/.env')

class Config:
    # ========================================================================
    # 🗄 DATABASE (MySQL/MariaDB)
    # ========================================================================
    MYSQL_CONFIG = {
        "host": os.getenv("DB_HOST", "127.0.0.1"),           # Адрес БД
        "user": os.getenv("DB_USER", "vpn_audit"),           # Пользователь БД (мин. права: SELECT, INSERT, UPDATE)
        "password": os.getenv("DB_PASSWORD"),                # ⚠️ Обязательно в .env!
        "database": os.getenv("DB_NAME", "vpn_audit"),       # Имя БД
        "charset": "utf8mb4",                                # Поддержка кириллицы и эмодзи
        "cursorclass": "DictCursor"                          # Возвращать строки как dict, а не tuple
    }
    
    # ========================================================================
    # 🌐 ACTIVE DIRECTORY / LDAP
    # ========================================================================
    LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://dc1.example.com")  # Контроллер домена (ldap:// или ldaps://)
    LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")                          # DN сервисной учётки (только чтение + write member)
    LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")              # ⚠️ Пароль сервисной учётки
    LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "DC=example,DC=com")     # Корень поиска пользователей
    LDAP_USE_SSL = False  # Если используете STARTTLS — настройте ldap3 согласно документации
    
    # ========================================================================
    # 🔐 ВЕБ-АУТЕНТИФИКАЦИЯ (Flask-дашборд)
    # ========================================================================
    AUTH_ENABLED = os.getenv("AUTH_ENABLED", "1") == "1"  # Включить AD-аутентификацию (0 = отключить для отладки)
    AUTH_AD_SERVER = os.getenv("AUTH_AD_SERVER", LDAP_SERVER)  # Отдельный сервер для аутентификации (опционально)
    AUTH_AD_BIND_DN = os.getenv("AUTH_AD_BIND_DN")  # Сервисная учётка для поиска пользователей при логине
    AUTH_AD_BIND_PASSWORD = os.getenv("AUTH_AD_BIND_PASSWORD")
    AUTH_AD_USER_SEARCH_BASE = os.getenv("AUTH_AD_USER_SEARCH_BASE", f"OU=Corporate,{os.getenv('LDAP_BASE_DN', 'DC=example,DC=com')}")
    AUTH_ALLOWED_ROLES = os.getenv("AUTH_ALLOWED_ROLES", "admin,viewer,auditor").split(",")  # Роли, которым разрешён вход
    SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "480"))  # Время жизни сессии (8 часов по умолчанию)
    
    # ========================================================================
    # 🎯 ЛОГИКА ОТКЛЮЧЕНИЯ (Бизнес-правила)
    # ========================================================================
    VPN_GROUP_DN = os.getenv("VPN_GROUP_DN")  # 🔥 DN группы доступа к VPN (обязательно!)
    VPN_INACTIVE_DAYS = int(os.getenv("VPN_INACTIVE_DAYS", "31"))  # Дней неактивности перед отключением
    
    # Исключения: эти пользователи НИКОГДА не будут отключены автоматически
    VPN_WHITELIST = set(u.strip() for u in os.getenv("VPN_WHITELIST", "").split(",") if u.strip())
    
    # Паттерн для системных/админских аккаунтов (исключаются из обработки)
    ADMIN_USERNAME_PATTERN = r"^sysadmin\d+$"
    
    # ========================================================================
    # 🧪 FLASK / ВЕБ-СЕРВЕР
    # ========================================================================
    SECRET_KEY = os.getenv("SECRET_KEY")  # 🔥 Обязательно: сгенерировать (openssl rand -hex 32)
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"  # Режим отладки (0 = production)
    
    # ========================================================================
    # 📧 EMAIL / SMTP (Уведомления пользователям)
    # ========================================================================
    EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "1") == "1"  # Включить отправку писем
    EMAIL_TO_IT = os.getenv("EMAIL_TO_IT", "it-support@example.com")  # Копия всех уведомлений в ИТ
    EMAIL_FROM = os.getenv("EMAIL_FROM", "noreply@example.com")  # Адрес отправителя
    EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "VPN Audit System")  # Имя отправителя
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")  # SMTP-релей
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))  # Порт (25, 465 или 587)
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "1") == "1"  # Использовать STARTTLS
    SMTP_USER = os.getenv("SMTP_USER")  # Логин SMTP (если требуется аутентификация)
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")  # Пароль SMTP
    EMAIL_SUBJECT_PREFIX = os.getenv("EMAIL_SUBJECT_PREFIX", "[VPN-AUDIT]")  # Префикс темы письма
    
    # 🔹 Тестовый режим: все письма уходят только на этот адрес (для отладки)
    EMAIL_TEST_OVERRIDE = os.getenv("EMAIL_TEST_OVERRIDE", "").strip() or None
    
    # ========================================================================
    # ⚙️ СИСТЕМНЫЕ НАСТРОЙКИ
    # ========================================================================
    LOG_DIR = os.getenv("LOG_DIR", "/opt/vpn-audit/logs")  # Папка для логов приложения
    TIMEZONE = os.getenv("TIMEZONE", "UTC")  # Часовой пояс для расчётов (совпадает с настройками БД)
    
    # 🔹 DRY_RUN: 1 = безопасный режим (только логи/письма, без изменений в AD)
    #            0 = production (реальное удаление из группы)
    DRY_RUN = os.getenv("VPN_DRY_RUN", "1").lower() == "1"
