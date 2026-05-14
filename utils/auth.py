#!/usr/bin/env python3
"""AD-аутентификация и проверка прав доступа"""
import logging
import re
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE
from config import Config

logger = logging.getLogger(__name__)


def authenticate_ad(username: str, password: str) -> dict | None:
    """
    Проверяет учётку в AD.
    1. Подключаемся под сервисной учёткой (из конфига)
    2. Ищем пользователя по sAMAccountName во всём домене
    3. Проверяем пароль пользователя, биндясь под его DN
    """
    try:
        # === Валидация сервисных кредов ===
        if not Config.AUTH_AD_BIND_DN or not Config.AUTH_AD_BIND_PASSWORD:
            logger.error("❌ AUTH_AD_BIND_DN или AUTH_AD_BIND_PASSWORD не заданы в конфиге/.env")
            return None
        
        server = Server(Config.AUTH_AD_SERVER, get_info=ALL, connect_timeout=5)
        
        # Биндимся под сервисной учёткой для поиска
        service_conn = Connection(
            server,
            user=Config.AUTH_AD_BIND_DN,
            password=Config.AUTH_AD_BIND_PASSWORD,
            authentication=SIMPLE,
            auto_bind=True
        )
        logger.info(f"✓ Service bind OK: {Config.AUTH_AD_BIND_DN}")
        
        # === Поиск пользователя ===
        # === Нормализация логина: поддерживаем sAMAccountName и UPN ===
        # Если пользователь ввёл 'user@domain' — ищем по userPrincipalName
        # Если ввёл 'username' — ищем по sAMAccountName
        if '@' in username:
            # UPN-формат: ищем по userPrincipalName
            search_filter = f'(&(objectClass=user)(userPrincipalName={username}))'
        else:
            # Простой логин: ищем по sAMAccountName
            search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
        
        logger.info(f"Searching with filter: {search_filter}")
        
        service_conn.search(
            search_base=Config.LDAP_BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'mail', 'memberOf', 'distinguishedName', 'userPrincipalName']
        )
        
        if not service_conn.entries:
            logger.warning(f"User '{username}' not found in AD (search base: {Config.LDAP_BASE_DN})")
            service_conn.unbind()
            return None
        
        user_entry = service_conn.entries[0]
        user_dn = str(user_entry.distinguishedName)  # Получаем полный DN пользователя
        logger.info(f"✓ Found user DN: {user_dn}")
        
        # === Проверка пароля пользователя ===
        # Создаём новое соединение под учёткой пользователя с его паролем
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=False  # Не авто-бинд, чтобы отловить ошибку
        )
        
        if not user_conn.bind():
            logger.warning(f"✗ Auth failed for {username}: {user_conn.result}")
            service_conn.unbind()
            return None
        
        logger.info(f"✓ Auth success: {username}")
        
        # Собираем инфо о пользователе (с нормализацией!)
        raw_username = str(user_entry.sAMAccountName)
        user_info = {
            'username': raw_username.lower(),  # 🔥 Ключевое: всегда нижний регистр
            'display_name': str(user_entry.displayName) if user_entry.displayName else raw_username,
            'email': str(user_entry.mail).lower() if user_entry.mail else None,
            'dn': user_dn,
            'member_of': [str(g) for g in (user_entry.memberOf or [])]
        }
        
        user_conn.unbind()
        service_conn.unbind()
        return user_info
        
    except Exception as e:
        logger.error(f"AD auth error: {type(e).__name__}: {e}", exc_info=True)
        return None



def get_user_role(username: str) -> str | None:
    """Возвращает роль пользователя из БД (с нормализацией)"""
    import pymysql
    from config import Config
    
    try:
        # 🔥 Нормализуем входной логин
        username = username.lower().strip()
        
        cfg = Config.MYSQL_CONFIG.copy()
        cursor_name = cfg.pop('cursorclass', 'Cursor')
        cursor_class = getattr(pymysql.cursors, cursor_name) if isinstance(cursor_name, str) else cursor_name
        
        conn = pymysql.connect(**cfg, cursorclass=cursor_class)
        cur = conn.cursor()
        cur.execute("SELECT role FROM vpn_access_roles WHERE samaccountname = %s", (username,))
        row = cur.fetchone()
        conn.close()
        return row['role'] if row else None
    except Exception as e:
        logger.error(f"Role check error: {e}")
        return None

def update_last_login(username: str):
    """Обновляет время последнего входа"""
    import pymysql
    from config import Config
    from datetime import datetime
    
    try:
        username = username.lower().strip()
        conn = pymysql.connect(**Config.MYSQL_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO vpn_access_roles (samaccountname, role, last_login)
            VALUES (%s, 'viewer', %s)
            ON DUPLICATE KEY UPDATE last_login = VALUES(last_login)
        """, (username, datetime.now()))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"update_last_login error: {e}")
