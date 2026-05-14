#!/usr/bin/env python3
"""
Поиск учётных записей в группе VPN, которые НИКОГДА не подключались.
Сравнивает членов группы в AD с данными в БД (vpn_sessions).
"""
import sys
import csv
import re
import os
from pathlib import Path
from ldap3 import Server, Connection, SUBTREE, SIMPLE
from ldap3.utils.conv import escape_filter_chars
import pymysql

# Загружаем .env если он рядом (для удобства ручного запуска)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / '.env')
except ImportError:
    pass

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import Config

def get_ad_vpn_members():
    """Получает sAMAccountName всех прямых участников группы VPN"""
    print("[LDAP] Подключение к AD...")
    server = Server(Config.LDAP_SERVER, get_info=None)
    conn = Connection(server, user=Config.LDAP_BIND_DN, password=Config.LDAP_BIND_PASSWORD, authentication=SIMPLE, auto_bind=False)
    if not conn.bind():
        print(f"[ERROR] AD bind failed: {conn.result}")
        sys.exit(1)

    # Ищем пользователей, состоящих в группе VPN
    safe_group_dn = escape_filter_chars(Config.VPN_GROUP_DN)
    search_filter = f'(&(objectClass=user)(sAMAccountName=*)(memberOf={safe_group_dn}))'
    
    # 🔥 Явно указываем deref_aliases=0, чтобы AD не ругался на aliases
    conn.search(
        Config.LDAP_BASE_DN,
        search_filter,
        SUBTREE,
        attributes=['sAMAccountName'],
        deref_aliases=0  # Аналог DEREF_NEVER
    )

    ad_users = {str(entry.sAMAccountName).lower() for entry in conn.entries}
    conn.unbind()
    return ad_users

def get_db_connected_users():
    """Получает список пользователей, чьи логи были распаршены (есть в БД)"""
    print("[DB] Подключение к MySQL...")
    db_cfg = Config.MYSQL_CONFIG.copy()
    cursor_name = db_cfg.pop('cursorclass', 'DictCursor')
    cursor_class = getattr(pymysql.cursors, cursor_name) if isinstance(cursor_name, str) else cursor_name
    conn = pymysql.connect(**db_cfg, cursorclass=cursor_class)
    cur = conn.cursor()
    
    # Берём уникальных пользователей из таблицы сессий
    cur.execute("SELECT DISTINCT LOWER(username) as username FROM vpn_sessions")
    db_users = {row['username'] for row in cur.fetchall()}
    conn.close()
    return db_users

def main():
    ad_vpn_members = get_ad_vpn_members()
    print(f"[INFO] В группе VPN (AD): {len(ad_vpn_members)}")

    db_connected = get_db_connected_users()
    print(f"[INFO] Подключались хотя бы раз (распаршены логи): {len(db_connected)}")

    # Исключаем whitelist и системные/админские аккаунты
    whitelist = {u.lower() for u in Config.VPN_WHITELIST}
    admin_pattern = getattr(Config, 'ADMIN_USERNAME_PATTERN', r'^admin\.')

    never_connected = ad_vpn_members - db_connected - whitelist
    never_connected = {u for u in never_connected if not re.match(admin_pattern, u)}
    sorted_list = sorted(never_connected)

    print(f"\n{'='*60}")
    print("🔍 Пользователи в группе VPN, которые НИКОГДА не подключались:")
    print(f"{'='*60}")
    
    if sorted_list:
        for user in sorted_list:
            print(f"  🔴 {user}")
        print(f"\nВсего: {len(sorted_list)}")

        # Экспорт в CSV для служебной записки
        csv_path = "never_connected_vpn_users.csv"
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['samaccountname', 'reason'])
            for user in sorted_list:
                writer.writerow([user, 'No connection logs found'])
        print(f"📄 Отчёт сохранён: {csv_path}")
    else:
        print("  ✅ Таких пользователей нет. Все в группе хотя бы раз подключались.")

if __name__ == "__main__":
    main()
