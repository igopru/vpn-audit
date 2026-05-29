#!/usr/bin/env python3
"""
Поиск "спящих" пользователей: есть в группе VPN, но НИКОГДА не подключались.
Использует ldapsearch для надёжного чтения AD без багов ldap3.
"""
import sys
import re
import csv
import subprocess
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
import pymysql

def get_ad_group_members(group_dn):
    """Получает sAMAccountName всех участников группы VPN через ldapsearch."""
    members = set()
    cmd = [
        'ldapsearch', '-x', '-LLL',
        '-H', Config.LDAP_SERVER,
        '-D', Config.LDAP_BIND_DN,
        '-w', Config.LDAP_BIND_PASSWORD,
        '-b', Config.LDAP_BASE_DN,
        f'(&(objectClass=user)(memberOf={group_dn}))',
        'sAMAccountName'
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            print(f"[WARN] ldapsearch failed: {result.stderr.strip()}")
            return members
        for line in result.stdout.splitlines():
            if line.startswith('sAMAccountName:'):
                login = line.split(':', 1)[1].strip().lower()
                if login:
                    members.add(login)
    except Exception as e:
        print(f"[ERROR] Exception in AD query: {e}")
    return members

def get_db_connected_users():
    """Получает список пользователей, чьи логи были распаршены (есть в БД)."""
    db_cfg = Config.MYSQL_CONFIG.copy()
    cursor_name = db_cfg.pop('cursorclass', 'DictCursor')
    cursor_class = getattr(pymysql.cursors, cursor_name) if isinstance(cursor_name, str) else cursor_name
    conn = pymysql.connect(**db_cfg, cursorclass=cursor_class)
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT LOWER(username) as username FROM vpn_sessions")
    db_users = {row['username'] for row in cur.fetchall()}
    conn.close()
    return db_users

def main():
    print("[LDAP] Получение списка участников группы VPN...")
    ad_vpn_members = get_ad_group_members(Config.VPN_GROUP_DN)
    print(f"[INFO] В группе VPN (AD): {len(ad_vpn_members)}")

    print("[DB] Анализ распаршенных логов...")
    db_connected = get_db_connected_users()
    print(f"[INFO] Подключались хотя бы раз: {len(db_connected)}")

    # Исключаем whitelist и системные/админские аккаунты
    whitelist = {u.lower().strip() for u in Config.VPN_WHITELIST if u.strip()}
    admin_pattern = re.compile(Config.ADMIN_USERNAME_PATTERN)

    # Находим "спящих" (в группе есть, в логах нет, не в белом списке, не админ)
    never_connected = ad_vpn_members - db_connected - whitelist
    never_connected = {u for u in never_connected if not admin_pattern.match(u)}
    sorted_list = sorted(never_connected)

    print(f"\n{'='*60}")
    print("🔍 СПЯЩИЕ ПОЛЬЗОВАТЕЛИ (есть доступ, но никогда не подключались):")
    print(f"{'='*60}")
    
    if sorted_list:
        for user in sorted_list:
            print(f"  🔴 {user}")
        print(f"\nВсего: {len(sorted_list)}")

        csv_path = "sleeping_vpn_users.csv"
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['samaccountname', 'status', 'action_required'])
            for user in sorted_list:
                writer.writerow([user, 'No connection history', 'Review & Remove from AD'])
        print(f"📄 Отчёт сохранён: {csv_path}")
    else:
        print("  ✅ Таких пользователей нет. Все в группе хотя бы раз подключались.")

if __name__ == "__main__":
    main()
