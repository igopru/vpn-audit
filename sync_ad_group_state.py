#!/usr/bin/env python3
"""
Синхронизация статуса членства в группе VPN (AD → БД).
v2: Прямой запрос по memberOf, защита от truncation, изоляция ошибок БД.
"""
import sys
import subprocess
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import Config
import pymysql

def get_db_connection():
    db_cfg = Config.MYSQL_CONFIG.copy()
    cursor_name = db_cfg.pop('cursorclass', 'DictCursor')
    cursor_class = getattr(pymysql.cursors, cursor_name) if isinstance(cursor_name, str) else cursor_name
    return pymysql.connect(**db_cfg, cursorclass=cursor_class)

def get_ad_group_members(group_dn):
    """Получает логины участников группы через прямой запрос к AD."""
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
            print(f"[WARN] ldapsearch вернул ошибку: {result.stderr.strip()}")
            return members
            
        for line in result.stdout.splitlines():
            if line.startswith('sAMAccountName:'):
                login = line.split(':', 1)[1].strip()
                if login:
                    members.add(login.lower())
    except Exception as e:
        print(f"[ERROR] Exception: {e}")
    return members

def sync_group_state():
    print(f"🔄 Синхронизация статуса группы: {Config.VPN_GROUP_DN}")
    
    ad_members = get_ad_group_members(Config.VPN_GROUP_DN)
    print(f"✅ Найдено в AD: {len(ad_members)} пользователей")
    
    if len(ad_members) == 0:
        print("⚠️ Внимание: список из AD пуст. Проверьте доступы, DN группы или фильтр.")
        
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT samaccountname, ad_group_state FROM vpn_users")
    db_users = {row['samaccountname'].lower(): row.get('ad_group_state', '') for row in cur.fetchall()}
    print(f"🗄 В БД отслеживается: {len(db_users)} пользователей")
    
    updated = 0
    for username in db_users:
        is_in = username in ad_members
        # Используем короткое значение, чтобы не ломать ENUM/VARCHAR(10)
        new_state = 'in_group' if is_in else 'absent' 
        
        if db_users[username] != new_state:
            try:
                cur.execute(
                    "UPDATE vpn_users SET ad_group_state = %s WHERE LOWER(samaccountname) = %s",
                    (new_state, username)
                )
                updated += 1
                print(f"  {'✅' if is_in else '❌'} {username}: {db_users[username]} → {new_state}")
            except Exception as db_err:
                print(f"  ⚠️ Ошибка БД для {username}: {db_err}")
                
    conn.commit()
    cur.close(); conn.close()
    print(f"\n✨ Готово. Обновлено записей: {updated}")

if __name__ == "__main__":
    sync_group_state()
