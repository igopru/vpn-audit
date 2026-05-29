#!/usr/bin/env python3
"""
Синхронизация доступа к VPN с Active Directory.
- Проверяет реальный статус учётки в AD
- Удаляет из группы доступа неактивных пользователей (> VPN_INACTIVE_DAYS)
- Игнорирует удалённых, помечает отключённых и перед удалением
- Уважает персональные дедлайны и whitelist
- Работает в DRY_RUN режиме по умолчанию
"""
import sys
import re
import pytz
from datetime import datetime, timedelta
from pathlib import Path
from ldap3 import Server, Connection, SUBTREE, MODIFY_DELETE, SIMPLE

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import Config
import pymysql
from utils.email import send_email

tz = pytz.timezone(Config.TIMEZONE)

def check_ad_status(conn, username: str) -> tuple:
    """
    Возвращает (status, dn)
    status: 'active', 'disabled', 'before_delete', 'deleted'
    """
    try:
        conn.search(
            search_base=Config.LDAP_BASE_DN,
            search_filter=f'(&(objectClass=user)(sAMAccountName={username}))',
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'userAccountControl']
        )
        if not conn.entries:
            return ('deleted', None)

        dn = str(conn.entries[0].distinguishedName)
        uac = int(str(conn.entries[0].userAccountControl)) if conn.entries[0].userAccountControl else 0
        is_disabled = bool(uac & 2)  # ACCOUNTDISABLE flag
        is_before_delete = 'OU=BeforeDelete' in dn

        if is_before_delete:
            return ('before_delete', dn)
        elif is_disabled:
            return ('disabled', dn)
        return ('active', dn)
    except Exception as e:
        print(f"[WARN] LDAP check failed for {username}: {e}")
        return ('unknown', None)

def sync_ad():
    # === 1. Подключение к БД (исправленная инициализация курсора) ===
    db_cfg = Config.MYSQL_CONFIG.copy()
    cursor_name = db_cfg.pop('cursorclass', 'DictCursor')
    cursor_class = getattr(pymysql.cursors, cursor_name) if isinstance(cursor_name, str) else cursor_name
    conn = pymysql.connect(**db_cfg, cursorclass=cursor_class)
    cur = conn.cursor()
    print(f"[DB] Connected to MySQL, cursor: {cursor_class.__name__}")

    # === 2. Подключение к AD (ИСПРАВЛЕНО: внутри функции!) ===
    print(f"[LDAP] Connecting to {Config.LDAP_SERVER} as {Config.LDAP_BIND_DN}")
    server = Server(Config.LDAP_SERVER, get_info=None)
    ad_conn = Connection(
        server,
        user=Config.LDAP_BIND_DN,
        password=Config.LDAP_BIND_PASSWORD,
        authentication=SIMPLE,
        auto_bind=False
    )
    if not ad_conn.bind():
        print(f"[ERROR] AD bind failed: {ad_conn.result}")
        sys.exit(1)
    print("[LDAP] Bind OK")

    cutoff = datetime.now(tz) - timedelta(days=Config.VPN_INACTIVE_DAYS)
    actions_log = []

    # === 3. Загрузка пользователей ===
    cur.execute("""
        SELECT u.samaccountname, u.last_active, u.status, u.ad_group_state, r.custom_deadline
        FROM vpn_users u
        LEFT JOIN vpn_user_rules r ON u.samaccountname = r.username
        WHERE u.status != 'whitelisted'
    """)
    users = cur.fetchall()
    print(f"[DB] Loaded {len(users)} users from vpn_users")

    for user in users:
        username = user['samaccountname']
        last_active = user['last_active']
        custom_deadline = user['custom_deadline']

        # Пропускаем whitelist и админ-паттерны
        if username in Config.VPN_WHITELIST:
            continue
        if re.match(Config.ADMIN_USERNAME_PATTERN, username):
            continue

        # Нормализация timezone
        if last_active and last_active.tzinfo is None:
            last_active = tz.localize(last_active)
        if custom_deadline and custom_deadline.tzinfo is None:
            custom_deadline = tz.localize(custom_deadline)

        # 4. Проверка статуса в AD и обновление в БД
        ad_status, user_dn = check_ad_status(ad_conn, username)
        print(f"[CHECK] {username} -> ad_status={ad_status}, dn={user_dn}")
        
        # 🔥 Обновляем статус в БД (с коммитом даже в DRY_RUN)
        try:
            cur.execute("UPDATE vpn_users SET ad_status = %s WHERE samaccountname = %s", (ad_status, username))
        except Exception as sql_err:
            print(f"[SQL ERROR] Failed to update {username}: {sql_err}")

        # Логика обработки по статусу
        if ad_status == 'deleted':
            continue  # Удалён -> полностью игнорируем

        if ad_status in ('disabled', 'before_delete'):
            msg = f"[REPORT-ONLY] {username} is {ad_status} in AD. Group membership untouched."
            actions_log.append(msg)
            print(msg)
            continue  # Не трогаем группу, но отмечаем для отчёта

        if not user_dn:
            continue  # Не удалось получить DN

        # 5. Активный пользователь: проверка неактивности
        # Сначала проверяем персональный дедлайн
        if custom_deadline and custom_deadline > datetime.now(tz):
            continue  # На индивидуальном таймере

        # Проверка глобального порога
        if last_active and last_active > cutoff:
            continue  # Активен по правилам

        # 6. Неактивен -> готовим отключение
        # Проверяем, есть ли пользователь в группе VPN
        ad_conn.search(
            Config.VPN_GROUP_DN,
            f'(member={user_dn})',
            search_scope=SUBTREE,
            attributes=['member']
        )
        is_member = bool(ad_conn.entries)

        if is_member:
            action_msg = f"REMOVE {username} (last: {last_active or 'never'}, ad_status: {ad_status})"
            
            if Config.DRY_RUN:
                print(f"[DRY-RUN] {action_msg}")
                actions_log.append(f"[DRY] {action_msg}")
            else:
                try:
                    ad_conn.modify(Config.VPN_GROUP_DN, {'member': [(MODIFY_DELETE, [user_dn])]})
                    if ad_conn.result['result'] == 0:
                        print(f"[APPLIED] {action_msg}")
                        actions_log.append(f"[OK] {action_msg}")
                        cur.execute("UPDATE vpn_users SET ad_group_state='removed' WHERE samaccountname=%s", (username,))
                    else:
                        print(f"[ERROR] {action_msg} | LDAP: {ad_conn.result}")
                        actions_log.append(f"[ERR] {action_msg}")
                except Exception as e:
                    print(f"[EXCEPTION] {action_msg} | {e}")
                    actions_log.append(f"[EXC] {action_msg}")

    # === 7. Финализация ===
    # 🔥 Коммитим обновления ad_status ВСЕГДА (даже в DRY_RUN)
    conn.commit()
    print(f"[DB] Committed ad_status updates for {len(users)} users")
    
    if not Config.DRY_RUN:
        # Пишем действия в audit_log только при реальном запуске
        for log_entry in actions_log:
            parts = log_entry.split()
            target_user = parts[1] if len(parts) > 1 else 'UNKNOWN'
            cur.execute("INSERT INTO audit_log (action, username, details) VALUES (%s, %s, %s)",
                        ('SYNC', target_user, log_entry))
        conn.commit()
        print(f"[AUDIT] Logged {len(actions_log)} actions")

    cur.close()
    conn.close()
    ad_conn.unbind()
    print(f"\n[SUMMARY] Processed: {len(actions_log)} actions/reports. DRY_RUN={Config.DRY_RUN}")

if __name__ == "__main__":
    sync_ad()
