#!/usr/bin/env python3
"""
Синхронизация VPN + AD с почтовыми оповещениями.
- 31 день неактивности → отключение + финальное письмо
- 24 дня → предупреждение (если ещё не отправлено)
- Индивидуальный дедлайн → только финальное письмо
- Whitelist сохраняется, но пуст по умолчанию
"""
import sys
import os
import re
import pytz
from datetime import datetime, timedelta
from pathlib import Path
from ldap3 import Server, Connection, SUBTREE, MODIFY_DELETE, SIMPLE
from ldap3.utils.conv import escape_filter_chars

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import Config
import pymysql
from utils.email import send_email

tz = pytz.timezone(Config.TIMEZONE)

def get_ad_connection():
    server = Server(Config.LDAP_SERVER, get_info=None)
    conn = Connection(server, user=Config.LDAP_BIND_DN, password=Config.LDAP_BIND_PASSWORD,
                      authentication=SIMPLE, auto_bind=False)
    if not conn.bind():
        print(f"[ERROR] AD bind failed: {conn.result}")
        sys.exit(1)
    return conn

def get_db_connection():
    db_cfg = Config.MYSQL_CONFIG.copy()
    cursor_name = db_cfg.pop('cursorclass', 'DictCursor')
    cursor_class = getattr(pymysql.cursors, cursor_name) if isinstance(cursor_name, str) else cursor_name
    return pymysql.connect(**db_cfg, cursorclass=cursor_class)

def sync_ad():
    conn = get_db_connection()
    ad_conn = get_ad_connection()
    cur = conn.cursor()

    cutoff_warning = datetime.now(tz) - timedelta(days=Config.VPN_INACTIVE_DAYS - 7)  # 24 дня
    cutoff_remove = datetime.now(tz) - timedelta(days=Config.VPN_INACTIVE_DAYS)      # 31 день
    
    cur.execute("""
        SELECT u.samaccountname, u.last_active, u.ad_status, u.ad_group_state, 
               r.custom_deadline, u.warned_at, u.disconnected_at
        FROM vpn_users u
        LEFT JOIN vpn_user_rules r ON u.samaccountname = r.username
    """)
    users = cur.fetchall()
    print(f"[DB] Loaded {len(users)} users")

    actions_log = []

    for user in users:
        username = user['samaccountname']
        ad_status = user['ad_status'] or 'active'
        last_active = user['last_active']
        custom_deadline = user['custom_deadline']
        warned_at = user['warned_at']
        disconnected_at = user['disconnected_at']

        # Пропускаем удалённых и готовящихся к удалению
        if ad_status in ('deleted', 'before_delete', 'disabled'):
            continue

        # === Нормализация timezone (явная, без цикла) ===
        if last_active and last_active.tzinfo is None:
            last_active = tz.localize(last_active)
        if custom_deadline and custom_deadline.tzinfo is None:
            custom_deadline = tz.localize(custom_deadline)
        if warned_at and warned_at.tzinfo is None:
            warned_at = tz.localize(warned_at)
        if disconnected_at and disconnected_at.tzinfo is None:
            disconnected_at = tz.localize(disconnected_at)

        # === Получаем DN и email из AD ===
        safe_user = escape_filter_chars(username)
        try:
            ad_conn.search(
                search_base=Config.LDAP_BASE_DN,
                search_filter=f'(&(objectClass=user)(sAMAccountName={safe_user}))',
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'mail']
            )
        except Exception as ldap_err:
            print(f"[WARN] LDAP search for {username} failed: {ldap_err}")
            continue
        if not ad_conn.entries:
            continue
            
        user_dn = str(ad_conn.entries[0].distinguishedName)
        user_email = str(ad_conn.entries[0].mail) if ad_conn.entries[0].mail else None

        # === ЛОГИКА ===
        # 1. Whitelist
        if username in Config.VPN_WHITELIST or re.match(Config.ADMIN_USERNAME_PATTERN, username):
            continue

        # 2. Индивидуальный дедлайн → только финальное письмо
        if custom_deadline:
            if custom_deadline <= datetime.now(tz) and not disconnected_at:
                recipient = Config.EMAIL_TEST_OVERRIDE or user_email
                if Config.EMAIL_TEST_OVERRIDE:
                    print(f"[TEST MODE] Deadline email: {user_email} → {recipient}")
                    
                if send_email(recipient, "Ваш доступ к VPN отключён",
                              f"Уважаемый {username},\n\nВаш доступ к корпоративной VPN был отключён в связи с истечением индивидуального срока действия.\n\nЕсли доступ вам ещё требуется, обратитесь в службу поддержки."):
                    cur.execute("UPDATE vpn_users SET disconnected_at=NOW() WHERE samaccountname=%s", (username,))
                    actions_log.append(f"[EMAIL+REMOVE] {username} (deadline)")
            continue

        # 3. Стандартная логика
        if last_active:
            # Предупреждение за 7 дней (24 дня неактивности)
            if last_active <= cutoff_warning and not warned_at:
                recipient = Config.EMAIL_TEST_OVERRIDE or user_email
                if Config.EMAIL_TEST_OVERRIDE:
                    print(f"[TEST MODE] Warning email: {user_email} → {recipient}")
                    
                if send_email(recipient, "Внимание: ваш доступ к VPN скоро будет отключён",
                              f"Уважаемый {username},\n\nВы не подключались к VPN более 24 дней. Если вы не проявите активность в ближайшие 7 дней, доступ будет автоматически отключён."):
                    cur.execute("UPDATE vpn_users SET warned_at=NOW() WHERE samaccountname=%s", (username,))
                    actions_log.append(f"[WARN EMAIL] {username}")

            # Отключение (31 день неактивности)
            if last_active <= cutoff_remove and not disconnected_at:
                recipient = Config.EMAIL_TEST_OVERRIDE or user_email
                if Config.EMAIL_TEST_OVERRIDE:
                    print(f"[TEST MODE] Disconnect email: {user_email} → {recipient}")
                    
                if send_email(recipient, "Ваш доступ к VPN отключён",
                              f"Уважаемый {username},\n\nВаш доступ к VPN отключён в связи с отсутствием активности за последние 31 день.\n\nДля восстановления обратитесь в IT-отдел."):
                    cur.execute("UPDATE vpn_users SET disconnected_at=NOW() WHERE samaccountname=%s", (username,))
                    actions_log.append(f"[EMAIL+REMOVE] {username}")
                
                # Удаление из группы AD (только если DRY_RUN выключен)
                if not Config.DRY_RUN and Config.VPN_GROUP_DN and user_dn:
                    try:
                        ad_conn.search(Config.VPN_GROUP_DN, f'(member={escape_filter_chars(user_dn)})', SUBTREE, attributes=['member'])
                        if ad_conn.entries:
                            ad_conn.modify(Config.VPN_GROUP_DN, {'member': [(MODIFY_DELETE, [user_dn])]})
                            if ad_conn.result['result'] == 0:
                                actions_log[-1] += " + AD removed"
                    except Exception as e:
                        actions_log.append(f"[AD_ERROR] {username}: {e}")


    # Финализация
    conn.commit()
    cur.close(); conn.close()
    ad_conn.unbind()

    print("\n[SUMMARY] Actions performed:")
    for line in actions_log:
        print(f"  • {line}")
    print(f"\n[SUMMARY] Total: {len(actions_log)} operations. DRY_RUN={Config.DRY_RUN}")

if __name__ == "__main__":
    sync_ad()
