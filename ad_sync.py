#!/usr/bin/env python3
"""
Синхронизация VPN + AD с почтовыми оповещениями.
Production-версия: использует ldapsearch через subprocess для 100% совместимости с Windows AD.
"""
import sys
import os
import re
import pytz
import subprocess
import json
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import Config
import pymysql
from utils.email import send_email

tz = pytz.timezone(Config.TIMEZONE)


def ldapsearch_user(username):
    """Ищет пользователя в AD через ldapsearch. Возвращает {dn, mail} или None."""
    safe_user = re.sub(r'[*()\\\x00]', '', username)
    
    # 🔥 Убрали -Q, добавили -D и -w для простого бинда под сервисной учёткой
    cmd = [
        'ldapsearch', '-x', '-LLL',
        '-H', Config.LDAP_SERVER,
        '-D', Config.LDAP_BIND_DN,
        '-w', Config.LDAP_BIND_PASSWORD,
        '-b', Config.LDAP_BASE_DN,
        f'(&(objectClass=user)(sAMAccountName={safe_user}))',
        'distinguishedName', 'mail'
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode != 0:
            # Фолбэк: пробуем без objectClass=user
            cmd[-2] = f'(sAMAccountName={safe_user})'
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            return None
        dn = mail = None
        for line in result.stdout.splitlines():
            if line.startswith('distinguishedName:'):
                dn = line.split(':', 1)[1].strip()
            elif line.startswith('mail:'):
                mail = line.split(':', 1)[1].strip()
        return {'dn': dn, 'mail': mail} if dn else None
    except Exception as e:
        print(f"  ⚠️ ldapsearch error for {username}: {e}")
        return None

def ldapsearch_check_group_membership(user_dn, group_dn):
    """Проверяет, состоит ли user_dn в группе через ldapsearch."""
    safe_dn = re.sub(r'[,=*()\\\x00]', r'\\\g<0>', user_dn)
    cmd = [
        'ldapsearch', '-x', '-LLL', '-Q',
        '-H', Config.LDAP_SERVER,
        '-b', group_dn,
        f'(member={safe_dn})',
        'member'
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        return result.returncode == 0 and 'member:' in result.stdout
    except Exception as e:
        print(f"  ⚠️ ldapsearch group check error: {e}")
        return False

def ldapsearch_remove_from_group(user_dn, group_dn):
    """Удаляет пользователя из группы через ldapmodify."""
    safe_dn = re.sub(r'[,=*()\\\x00]', r'\\\g<0>', user_dn)
    ldif = f"""dn: {group_dn}
changetype: modify
delete: member
member: {safe_dn}
"""
    cmd = [
        'ldapmodify', '-x', '-Q',
        '-H', Config.LDAP_SERVER,
        '-D', Config.LDAP_BIND_DN,
        '-w', Config.LDAP_BIND_PASSWORD
    ]
    try:
        result = subprocess.run(cmd, input=ldif, text=True, capture_output=True, timeout=10, check=False)
        return result.returncode == 0
    except Exception as e:
        print(f"  ⚠️ ldapmodify error: {e}")
        return False

def get_db_connection():
    db_cfg = Config.MYSQL_CONFIG.copy()
    cursor_name = db_cfg.pop('cursorclass', 'DictCursor')
    cursor_class = getattr(pymysql.cursors, cursor_name) if isinstance(cursor_name, str) else cursor_name
    return pymysql.connect(**db_cfg, cursorclass=cursor_class)

def sync_ad():
    conn_db = get_db_connection()
    cur = conn_db.cursor()

    cutoff_warning = datetime.now(tz) - timedelta(days=Config.VPN_INACTIVE_DAYS - 7)
    cutoff_remove = datetime.now(tz) - timedelta(days=Config.VPN_INACTIVE_DAYS)
    
    cur.execute("""
        SELECT u.samaccountname, u.last_active, u.ad_status, u.ad_group_state, 
               r.custom_deadline, u.warned_at, u.disconnected_at
        FROM vpn_users u
        LEFT JOIN vpn_user_rules r ON u.samaccountname = r.username
    """)
    users = cur.fetchall()
    print(f"[DB] Loaded {len(users)} users")

    success_count = 0
    skip_count = 0
    error_count = 0
    actions_log = []

    for idx, user in enumerate(users, 1):
        username = user['samaccountname']
        try:
            ad_status = user['ad_status'] or 'active'
            last_active = user['last_active']
            custom_deadline = user['custom_deadline']
            warned_at = user['warned_at']
            disconnected_at = user['disconnected_at']

            if ad_status in ('deleted', 'before_delete', 'disabled'):
                skip_count += 1
                continue

            # Нормализация timezone
            if last_active and last_active.tzinfo is None: last_active = tz.localize(last_active)
            if custom_deadline and custom_deadline.tzinfo is None: custom_deadline = tz.localize(custom_deadline)
            if warned_at and warned_at.tzinfo is None: warned_at = tz.localize(warned_at)
            if disconnected_at and disconnected_at.tzinfo is None: disconnected_at = tz.localize(disconnected_at)

            # 🔍 Поиск в AD через ldapsearch
            ad_info = ldapsearch_user(username)
            if not ad_info or not ad_info['dn']:
                skip_count += 1
                continue
                
            user_dn = ad_info['dn']
            user_email = ad_info['mail']

            if username in Config.VPN_WHITELIST or re.match(Config.ADMIN_USERNAME_PATTERN, username):
                skip_count += 1
                continue

            recipient = Config.EMAIL_TEST_OVERRIDE or user_email

            # 1. Индивидуальный дедлайн
            if custom_deadline:
                if custom_deadline <= datetime.now(tz) and not disconnected_at:
                    if send_email(recipient, "Ваш доступ к VPN отключён",
                                  f"Уважаемый {username},\n\nВаш доступ отключён в связи с истечением индивидуального срока действия."):
                        cur.execute("UPDATE vpn_users SET disconnected_at=NOW() WHERE samaccountname=%s", (username,))
                        actions_log.append(f"[EMAIL+REMOVE] {username} (deadline) -> {recipient}")
                    else:
                        actions_log.append(f"[EMAIL_FAIL] {username}")
                success_count += 1
                continue

            # 2. Стандартная логика
            if last_active:
                if last_active <= cutoff_warning and not warned_at:
                    if send_email(recipient, "Внимание: ваш доступ к VPN скоро будет отключён",
                                  f"Уважаемый {username},\n\nВы не подключались к VPN более 24 дней. Подключитесь для сохранения доступа."):
                        cur.execute("UPDATE vpn_users SET warned_at=NOW() WHERE samaccountname=%s", (username,))
                        actions_log.append(f"[WARN EMAIL] {username} -> {recipient}")

                if last_active <= cutoff_remove and not disconnected_at:
                    if send_email(recipient, "Ваш доступ к VPN отключён",
                                  f"Уважаемый {username},\n\nВаш доступ отключён в связи с отсутствием активности за последние 31 день."):
                        cur.execute("UPDATE vpn_users SET disconnected_at=NOW() WHERE samaccountname=%s", (username,))
                        actions_log.append(f"[EMAIL+REMOVE] {username} -> {recipient}")

                        # 🔥 Удаление из группы через ldapmodify
                        if not Config.DRY_RUN and Config.VPN_GROUP_DN and user_dn:
                            if ldapsearch_check_group_membership(user_dn, Config.VPN_GROUP_DN):
                                if ldapsearch_remove_from_group(user_dn, Config.VPN_GROUP_DN):
                                    actions_log[-1] += " + AD removed"
                                else:
                                    actions_log.append(f"[AD_ERROR] {username}: ldapmodify failed")
            success_count += 1

        except Exception as e:
            error_count += 1
            print(f"  ⚠️ Ошибка обработки {username}: {e}")
            continue

    conn_db.commit()
    cur.close(); conn_db.close()

    print("\n" + "="*60)
    print(f"[SUMMARY] Processed: {success_count} OK | {skip_count} SKIPPED | {error_count} ERRORS")
    print(f"  Actions logged: {len(actions_log)}")
    print(f"  DRY_RUN: {Config.DRY_RUN}")
    print("="*60)
    if actions_log:
        print("DETAILS:")
        for line in actions_log:
            print(f"  • {line}")

if __name__ == "__main__":
    sync_ad()
