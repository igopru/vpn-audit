#!/usr/bin/env python3
"""
Парсер логов Cisco ASA (универсальный: поддержка старого и rsyslog-формата)
"""
import re
import os
import sys
import pytz
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import Config
import pymysql

cursor_class = getattr(pymysql.cursors, Config.MYSQL_CONFIG.pop('cursorclass', 'Cursor'))

# Универсальные regex для извлечения данных из сообщения
RE_START = re.compile(
    r'722051:.*?User\s+<([^>]+)>\s+IP\s+<([\d.]+)>\s+IPv4 Address\s+<([\d.]+)>.*?assigned to session',
    re.IGNORECASE
)
RE_END = re.compile(
    r'722037:.*?User\s+<([^>]+)>\s+IP\s+<([\d.]+)>.*?SVC closing connection:',
    re.IGNORECASE
)

MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
          'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

def parse_timestamp(ts_str: str) -> datetime:
    tz = pytz.timezone(Config.TIMEZONE)
    ts_str = ts_str.strip()
    
    # Формат 1 (Старый): Wed Apr 29 06:47:34 2026
    m1 = re.match(r'^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+([\d:]+)\s+(\d{4})', ts_str)
    if m1:
        dow, mon, day, time_str, year = m1.groups()
        h, m, s = map(int, time_str.split(':'))
        return tz.localize(datetime(int(year), MONTHS[mon], int(day), h, m, s))
        
    # Формат 2 (Стандартный syslog): May  7 11:25:00 (год не указан, берём текущий)
    m2 = re.match(r'^(\w{3})\s+(\d{1,2})\s+([\d:]+)', ts_str)
    if m2:
        mon, day, time_str = m2.groups()
        h, m, s = map(int, time_str.split(':'))
        year = datetime.now(tz).year
        return tz.localize(datetime(year, MONTHS[mon], int(day), h, m, s))
        
    raise ValueError(f"Unknown timestamp: {ts_str}")

def parse_and_save():
    tz = pytz.timezone(Config.TIMEZONE)
    conn = pymysql.connect(**Config.MYSQL_CONFIG, cursorclass=cursor_class, autocommit=True)
    cur = conn.cursor()
    
    log_path = Path(Config.LOG_DIR)
    processed = 0
    
    for log_file in sorted(log_path.glob("*.log")):
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                # === Разбор строки: поддерживаем оба формата ===
                if ';' in line:
                    # Старый формат: "Wed Apr 29 06:47:34 2026;10.10.10.2; <172>:..."
                    ts_part, _, msg_part = line.partition(';')
                    msg_part = msg_part.lstrip(';').strip()
                else:
                    # Стандартный syslog: "May  7 11:25:00 hostname message"
                    # split() без аргумента разбивает по ЛЮБОМУ пробелу и убирает пустые строки
                    tokens = line.split()
                    if len(tokens) < 5:
                        continue  # слишком короткая строка
                    # tokens[0]=Mon, [1]=DD, [2]=HH:MM:SS, [3]=hostname, [4:]=message
                    ts_part = f"{tokens[0]} {tokens[1]} {tokens[2]}"
                    msg_part = ' '.join(tokens[4:])  # всё после hostname
                
                try:
                    event_time = parse_timestamp(ts_part)
                except Exception:
                    continue  # пропускаем строки с непонятным временем
                
                # Start session (722051)
                m = RE_START.search(msg_part)
                if m:
                    username, ext_ip, vpn_ip = m.groups()
                    cur.execute(
                        "INSERT INTO vpn_sessions (username, src_ip, assigned_vpn_ip, start_time) "
                        "VALUES (%s, %s, %s, %s) "
                        "ON DUPLICATE KEY UPDATE start_time=VALUES(start_time), assigned_vpn_ip=VALUES(assigned_vpn_ip)",
                        (username, ext_ip, vpn_ip, event_time)
                    )
                    processed += 1
                    continue
                
                # End session (722037)
                m = RE_END.search(msg_part)
                if m:
                    username, ext_ip = m.groups()
                    cur.execute(
                        "UPDATE vpn_sessions "
                        "SET end_time = %s, status = 'closed' "
                        "WHERE username = %s AND src_ip = %s AND end_time IS NULL "
                        "ORDER BY start_time DESC LIMIT 1",
                        (event_time, username, ext_ip)
                    )
                    if cur.rowcount > 0:
                        processed += 1

    # Агрегация last_active
    cur.execute(
        "INSERT INTO vpn_users (samaccountname, last_active, status) "
        "SELECT username, MAX(COALESCE(end_time, start_time)), 'active' "
        "FROM vpn_sessions WHERE end_time IS NOT NULL OR start_time IS NOT NULL "
        "GROUP BY username "
        "ON DUPLICATE KEY UPDATE last_active=VALUES(last_active), updated_at=NOW()"
    )
    
    cur.close()
    conn.close()
    print(f"[{datetime.now(tz)}] Parser: {processed} events processed")

if __name__ == "__main__":
    parse_and_save()
