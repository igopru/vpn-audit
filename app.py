#!/usr/bin/env python3
import os
import pymysql
import pytz
from datetime import datetime, timedelta
from flask import Flask, render_template, session, request, jsonify, redirect, url_for
from config import Config
from functools import wraps
from utils.auth import authenticate_ad, get_user_role, update_last_login
import secrets

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-change-me")
tz = pytz.timezone(getattr(Config, "TIMEZONE", "Europe/Moscow"))

app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = '/opt/vpn-audit/sessions'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES)

# Создаём папку для сессий
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

from flask_session import Session
Session(app)


def login_required(f):
    """Декоратор: требует авторизации"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not Config.AUTH_ENABLED:
            return f(*args, **kwargs)
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Декоратор: требует определённой роли"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not Config.AUTH_ENABLED:
                return f(*args, **kwargs)
            user_role = session.get('role')
            if user_role not in roles:
                return jsonify({'error': 'Access denied'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def get_db():
    """Создаёт подключение к БД с корректным курсором"""
    import pymysql
    from config import Config
    cfg = Config.MYSQL_CONFIG.copy()
    cursor_name = cfg.pop('cursorclass', 'Cursor')  # Удаляем из kwargs
    if isinstance(cursor_name, str):
        cursor_class = getattr(pymysql.cursors, cursor_name)
    else:
        cursor_class = cursor_name  # Уже класс
    return pymysql.connect(**cfg, cursorclass=cursor_class)

@app.route('/api/rule/<username>', methods=['DELETE'])
def delete_rule(username):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM vpn_user_rules WHERE username = %s", (username,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route('/api/user/<username>/export')
def export_user_csv(username):
    """Экспорт статистики пользователя в CSV"""
    import csv
    from io import StringIO
    
    conn = get_db()
    cur = conn.cursor()
    
    # Собираем детальные данные
    cur.execute("""
        SELECT 
            DATE_FORMAT(start_time, '%%Y-%%m-%%d') as date,
            start_time,
            COALESCE(end_time, NOW()) as end_time,
            TIMESTAMPDIFF(MINUTE, start_time, COALESCE(end_time, NOW())) as duration_min,
            src_ip,
            assigned_vpn_ip,
            status
        FROM vpn_sessions
        WHERE username = %s
        ORDER BY start_time DESC
    """, (username,))
    
    rows = cur.fetchall()
    conn.close()
    
    # Генерируем CSV
    si = StringIO()
    cw = csv.writer(si, delimiter=';', lineterminator='\n')
    cw.writerow(['Дата', 'Начало', 'Конец', 'Длительность (мин)', 'Внешний IP', 'VPN IP', 'Статус'])
    
    for r in rows:
        cw.writerow([
            r['date'],
            r['start_time'].strftime('%Y-%m-%d %H:%M'),
            r['end_time'].strftime('%Y-%m-%d %H:%M') if r['end_time'] else 'активна',
            r['duration_min'],
            r['src_ip'],
            r['assigned_vpn_ip'] or '',
            r['status']
        ])
    
    output = si.getvalue()
    return output, 200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': f'attachment; filename="{username}_vpn_sessions.csv"'
    }

# === Аналитика по пользователю ===
@app.route('/api/user/<username>/stats')
def user_stats(username):
    """Помесячная статистика: часы, сессии, среднее время"""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT 
            DATE_FORMAT(start_time, '%%Y-%%m') as month,
            COUNT(*) as sessions,
            SUM(COALESCE(
                TIMESTAMPDIFF(SECOND, start_time, COALESCE(end_time, NOW())),
                TIMESTAMPDIFF(SECOND, start_time, NOW())
            )) as total_seconds,
            GROUP_CONCAT(DISTINCT src_ip ORDER BY src_ip SEPARATOR ',') as external_ips,
            GROUP_CONCAT(DISTINCT assigned_vpn_ip ORDER BY assigned_vpn_ip SEPARATOR ',') as vpn_ips
        FROM vpn_sessions
        WHERE username = %s AND start_time >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
        GROUP BY month
        ORDER BY month DESC
    """, (username,))
    
    rows = cur.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        hours = round((r['total_seconds'] or 0) / 3600, 2)
        result.append({
            'month': r['month'],
            'sessions': r['sessions'],
            'hours': hours,
            'external_ips': (r['external_ips'] or '').split(',') if r['external_ips'] else [],
            'vpn_ips': (r['vpn_ips'] or '').split(',') if r['vpn_ips'] else []
        })
    return jsonify(result)


@app.route('/api/user/<username>/recent')
def user_recent(username):
    """Последние 50 сессий пользователя для детального просмотра"""
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT 
            start_time, end_time,
            TIMESTAMPDIFF(MINUTE, start_time, COALESCE(end_time, NOW())) as duration_min,
            src_ip, assigned_vpn_ip, status
        FROM vpn_sessions
        WHERE username = %s
        ORDER BY start_time DESC
        LIMIT 50
    """, (username,))
    
    rows = cur.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        result.append({
            'start': r['start_time'].strftime('%Y-%m-%d %H:%M') if r['start_time'] else None,
            'end': r['end_time'].strftime('%Y-%m-%d %H:%M') if r['end_time'] else '⏳ активна',
            'duration_min': r['duration_min'],
            'src_ip': r['src_ip'],
            'vpn_ip': r['assigned_vpn_ip'],
            'status': r['status']
        })
    return jsonify(result)


@app.route('/api/search')
def search_users():
    """Поиск пользователей по подстроке"""
    query = request.args.get('q', '').strip()
    if len(query) < 2:
        return jsonify([])
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT samaccountname, last_active, status
        FROM vpn_users
        WHERE samaccountname LIKE %s
        ORDER BY last_active DESC
        LIMIT 20
    """, (f'%{query}%',))
    
    rows = cur.fetchall()
    conn.close()
    
    return jsonify([{
        'username': r['samaccountname'],
        'last_active': r['last_active'].strftime('%Y-%m-%d %H:%M') if r['last_active'] else None,
        'status': r['status']
    } for r in rows])

# === Настройки ===
@app.route('/settings')
@login_required
@role_required('admin')
def settings_page():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT config_key, config_value, description FROM app_config ORDER BY config_key")
    configs = {r['config_key']: {'value': r['config_value'], 'desc': r['description']} for r in cur.fetchall()}
    conn.close()
    return render_template('settings.html', configs=configs)

@app.route('/api/config', methods=['POST'])
@login_required
@role_required('admin')
def update_config():
    data = request.json
    key, value = data.get('key'), data.get('value')
    if not key:
        return jsonify({'error': 'Missing key'}), 400
        
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO app_config (config_key, config_value, description) 
        VALUES (%s, %s, '') 
        ON DUPLICATE KEY UPDATE config_value=%s
    """, (key, value, value))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', next=request.args.get('next', '/'))
    
    # POST: обработка формы
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    next_url = request.form.get('next', '/')
    
    if not username or not password:
        return render_template('login.html', error='Заполните логин и пароль', next=next_url)
    
    # Проверяем в AD
    user_info = authenticate_ad(username, password)
    if not user_info:
        return render_template('login.html', error='Неверный логин или пароль', next=next_url)
    
    # Проверяем роль в БД
    role = get_user_role(username)
    if not role:
        return render_template('login.html', error='Доступ не предоставлен. Обратитесь к администратору.', next=next_url)
    
    # Успех — создаём сессию
    session.permanent = True
    session['user'] = user_info['username'].lower() 
    session['display_name'] = user_info['display_name']
    session['role'] = role
    session['email'] = user_info['email']
    
    update_last_login(username)
    
    return redirect(next_url if next_url.startswith('/') else '/')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/whoami')
@login_required
def whoami():
    return jsonify({
        'username': session['user'],
        'display_name': session['display_name'],
        'role': session['role'],
        'email': session['email']
    })


# === Защищаем существующие маршруты ===
@app.route('/')
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()
    
    # Загружаем пользователей
    cur.execute("""
        SELECT u.samaccountname, u.last_active, u.status, u.ad_group_state, u.ad_status,
               r.custom_deadline, r.reason, r.created_by
        FROM vpn_users u
        LEFT JOIN vpn_user_rules r ON u.samaccountname = r.username
        ORDER BY COALESCE(r.custom_deadline, u.last_active) DESC
    """)
    users = cur.fetchall()
    
    # 🔥 Загружаем порог неактивности из настроек
    cur.execute("SELECT config_value FROM app_config WHERE config_key = 'vpn_inactive_days'")
    row = cur.fetchone()
    inactive_days = int(row['config_value']) if row and row['config_value'] else 30
    
    conn.close()
    
    now_naive = datetime.now(tz).replace(tzinfo=None)
    
    return render_template('dashboard.html', 
                           users=users, 
                           now=now_naive,
                           inactive_days=inactive_days,
                           current_user=session['user'],
                           current_role=session['role'])


@app.route('/api/rule', methods=['POST'])
@login_required
@role_required('admin', 'auditor')
def set_rule():
    data = request.json
    username = data.get('username', '').strip()
    deadline_str = data.get('deadline')
    reason = data.get('reason', 'Без указания причины')
    
    if not username or not deadline_str:
        return jsonify({'error': 'username и deadline обязательны'}), 400
    try:
        deadline = datetime.fromisoformat(deadline_str)
    except ValueError:
        return jsonify({'error': 'Неверный формат даты'}), 400
        
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vpn_user_rules (username, custom_deadline, reason, created_by)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE custom_deadline=VALUES(custom_deadline), reason=VALUES(reason), created_at=NOW()
    """, (username, deadline, reason, session.get('user')))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

# Добавляем маршрут для управления доступом (только админы)
# === Управление доступом (только админы) ===
@app.route('/access')
@login_required
@role_required('admin')
def access_management():
    """Страница выдачи/отзыва прав доступа"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT samaccountname, role, granted_by, granted_at, last_login 
        FROM vpn_access_roles 
        ORDER BY granted_at DESC
    """)
    users = cur.fetchall()
    conn.close()
    return render_template('access.html', users=users, current_user=session['user'])


@app.route('/api/access', methods=['POST'])
@login_required
@role_required('admin')
def grant_access():
    """Выдать доступ пользователю"""
    data = request.json
    username = data.get('username', '').strip()
    role = data.get('role', 'viewer')
    
    if not username or role not in Config.AUTH_ALLOWED_ROLES:
        return jsonify({'error': 'Invalid username or role'}), 400
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vpn_access_roles (samaccountname, role, granted_by)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE role = VALUES(role), granted_at = NOW()
    """, (username, role, session['user']))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'ok'})


@app.route('/api/access/<username>', methods=['DELETE'])
@login_required
@role_required('admin')
def revoke_access(username):
    """Отозвать доступ у пользователя"""
    # Защита от самоудаления
    if username == session['user']:
        return jsonify({'error': 'Cannot revoke your own access'}), 400
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM vpn_access_roles WHERE samaccountname = %s", (username,))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'ok'})

@app.route('/api/toggle_whitelist', methods=['POST'])
@login_required
@role_required('admin')  # Только админы могут менять белый список
def toggle_whitelist():
    data = request.get_json()
    username = data.get('username', '').lower()
    if not username:
        return jsonify({'error': 'Требуется имя пользователя'}), 400

    conn = get_db()
    cur = conn.cursor()
    
    # Проверяем текущий статус
    cur.execute("SELECT status FROM vpn_users WHERE LOWER(samaccountname) = %s", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Пользователь не найден'}), 404

    # Переключаем: whitelisted <-> active
    current_status = row['status'] or 'active'
    new_status = 'active' if current_status == 'whitelisted' else 'whitelisted'
    
    cur.execute("UPDATE vpn_users SET status = %s WHERE LOWER(samaccountname) = %s", (new_status, username))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'new_status': new_status})

@app.route('/logs/<path:filename>')
@login_required
def view_log(filename):
    """Просмотр логов через Flask (без прямого доступа к файловой системе)"""
    import os
    
    # Безопасность: разрешаем только файлы из настроенной директории
    log_dir = os.path.normpath(Config.LOG_DIR)
    requested = os.path.normpath(os.path.join(log_dir, filename))
    
    if not requested.startswith(log_dir):
        return jsonify({'error': 'Access denied'}), 403
    
    if not os.path.exists(requested):
        return jsonify({'error': 'File not found'}), 404
    
    # Возвращаем последние 1000 строк (чтобы не грузить браузер)
    with open(requested, 'r', errors='ignore') as f:
        lines = f.readlines()[-1000:]
    
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain; charset=utf-8'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
