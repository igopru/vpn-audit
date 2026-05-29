#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify
import pymysql
import csv
from io import StringIO

app = Flask(__name__)
DB_CONF = {"host":"127.0.0.1","user":"vpn_audit","password":"CHANGE_ME","database":"vpn_audit","cursorclass":pymysql.cursors.DictCursor}

@app.route('/')
def dashboard():
    conn = pymysql.connect(**DB_CONF)
    cur = conn.cursor()
    cur.execute("SELECT * FROM vpn_users ORDER BY last_active DESC")
    users = cur.fetchall()
    cur.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 50")
    logs = cur.fetchall()
    conn.close()
    return render_template('index.html', users=users, logs=logs)

@app.route('/api/trigger_sync', methods=['POST'])
def trigger_sync():
    # Можно вызвать подпроцесс ad_sync.py или импортировать функцию
    return jsonify({"status": "queued"})

@app.route('/export')
def export():
    conn = pymysql.connect(**DB_CONF)
    cur = conn.cursor()
    cur.execute("SELECT * FROM vpn_users")
    rows = cur.fetchall()
    conn.close()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(rows[0].keys())
    cw.writerows([r.values() for r in rows])
    output = si.getvalue()
    return output, 200, {'Content-Type': 'text/csv'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
