🔐 VPN Audit & AD Sync System
A self-hosted solution for monitoring corporate VPN usage, automatically managing Active Directory group membership based on inactivity, and sending email notifications. Built with Python, Flask, MySQL, and LDAP.
✅ Production-ready | 🔒 Security-first | 📧 Email notifications | 🌐 Role-based Web UI



## 📋 Features

- 📡 **Cisco ASA Syslog Parsing** – Dual-format support (legacy & standard rsyslog), automatic deduplication, timezone-aware timestamps
- 🔄 **AD Group Synchronization** – Removes users from VPN access group after configurable inactivity threshold
- 📧 **Smart Email Notifications** – Warning at day 24, final notice at day 31, anti-spam flags prevent duplicate sends
- 🛡 **Dry-Run Mode** – Test all logic safely before touching Active Directory
- 👥 **Custom Deadlines & Whitelists** – Grace periods for auditors, contractors, or VIPs via CLI or Web UI
- 📊 **Web Dashboard** – Flask + Bootstrap, role-based access (admin/auditor/viewer), session analytics, CSV export
- 🔍 **Never-Connected Detector** – `find_never_connected.py` finds AD group members with zero login history
- 🔒 **Security** – LDAP injection protection, parameterized SQL queries, `.env`-driven secrets, systemd isolation

---

## 🏗 Architecture



Cisco ASA ──UDP 514──▶ rsyslog ──▶ /opt/vpn-audit/logs/syslog.log
                                      │
                                      ▼
                               parser.py (cron */15)
                                      │
                                      ▼
                               MySQL (vpn_sessions → vpn_users)
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
        ad_sync.py (cron)      Flask Web UI (systemd)   find_never_connected.py
                 │                    │                    │
                 ▼                    ▼                    ▼
          AD Group Update      Dashboard / Reports     Audit CSV Export
          Email Notifications  Role Management        Clean-up Candidates



## ⚙️ Requirements

- Python 3.9+
- MySQL 8.0 / MariaDB 10.5+
- `rsyslog` (system package)
- Active Directory / LDAP access
- `systemd` & `cron`

---

## 🚀 Installation

# 1. Clone & enter

    git clone https://github.com/YOUR_ORG/vpn-audit.git

    cd vpn-audit

# 2. Virtual environment & dependencies

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

# 3. Configure secrets

    cp .env.example .env

    chmod 600 .env

    nano .env  # ← Fill in your DB, LDAP, SMTP, and SECRET_KEY

# 4. Create database

    mysql -u root -p

CREATE DATABASE vpn_audit CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vpn_audit'@'localhost' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON vpn_audit.* TO 'vpn_audit'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# 5. Run initial parser (if historical logs exist)

    python parser.py



### 🗄 Database Schema

The application expects the following core tables. You can create them manually or import `docs/schema.sql` (provided in the repo):



CREATE TABLE vpn_users (
  samaccountname VARCHAR(255) PRIMARY KEY,
  last_active DATETIME NULL,
  status VARCHAR(50) DEFAULT 'active',
  ad_status ENUM('active','disabled','before_delete','deleted') DEFAULT 'active',
  ad_group_state VARCHAR(50) DEFAULT 'in_group',
  warned_at DATETIME NULL,
  disconnected_at DATETIME NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE vpn_sessions (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255),
  src_ip VARCHAR(45),
  assigned_vpn_ip VARCHAR(45),
  start_time DATETIME,
  end_time DATETIME NULL,
  duration_sec INT GENERATED ALWAYS AS (TIMESTAMPDIFF(SECOND, start_time, COALESCE(end_time, start_time))) STORED,
  status VARCHAR(20) DEFAULT 'active',
  UNIQUE KEY uk_session (username, src_ip, start_time),
  INDEX idx_user (username),
  INDEX idx_start (start_time)
);
-- Additional tables: vpn_access_roles, vpn_user_rules, audit_log

## ⚡ Running the Application

### 🔹 Development

    source venv/bin/activate

    export FLASK_DEBUG=1

    python app.py

 → http://localhost:5010



### 🔹 Production (systemd)



# /etc/systemd/system/vpn-audit-web.service

[Unit]
Description=VPN Audit Web UI
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/vpn-audit
Environment="PATH=/opt/vpn-audit/venv/bin"
ExecStart=/opt/vpn-audit/venv/bin/gunicorn --bind 127.0.0.1:5010 --workers 3 --timeout 120 app:app
Restart=always

[Install]
WantedBy=multi-user.target



    sudo systemctl daemon-reload

    sudo systemctl enable --now vpn-audit-web



## 📅 Automation (Cron & Logrotate)

### 🔹 Parser (every 15 min)

*/15 * * * * cd /opt/vpn-audit && /opt/vpn-audit/venv/bin/python parser.py >> /var/log/vpn-audit/parser.log 2>&1



### 🔹 AD Sync (daily at 09:00, Mon-Fri)

0 9 * * 1-5 cd /opt/vpn-audit && /opt/vpn-audit/venv/bin/python ad_sync.py >> /var/log/vpn-audit/sync.log 2>&1

### 🔹 Logrotate (`/etc/logrotate.d/vpn-audit`)

/opt/vpn-audit/logs/syslog.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    prerotate
        /opt/vpn-audit/venv/bin/python /opt/vpn-audit/parser.py >> /var/log/vpn-audit/parser.log 2>&1 || true
    endscript
    postrotate
        /bin/kill -HUP $(cat /var/run/rsyslogd.pid 2>/dev/null || pgrep rsyslogd) 2>/dev/null || true
    endscript
}



## 🔑 Configuration Variables (`.env`)

| Variable                                                                 | Description                        | Default                  |
| ------------------------------------------------------------------------ | ---------------------------------- |:------------------------:|
| `SECRET_KEY`                                                             | Flask session encryption           | *(required)*             |
| `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`                           | MySQL credentials                  | `127.0.0.1`              |
| `LDAP_SERVER`, `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD`                      | AD service account                 | `ldap://dc1.example.com` |
| `LDAP_BASE_DN`, `LDAP_GROUP_DN`                                          | Search base & VPN group DN         | `DC=example,DC=com`      |
| `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USE_TLS`, `SMTP_USER`, `SMTP_PASSWORD` | Mail relay                         | `smtp.example.com`       |
| `VPN_INACTIVE_DAYS`                                                      | Days before disconnection          | `31`                     |
| `VPN_DRY_RUN`                                                            | `1` = safe mode, `0` = production  | `1`                      |
| `EMAIL_TEST_OVERRIDE`                                                    | Redirect all emails to one address | *(empty)*                |
| `TIMEZONE`                                                               | Python timezone string             | `UTC`                    |

## 🛡 Security & Best Practices

1. **Never commit `.env`** – It's in `.gitignore` by default. Use `secrets management` in CI/CD.
2. **Minimal LDAP permissions** – The service account only needs `Read` on user objects and `Write` on `memberOf` for the target VPN group.
3. **Always start with `VPN_DRY_RUN=1`** – Review logs before switching to production.
4. **Anti-spam protection** – `warned_at` and `disconnected_at` columns prevent duplicate emails on every cron run.
5. **LDAP Injection Prevention** – All filters use `ldap3.utils.conv.escape_filter_chars()`.
6. **SQL Injection Prevention** – All queries use parameterized `%s` placeholders.

---

## 🧪 Testing & Validation

1. Test email delivery (redirects to EMAIL_TEST_OVERRIDE)

    python test_email.py

2. Dry-run sync (no AD changes, emails go to override address)

    VPN_DRY_RUN=1 python ad_sync.py

3. Find AD group members with zero VPN logins

       python scripts/find_never_connected.py

| Issue                                                              | Solution                                                                        |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| `LDAPInvalidDereferenceAliasesError`                               | Ensure `Server(..., get_info=None)` or use `OFFLINE_AD` in `ldap3`              |
| rsyslog writes to `syslog.log.1` after rotation                    | Add `kill -HUP` to `postrotate` (see logrotate config above)                    |
| `TypeError: can't compare offset-naive and offset-aware datetimes` | Ensure all DB timestamps are localized with `pytz`/`zoneinfo` before comparison |
| Web UI shows `403` or login fails                                  | Verify `AUTH_AD_BIND_DN/PASSWORD` in `.env` and AD connectivity                 |
| Emails not sending                                                 | Check `SMTP_USE_TLS`, relay whitelist, and `EMAIL_ENABLED=1`                    |

## 📜 License

[MIT License](https://chat.qwen.ai/c/LICENSE)

---

> 💡 **Need help?** Open an Issue with your environment details, logs, and `.env.example` (redacted). Contributions and security audits are welcome. 🛡️✨
