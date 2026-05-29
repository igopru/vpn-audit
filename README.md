# 🔐 VPN Audit & AD Sync System

> **Production-ready solution** for monitoring corporate VPN usage, automatically managing Active Directory group membership based on inactivity, and sending email notifications.

## ✨ Features

- 📡 **Cisco ASA Syslog Parsing** – Dual-format support, automatic deduplication, timezone-aware timestamps
- 🔄 **AD Group Synchronization** – Removes users from VPN access group after configurable inactivity (24/31 days logic)
- 📧 **Smart Email Notifications** – Warning at day 24, final notice at day 31, anti-spam flags
- 🛡 **Dry-Run Mode** – Test all logic safely before touching Active Directory
- 👥 **Custom Deadlines & Whitelists** – Grace periods for auditors, contractors, or VIPs
- 📊 **Web Dashboard** – Flask + Bootstrap, role-based access, session analytics, CSV export
- 🔍 **Never-Connected Detector** – Finds AD group members with zero login history
- 🔒 **Security** – LDAP injection protection, parameterized SQL queries, `.env`-driven secrets

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- MySQL 8.0 / MariaDB 10.5+
- `rsyslog` + `ldap-utils` (for ldapsearch)
- Active Directory access

### 2. Installation
```bash
# Clone & enter
git clone https://github.com/igopru/vpn-audit.git
cd vpn-audit
````
# Virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

# Configure secrets
```bash
cp .env.example .env
chmod 600 .env
nano .env  # ← Fill in your DB, LDAP, SMTP settings
```

# Create database
```bash
mysql -u root -p < docs/schema.sql
```

# Initial parse (if historical logs exist)
```bash
python parser.py
```

# 3. Automation (Cron)

```text
# Parser: every 15 min (or daily at 08:45)
45 8 * * * cd /opt/vpn-audit && venv/bin/python parser.py >> /var/log/vpn-audit/parser.log 2>&1

# AD Sync: Mon-Fri at 09:00
0 9 * * 1-5 cd /opt/vpn-audit && venv/bin/python ad_sync.py >> /var/log/vpn-audit/sync.log 2>&1

# Group status sync: hourly (for accurate UI)
0 * * * * cd /opt/vpn-audit && venv/bin/python sync_ad_group_state.py >> /var/log/vpn-audit/group_sync.log 2>&1
```

## ⚙️ Configuration (.env)

| Variable | Description | Default |
|----------|-------------|---------|
| `VPN_DRY_RUN` | `1` = safe mode (no AD changes), `0` = production | `1` |
| `EMAIL_TEST_OVERRIDE` | Redirect all emails to one address (for testing) | *(empty)* |
| `LDAP_SERVER` | AD controller URL | `ldap://dc1.example.com` |
| `LDAP_GROUP_DN` | DN of the VPN access group | `CN=VPN-Access,OU=SecurityGroups,DC=example,DC=com` |
| `VPN_INACTIVE_DAYS` | Days before disconnection | `31` |

> ⚠️ **Never commit `.env` to Git!** Use `.env.example` as a template.

## 🆘 Troubleshooting

| Issue | Solution |
|-------|----------|
| Emails not sending | Check `SMTP_*` in `.env`, spam folder, port 587 availability |
| `ldapsearch` not found | Install: `sudo apt install ldap-utils` |
| Negative durations in DB | Run the `ALTER TABLE ... GREATEST(0, ...)` SQL command (see docs) |
| Users not hiding in UI | Ensure `sync_ad_group_state.py` runs and CSS has `tr[data-user-state="historical"] { display: none; }` |


📜 License
MIT License – Free for internal and commercial use.
