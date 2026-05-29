# 📘 Административная документация: VPN Audit & AD Sync System

> **Версия:** 1.0 | **Дата:** 15.05.2026 | **Для:** Системных администраторов и инженеров ИБ

---

## 📖 1. Назначение и архитектура

Система автоматически:

- Собирает логи Cisco ASA через `rsyslog`
- Парсит сессии и сохраняет в MySQL
- Анализирует активность пользователей
- Отправляет предупреждения (24 дня) и уведомления об отключении (31 день)
- Удаляет неактивных пользователей из группы AD (`VPNAnyConnect`)
- Предоставляет веб-дашборд для ручного управления, установки дедлайнов и аудита

### 🏗 Компоненты

| Файл                      | Назначение                                                                  |
| ------------------------- | --------------------------------------------------------------------------- |
| `parser.py`               | Парсинг `syslog.log`, запись сессий в БД                                    |
| `ad_sync.py`              | Логика отключения, отправка писем, удаление из AD (через `ldapsearch`)      |
| `sync_ad_group_state.py`  | Синхронизация статуса членства в группе (обновляет `ad_group_state` для UI) |
| `app.py`                  | Flask-дашборд (аутентификация, API, отчёты)                                 |
| `find_never_connected.py` | Поиск учётных записей в группе AD без единой сессии в логах                 |
| `test_disconnect.py`      | Изолированный тест отключения на одном пользователе                         |

---

## 🚀 2. Быстрый старт (развертывание)

### 🔹 Требования

- Python 3.10+
- MySQL 8.0 / MariaDB 10.5+
- `rsyslog`
- Пакет `ldap-utils` (обязательно для `ldapsearch`)
- `systemd` + `cron`

### 🔹 Установка

```
# 1. Клонирование / копирование
mkdir -p /opt/vpn-audit
cd /opt/vpn-audit

# 2. Виртуальное окружение и зависимости
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo apt-get install -y ldap-utils  # ⚠️ Обязательно!

# 3. Конфигурация
cp .env.example .env
chmod 600 .env
nano .env  # ← Заполните реальные данные

# 4. База данных
mysql -u root -p <<SQL
CREATE DATABASE vpn_audit CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vpn_audit'@'localhost' IDENTIFIED BY 'strong_password';
GRANT ALL PRIVILEGES ON vpn_audit.* TO 'vpn_audit'@'localhost';
FLUSH PRIVILEGES;
SQL

# 5. Первый запуск парсера (если есть исторические логи)
python parser.py
```

🔹 Регистрация сервисов

```
sudo cp systemd/vpn-audit-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-audit-web
sudo journalctl -u vpn-audit-web -f  # Проверка логов
```

## ⚙️ 3. Конфигурация (`.env`)

| Переменная                            | Описание                                                                   | Пример                                                    |
| ------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------- |
| `VPN_DRY_RUN`                         | `1` = безопасный режим (только логи/письма), `0` = реальное удаление из AD | `1`                                                       |
| `EMAIL_TEST_OVERRIDE`                 | Все письма уходят только на этот адрес (для тестов)                        | `admin@company.ru`                                        |
| `LDAP_SERVER`                         | Адрес контроллера домена                                                   | `ldap://dc1.company.local`                                |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | Сервисная учётка AD (только чтение + запись в `memberOf` целевой группы)   | `CN=svc_vpn_audit,OU=ServiceAccounts,DC=company,DC=local` |
| `LDAP_BASE_DN`                        | База поиска пользователей                                                  | `DC=company,DC=local`                                     |
| `LDAP_GROUP_DN`                       | DN группы доступа к VPN                                                    | `CN=VPN-Access,OU=SecurityGroups,DC=company,DC=local`     |
| `SMTP_*`                              | Настройки почтового релея                                                  | `SMTP_PORT=587`, `SMTP_USE_TLS=1`                         |
| `VPN_INACTIVE_DAYS`                   | Порог неактивности перед отключением                                       | `31`                                                      |
| `TIMEZONE`                            | Часовой пояс для расчётов                                                  | `Europe/Moscow`                                           |

> ⚠️ **Никогда не коммитьте `.env` в Git.** Используйте `.env.example` как шаблон.

## 🖥 4. Ежедневная эксплуатация

### 📅 Расписание (Cron)

```
# Парсер логов: каждые 15 минут (08:00–22:00)
*/15 8-22 * * * cd /opt/vpn-audit && venv/bin/python parser.py >> /var/log/vpn-audit/parser.log 2>&1

# Синхронизация статуса группы AD → БД: каждый час
0 * * * * cd /opt/vpn-audit && venv/bin/python sync_ad_group_state.py >> /var/log/vpn-audit/group_sync.log 2>&1

# Отключение + уведомления: Пн-Пт в 09:00
0 9 * * 1-5 cd /opt/vpn-audit && venv/bin/python ad_sync.py >> /var/log/vpn-audit/sync.log 2>&1
```

### 🌐 Веб-дашборд (`http://<host>:5010`)

| Функция             | Как использовать                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------- |
| 🔍 Поиск            | Введите `samaccountname` → находит любого, включая скрытых/уволенных                              |
| ⏱ Дедлайн           | Введите логин, дату/время и причину → пользователь получит только финальное письмо в момент срока |
| 🛡 Белый список     | Галочка в таблице → пользователь полностью игнорируется логикой отключения                        |
| 📜 Показать скрытых | Кнопка под таблицей → переключает отображение уволенных и исключённых из группы                   |
| 📊 Детали           | Клик по логину → модальное окно со статистикой по месяцам, последними сессиями и IP               |

---

## 🛠 5. Ручные утилиты

### 🔹 `sync_ad_group_state.py`

Обновляет поле `ad_group_state` в БД на основе реального состава группы AD.

```
cd /opt/vpn-audit && source venv/bin/activate
python sync_ad_group_state.py
# ✅ Обновляет статусы, чтобы дашборд корректно скрывал "архивных"
```

### 🔹 `find_never_connected.py`

Находит учётные записи в группе VPN, у которых **никогда не было сессий** в логах.

```bash
python find_never_connected.py
# 📄 Генерирует CSV для аудита и чистки группы
```

### 🔹 `test_disconnect.py`

Безопасный тест отключения на одном пользователе.

```bash
# В скрипте: AD_DRY_RUN = True (по умолчанию)
python test_disconnect.py
# ✅ Придёт 2 тестовых письма. Группа в AD НЕ изменится.
# Для реального теста: AD_DRY_RUN = False → запустить → проверить AD → вернуть True
```

🆘 6. Устранение неполадок
Симптом
Диагностика
Решение
Письма не уходят
tail -f /var/log/vpn-audit/sync.log | grep EMAIL
Проверить SMTP_* в .env, папку "Спам", доступность порта 587
ad_sync.py пишет 0 OK
pip show ldap-utils
Установить sudo apt install ldap-utils. Скрипт работает через ldapsearch
rsyslog пишет в syslog.log.1
ls -la logs/
Применить postrotate: kill -HUP $(pgrep rsyslogd) в /etc/logrotate.d/vpn-audit
Дашборд показывает старых пользователей
SELECT ad_group_state FROM vpn_users LIMIT 5;
Запустить sync_ad_group_state.py вручную или дождаться cron-запуска
Кнопка «📜 Показать скрытых» не переключается
F12 → Console
Очистить кэш браузера (Ctrl+Shift+R). Убедиться, что в <style> есть display: none для скрытых строк
TypeError: can't compare offset-naive...
Логи ad_sync.py
Убедиться, что TIMEZONE в .env корректен и совпадает с настройками MySQL
📍 Где смотреть логи

```bash
journalctl -u vpn-audit-web -f          # Веб-интерфейс
tail -f /var/log/vpn-audit/sync.log     # Отключение + письма
tail -f /var/log/vpn-audit/parser.log   # Парсинг логов ASA
tail -f /var/log/vpn-audit/group_sync.log # Синхронизация статуса группы
```

🔒 7. Безопасность и регламенты
DRY_RUN по умолчанию → VPN_DRY_RUN=1 в .env.example. Переключайте в 0 только после согласования с руководством.
Минимальные права AD → сервисная учётка требует только:
Read на sAMAccountName, distinguishedName, mail
Write на атрибут member целевой группы VPN
Защита от спама → колонки warned_at и disconnected_at блокируют повторную отправку писем при каждом запуске cron.
Изоляция ошибок → если один пользователь вызывает ошибку LDAP/DB, скрипт логирует её и продолжает обработку остальных.
Регламент очистки → раз в квартал запускайте find_never_connected.py, выгружайте CSV и удаляйте "мёртвые души" из группы AD.
📎 Приложения
🗃 Пути в системе


```textile
/opt/vpn-audit/
├── .env                    # Секреты (chmod 600)
├── config.py               # Логика чтения конфигов
├── ad_sync.py              # Основная логика отключения
├── parser.py               # Парсер syslog
├── app.py                  # Flask-дашборд
├── sync_ad_group_state.py  # Обновление статуса группы для UI
├── find_never_connected.py # Аудит неиспользуемых доступов
├── logs/                   # Входящие логи ASA
├── venv/                   # Python-окружение
└── templates/dashboard.html # Интерфейс
```

### 🔄 Сброс тестовых флагов (перед первым боевым запуском)

```sql
USE vpn_audit;
UPDATE vpn_users SET warned_at = NULL, disconnected_at = NULL;    
```

### 📝 Пример полного `.env` для production

```sql
SECRET_KEY=openssl_rand_hex_32_here
FLASK_DEBUG=0
DB_HOST=127.0.0.1
DB_USER=vpn_audit
DB_PASSWORD=change_me_strong
DB_NAME=vpn_audit
LDAP_SERVER=ldap://dc1.company.local
LDAP_BIND_DN=CN=svc_vpn_audit,OU=ServiceAccounts,DC=company,DC=local
LDAP_BIND_PASSWORD=svc_password
LDAP_BASE_DN=DC=company,DC=local
LDAP_GROUP_DN=CN=VPN-Access,OU=SecurityGroups,DC=company,DC=local
SMTP_SERVER=smtp.company.local
SMTP_PORT=587
SMTP_USE_TLS=1
SMTP_USER=vpn-notify@company.local
SMTP_PASSWORD=smtp_pass
EMAIL_FROM=VPN-Audit <vpn-notify@company.local>
VPN_INACTIVE_DAYS=31
VPN_DRY_RUN=0
TIMEZONE=Europe/Moscow
LOG_DIR=/opt/vpn-audit/logs
```

> 💡 **Нужна помощь?**  
> Все ошибки логируются с префиксом `[ERROR]` / `[WARN]`.  
> При создании тикета прикладывайте: вывод `tail -n 50 /var/log/vpn-audit/sync.log`, фрагмент `.env` (без паролей) и версию Python (`python3 --version`).

Система полностью готова к эксплуатации. Документация покрывает все рабочие сценарии, найденные в процессе стабилизации. 🛡️📚


