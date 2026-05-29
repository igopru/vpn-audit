# 🔐 VPN Audit System

Инструмент для аудита, мониторинга и автоматического управления доступом к Cisco AnyConnect VPN.
Собирает логи с firewall (Cisco ASA), хранит историю сессий в MySQL и позволяет гибко управлять доступом пользователей через веб-интерфейс с авторизацией по AD.

## ✨ Возможности

- **📊 Сбор логов:** Парсинг логов Cisco ASA (AnyConnect) с помощью `rsyslog`.
- **📈 Аналитика:** Статистика по месяцам, часы активности, IP-адреса.
- **🛡 Управление доступом:**
  - Автоматическое исключение неактивных пользователей из AD-группы.
  - Гибкие таймеры: глобальный порог (напр. 30 дней) и персональные исключения (VIP, отпуск, аудиторы).
- **🔐 Безопасность:**
  - Авторизация по Active Directory (ролевой доступ: admin, auditor, viewer).
  - Защита от несанкционированного доступа к настройкам.
- **📤 Экспорт:** Выгрузка статистики пользователя в CSV.
- **🐳 Docker:** Готов к развёртыванию в контейнерах.

## 🚀 Быстрый старт

### 1. Предварительные требования
- Linux (Debian/Ubuntu/CentOS)
- Python 3.10+
- MySQL 8.0+
- Active Directory (для авторизации и управления группами)

### 2. Установка из исходников

# Клонирование или копирование файлов
```bash
cd /opt/vpn-audit
```
# Виртуальное окружение
```bash
python3 -m venv venv
source venv/bin/activate
```

# Установка зависимостей
```bash
pip install -r requirements.txt
```

# Создание базы данных и пользователя (запрос пароля будет)
```bash
mysql -u root -p < db_schema.sql
```

# Настройка конфигурации
```bash
cp .env.example .env
```

# Отредактируйте .env: введите пароли БД и AD
```bash
nano .env
```

### 3. Настройка логов (rsyslog)
На сервере, где крутится приложение:
```bash
# /etc/rsyslog.d/99-remote.conf
module(load="imudp")
input(type="imudp" port="514")
:fromhost-ip, !isequal, "127.0.0.1" /opt/vpn-audit/logs/syslog.log
```

Перезагрузите rsyslog: systemctl restart rsyslog.

### 4. Запуск сервиса

# Парсер логов 
```bash
(добавить в crontab: */15 * * * * /path/to/venv/bin/python parser.py)
```

```bash
python parser.py
```

# Веб-сервер
```bash
gunicorn --bind 0.0.0.0:8000 app:app
```

### 🐳 Docker (Docker Compose)
Для быстрого развёртывания используйте docker-compose:

# Создайте директорию для логов и данных
```bash
mkdir -p logs data
```

# Запуск
```bash
docker-compose up -d
```

Контейнер ожидает, что логи будут писать в папку ./logs на хост-машине.

### ⚙️ Конфигурация
Основные настройки находятся в файле .env:
DB_*: Параметры подключения к MySQL.
AUTH_AD_*: Параметры подключения к AD (сервер, учётка, OU).
VPN_*: Путь к логом, DN группы доступа.
🛡 Развертывание в Production
Рекомендуется поставить Nginx как реверс-прокси:
```bash
server {
    listen 80;
    server_name vpn-audit.local;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 📜 Лицензия
MIT License. Свободно для использования во внутренних сетях.


---

### 🐳 2. Файл `Dockerfile`
Создайте его в корне `/opt/vpn-audit/Dockerfile`. Он настроит среду для приложения.

```dockerfile
# Базовый образ Python
FROM python:3.10-slim
```

# Рабочая директория
WORKDIR /app

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код приложения
COPY . .

# Создаем пользователя (для безопасности)
```bash
RUN useradd -m vpnuser && chown -R vpnuser:vpnuser /app
USER vpnuser
```

# Экспонируем порт для Gunicorn
EXPOSE 8000

# Команда запуска
```bash
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
```
