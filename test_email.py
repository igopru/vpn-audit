#!/usr/bin/env python3
"""Тест отправки письма через настроенный SMTP"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import Config
from utils.email import send_email

# 🔥 Куда отправлять тест (замените на свой ящик)
TEST_TO = "admin@example.com"

subject = "🧪 Тест: ВПН АУДИТ — отправка уведомлений"
body = """Уважаемый администратор,

Это тестовое письмо от системы аудита VPN.

Если вы его видите — значит:
✅ SMTP-настройки в .env верны
✅ Порт {port} доступен
✅ Учётные данные работают
✅ Письма доходят до получателя

Далее система будет отправлять:
- Предупреждение за 7 дней до отключения (день 24)
- Финальное уведомление при отключении (день 31)

С уважением,
{from_name} <{from_addr}>
""".format(
    port=Config.SMTP_PORT,
    from_name=Config.EMAIL_FROM_NAME,
    from_addr=Config.EMAIL_FROM
)

print(f"📤 Отправляем тест на {TEST_TO}...")
if send_email(TEST_TO, subject, body):
    print("✅ Письмо отправлено успешно!")
    print("📬 Проверьте ящик (и папку «Спам», на всякий случай)")
else:
    print("❌ Ошибка отправки. Проверьте логи и настройки SMTP.")
    sys.exit(1)
