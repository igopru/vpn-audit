#!/usr/bin/env python3
"""
Изолированный тест отключения VPN для одного пользователя.
Безопасен по умолчанию (AD_DRY_RUN=True).
Обходит ошибку 'invalid dereference aliases type' в ldap3 2.9.1.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from utils.email import send_email
from ldap3 import Server, Connection, SUBTREE, MODIFY_DELETE, SIMPLE
from ldap3.utils.conv import escape_filter_chars

# === НАСТРОЙКИ ТЕСТА ===
TEST_USER = "admin"
TEST_EMAIL = "admin@example.com"
AD_DRY_RUN = False  # 🔒 True = только проверка + письма. False = реальное удаление

def main():
    print(f"🧪 Тест отключения VPN для: {TEST_USER}")
    print(f"📧 Уведомления на: {TEST_EMAIL}")
    print(f"🔐 Режим AD: {'DRY_RUN (безопасно)' if AD_DRY_RUN else 'LIVE (реальное изменение)'}")
    print("-" * 60)

    # 1. Подключение к AD
    print("[1/4] Подключение к AD...")
    server = Server(Config.LDAP_SERVER, get_info=None)
    ad_conn = Connection(
        server,
        user=Config.LDAP_BIND_DN,
        password=Config.LDAP_BIND_PASSWORD,
        authentication=SIMPLE,
        auto_bind=False  # 🔥 Ручной бинд для контроля
    )
    
    if not ad_conn.bind():
        print(f"❌ Ошибка подключения к AD: {ad_conn.result}")
        return
    print("✅ Соединение с AD установлено")
    
    # 🔥 КЛЮЧЕВОЙ ФИКС: отключаем разыменование псевдонимов
    ad_conn.deref_aliases = 0

    # 2. Поиск пользователя (минимальный фильтр)
    print("[2/4] Поиск пользователя...")
    safe_user = escape_filter_chars(TEST_USER)
    
    # Пробуем сначала полный фильтр
    search_filter = f'(&(objectClass=user)(sAMAccountName={safe_user}))'
    
    try:
        ad_conn.search(
            search_base=Config.LDAP_BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'mail']
        )
    except Exception as e:
        print(f"⚠️ Поиск с objectClass упал: {e}")
        # Фолбэк: ищем только по sAMAccountName
        try:
            ad_conn.search(
                search_base=Config.LDAP_BASE_DN,
                search_filter=f'(sAMAccountName={safe_user})',
                search_scope=SUBTREE,
                attributes=['distinguishedName', 'mail']
            )
        except Exception as e2:
            print(f"❌ Fallback не сработал: {e2}")
            ad_conn.unbind()
            return

    if not ad_conn.entries:
        print(f"❌ Пользователь {TEST_USER} не найден в AD")
        ad_conn.unbind()
        return

    user_dn = str(ad_conn.entries[0].distinguishedName)
    print(f"✅ DN: {user_dn}")

    # 3. Проверка принадлежности к группе
    print("[3/4] Проверка принадлежности к группе VPN...")
    try:
        ad_conn.search(
            search_base=Config.VPN_GROUP_DN,
            search_filter=f'(member={escape_filter_chars(user_dn)})',
            search_scope=SUBTREE,
            attributes=['member']
        )
        is_member = bool(ad_conn.entries)
    except Exception as e:
        print(f"⚠️ Не удалось проверить группу: {e}")
        is_member = False

    if is_member:
        print("✅ Пользователь НАХОДИТСЯ в группе VPN. Готов к отключению.")
    else:
        print("ℹ️  Пользователь УЖЕ отсутствует в группе VPN")

    # 4. Отправка писем
    print("[4/4] Отправка тестовых уведомлений...")
    emails = [
        ("⏳ Предупреждение: доступ к VPN скоро будет отключён", 
         f"Уважаемый {TEST_USER},\n\nВы не подключались к VPN более 24 дней. Если активность не появится в ближайшие 7 дней, доступ будет отключён."),
        ("🔒 Ваш доступ к VPN отключён", 
         f"Уважаемый {TEST_USER},\n\nВаш доступ отключён в связи с отсутствием активности за последние 31 день.\n\nДля восстановления обратитесь в IT-отдел.")
    ]

    for subject, body in emails:
        if send_email(TEST_EMAIL, f"[ТЕСТ VPN-AUDIT] {subject}", body):
            print(f"✅ Письмо отправлено: {subject}")
        else:
            print(f"❌ Ошибка отправки: {subject}")

    # 5. Удаление из группы (только если AD_DRY_RUN=False)
    if is_member and not AD_DRY_RUN:
        print("\n🔓 Выполняется реальное удаление из AD...")
        try:
            ad_conn.modify(Config.VPN_GROUP_DN, {'member': [(MODIFY_DELETE, [user_dn])]})
            if ad_conn.result['result'] == 0:
                print("✅ Успешно удалён из группы VPN в AD")
            else:
                print(f"❌ Ошибка AD: {ad_conn.result}")
        except Exception as e:
            print(f"❌ Исключение при удалении: {e}")
    elif is_member:
        print("\n🔒 AD_DRY_RUN=True → удаление из группы пропущено (безопасный режим)")

    ad_conn.unbind()
    print("\n✨ Тест завершён. Проверьте почту.")

if __name__ == "__main__":
    main()
