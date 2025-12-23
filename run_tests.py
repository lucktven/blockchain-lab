# run_tests.py
"""Скрипт для запуску всіх тестів"""

import sys
import os

# Додаємо батьківську директорію до шляху
sys.path.insert(0, os.path.abspath('.'))

if __name__ == '__main__':
    print("Запуск тестів для блокчейну...")
    print("=" * 60)

    # Запускаємо тести
    from tests.test_blockchain import run_tests

    success = run_tests()

    if success:
        print("\n✅ Всі тести пройдено успішно!")
    else:
        print("\n❌ Деякі тести не пройдено!")

    sys.exit(0 if success else 1)