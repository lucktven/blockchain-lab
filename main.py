# main.py
"""Головний файл для запуску програми"""

import sys
import os

# Додаємо теку core до шляху пошуку модулів
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))


def main():
    """Головна функція програми"""
    print("=" * 60)
    print("ЛАБОРАТОРНА РОБОТА №3")
    print("Реалізація власного blockchain")
    print("=" * 60)

    print("\nОберіть режим роботи:")
    print("1. Запустити повну демонстрацію роботи блокчейну")
    print("2. Запустити тестування функціональності облікових записів")
    print("3. Запустити тести")
    print("4. Створити простий блокчейн для тестування")
    print("0. Вийти")

    try:
        choice = input("\nВаш вибір (0-4): ").strip()

        if choice == "1":
            from demo import demonstrate_blockchain
            demonstrate_blockchain()
        elif choice == "2":
            from demo import test_account_functionality
            test_account_functionality()
        elif choice == "3":
            print("Запуск тестів...")
            # Тут можна додати запуск тестів
            import unittest
            from tests.test_blockchain import TestBlockchain
            unittest.main(module='tests.test_blockchain', exit=False)
        elif choice == "4":
            create_simple_blockchain()
        elif choice == "0":
            print("До побачення!")
            sys.exit(0)
        else:
            print("Невірний вибір. Спробуйте ще раз.")

    except KeyboardInterrupt:
        print("\n\nПрограму перервано користувачем.")
    except Exception as e:
        print(f"\nСталася помилка: {e}")
        import traceback
        traceback.print_exc()


def create_simple_blockchain():
    """Створення простого блокчейну для тестування"""
    from core.blockchain import Blockchain
    from core.account import Account

    print("\nСтворення простого блокчейну...")

    # Створення блокчейну
    blockchain = Blockchain(name="TestChain")

    # Створення акаунтів
    account1 = Account.genAccount()
    account2 = Account.genAccount()

    # Поповнення з крана
    blockchain.getTokenFromFaucet(account1, 500)
    blockchain.getTokenFromFaucet(account2, 300)

    print(f"\nСтворено блокчейн: {blockchain}")
    print(f"Акаунт 1: {account1.account_id[:15]}..., баланс: {account1.getBalance()}")
    print(f"Акаунт 2: {account2.account_id[:15]}..., баланс: {account2.getBalance()}")

    # Показати стан
    blockchain.showCoinDatabase()
    blockchain.showBlockHistory()

    return blockchain


if __name__ == "__main__":
    main()