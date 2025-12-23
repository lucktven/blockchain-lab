# utils/helpers.py
"""Допоміжні функції для роботи з блокчейном"""

import time
from typing import List
from core.hash import Hash
from core.account import Account


def generate_document_hash(document_content: str) -> str:
    """
    Генерація хешу документу з контенту

    Args:
        document_content: Вміст документу

    Returns:
        Хеш документу
    """
    return Hash.toSHA256(document_content)


def create_test_accounts(count: int = 3) -> List[Account]:
    """
    Створення тестових облікових записів

    Args:
        count: Кількість облікових записів для створення

    Returns:
        Список облікових записів
    """
    accounts = []
    for i in range(count):
        account = Account.genAccount()
        accounts.append(account)
        print(f"Created account #{i}: {account.account_id[:15]}...")
    return accounts


def print_separator(title: str = ""):
    """Друкує роздільник з заголовком"""
    print("\n" + "=" * 60)
    if title:
        print(f" {title}")
        print("=" * 60)


def timestamp_to_readable(timestamp: float) -> str:
    """Конвертує timestamp у читабельний формат"""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))


def calculate_total_coins(blockchain) -> int:
    """Обчислює загальну кількість монет у системі"""
    total_in_circulation = sum(blockchain.coin_database.values())
    total_in_faucet = blockchain.faucet_coins
    return total_in_circulation + total_in_faucet