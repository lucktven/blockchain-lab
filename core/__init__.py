# core/__init__.py
"""Пакет основних класів блокчейну"""

# Імпортуємо всі основні класи для зручного доступу
from .hash import Hash
from .signature import KeyPair, Signature
from .account import Account
from .operation import Operation, Transaction
from .block import Block
from .blockchain import Blockchain

__all__ = [
    'Hash',
    'KeyPair',
    'Signature',
    'Account',
    'Operation',
    'Transaction',
    'Block',
    'Blockchain'
]