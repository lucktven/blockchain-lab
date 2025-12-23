# core/account.py
"""Клас Account для роботи з обліковими записами (ETAP 3)"""

from dataclasses import dataclass, field
from typing import List
from .hash import Hash
from .signature import KeyPair

@dataclass
class Account:
    """Клас для роботи з обліковим записом"""

    account_id: str
    wallet: List[KeyPair] = field(default_factory=list)
    balance: int = 0

    @staticmethod
    def genAccount() -> 'Account':
        """Створення нового облікового запису з генерованою ключовою парою"""
        keypair = KeyPair()
        account_id = Hash.toSHA256(keypair.getPublicKeyPEM())
        return Account(account_id=account_id, wallet=[keypair], balance=0)

    @staticmethod
    def createFromKeyPair(keypair: KeyPair) -> 'Account':
        """Створення облікового запису з існуючої ключової пари"""
        account_id = Hash.toSHA256(keypair.getPublicKeyPEM())
        return Account(account_id=account_id, wallet=[keypair], balance=0)

    def addKeyPairToWallet(self, keypair: KeyPair):
        """Додавання ключової пари до гаманця"""
        self.wallet.append(keypair)
        print(f"KeyPair added to wallet. Total keys: {len(self.wallet)}")

    def updateBalance(self, amount: int):
        """Оновлення балансу облікового запису"""
        self.balance += amount

    def getBalance(self) -> int:
        """Отримання поточного балансу"""
        return self.balance

    def printBalance(self):
        """Вивід балансу облікового запису"""
        print(f"Account {self.account_id[:10]}...: Balance = {self.balance}")

    def signData(self, data: str, key_index: int = 0) -> str:
        """
        Підпис даних ключем з гаманця

        Args:
            data: Дані для підпису
            key_index: Індекс ключа в гаманці (за замовчуванням 0)

        Returns:
            Підпис у форматі Base64
        """
        if key_index >= len(self.wallet):
            raise IndexError(f"Invalid key index: {key_index}. Wallet size: {len(self.wallet)}")

        private_key = self.wallet[key_index].getPrivateKey()
        from .signature import Signature
        return Signature.signData(private_key, data)

    def getPublicKeyPEM(self, key_index: int = 0) -> str:
        """Отримання публічного ключа у форматі PEM"""
        if key_index >= len(self.wallet):
            raise IndexError(f"Invalid key index: {key_index}")
        return self.wallet[key_index].getPublicKeyPEM()

    def printAccountInfo(self):
        """Вивід повної інформації про обліковий запис"""
        print(f"\n=== Account Information ===")
        print(f"Account ID: {self.account_id}")
        print(f"Balance: {self.balance}")
        print(f"Keys in wallet: {len(self.wallet)}")
        for i, keypair in enumerate(self.wallet):
            print(f"  Key #{i}: {keypair.getPublicKeyPEM()[:40]}...")

    def __str__(self) -> str:
        return f"Account(ID={self.account_id[:10]}..., balance={self.balance}, keys={len(self.wallet)})"