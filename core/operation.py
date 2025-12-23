# core/operation.py
"""Класи Operation та Transaction (ETAP 4)"""

import time
from dataclasses import dataclass, field
from typing import List, Optional
from .hash import Hash
from .account import Account
from .signature import Signature


@dataclass
class Operation:
    """Клас для операції платежу або реєстрації документу"""

    operation_id: str
    sender: Account
    receiver: Account
    amount: int
    document_hash: str = ""  # Хеш документу для реєстрації
    signature: str = ""
    timestamp: float = field(default_factory=time.time)

    @staticmethod
    def createOperation(sender: Account, receiver: Account,
                        amount: int, document_hash: str = "",
                        key_index: int = 0) -> 'Operation':
        """
        Створення операції з підписом

        Args:
            sender: Обліковий запис відправника
            receiver: Обліковий запис отримувача
            amount: Сума передачі
            document_hash: Хеш документу для реєстрації (опціонально)
            key_index: Індекс ключа для підпису

        Returns:
            Об'єкт Operation
        """
        # Створюємо дані для підпису
        op_data = f"{sender.account_id}{receiver.account_id}{amount}{document_hash}{time.time()}"

        # Генеруємо підпис
        signature = sender.signData(op_data, key_index)

        # Генеруємо ID операції
        operation_id = Hash.toSHA256(op_data + signature)

        return Operation(
            operation_id=operation_id,
            sender=sender,
            receiver=receiver,
            amount=amount,
            document_hash=document_hash,
            signature=signature,
            timestamp=time.time()
        )

    def verifyOperation(self, sender_balance: int) -> bool:
        """
        Перевірка операції

        Args:
            sender_balance: Поточний баланс відправника

        Returns:
            True якщо операція валідна, False - якщо ні
        """
        # 1. Перевірка балансу
        if self.amount > sender_balance:
            print(f"Operation verification failed: Insufficient balance ({sender_balance} < {self.amount})")
            return False

        # 2. Перевірка підпису
        op_data = f"{self.sender.account_id}{self.receiver.account_id}{self.amount}{self.document_hash}{self.timestamp}"

        # Перевіряємо підпис за допомогою публічного ключа
        for keypair in self.sender.wallet:
            public_key = keypair.getPublicKey()
            if Signature.verifySignature(public_key, op_data, self.signature):
                return True

        print("Operation verification failed: Invalid signature")
        return False

    def getOperationData(self) -> str:
        """Повертає строкове представлення даних операції"""
        doc_info = f", Document: {self.document_hash[:10]}..." if self.document_hash else ""
        return f"From: {self.sender.account_id[:8]}... To: {self.receiver.account_id[:8]}..., Amount: {self.amount}{doc_info}"

    def __str__(self) -> str:
        doc_info = f", doc={self.document_hash[:10]}..." if self.document_hash else ""
        return f"Operation(ID={self.operation_id[:8]}..., {self.sender.account_id[:6]}... → {self.receiver.account_id[:6]}..., amount={self.amount}{doc_info})"


@dataclass
class Transaction:
    """Клас транзакції з набором операцій"""

    transaction_id: str
    operations: List[Operation]
    nonce: int
    timestamp: float

    @staticmethod
    def createTransaction(operations: List[Operation], nonce: int) -> 'Transaction':
        """
        Створення транзакції з набором операцій

        Args:
            operations: Список операцій
            nonce: Унікальне значення для захисту від дублювання

        Returns:
            Об'єкт Transaction
        """
        # Формуємо дані для хешування
        tx_data = ""
        for op in operations:
            tx_data += op.operation_id + str(op.amount) + op.document_hash

        tx_data += str(nonce) + str(time.time())
        transaction_id = Hash.toSHA256(tx_data)

        return Transaction(
            transaction_id=transaction_id,
            operations=operations,
            nonce=nonce,
            timestamp=time.time()
        )

    def verifyTransaction(self, balances: dict) -> bool:
        """
        Перевірка всіх операцій в транзакції

        Args:
            balances: Словник з балансами облікових записів

        Returns:
            True якщо всі операції валідні
        """
        for op in self.operations:
            sender_id = op.sender.account_id
            sender_balance = balances.get(sender_id, 0)

            if not op.verifyOperation(sender_balance):
                return False

        return True

    def getOperationsInfo(self) -> str:
        """Повертає інформацію про операції в транзакції"""
        info = f"Transaction {self.transaction_id[:10]}...:\n"
        for i, op in enumerate(self.operations):
            info += f"  Op #{i}: {op.getOperationData()}\n"
        return info

    def __str__(self) -> str:
        return f"Transaction(ID={self.transaction_id[:10]}..., ops={len(self.operations)}, nonce={self.nonce})"