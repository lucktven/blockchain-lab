# core/block.py
"""Клас Block для роботи з блоками (ETAP 5)"""

import time
from dataclasses import dataclass, field
from typing import List
from .hash import Hash
from .operation import Transaction


@dataclass
class Block:
    """Клас блоку з транзакціями"""

    block_id: str
    prev_hash: str
    transactions: List[Transaction]
    timestamp: float
    nonce: int = 0  # Для спрощення, без PoW
    block_number: int = 0

    @staticmethod
    def createBlock(transactions: List[Transaction], prev_hash: str, block_number: int = 0) -> 'Block':
        """
        Створення нового блоку

        Args:
            transactions: Список транзакцій для включення в блок
            prev_hash: Хеш попереднього блоку
            block_number: Номер блоку в ланцюжку

        Returns:
            Об'єкт Block
        """
        # Формуємо дані для хешування
        block_data = prev_hash + str(block_number)

        for tx in transactions:
            block_data += tx.transaction_id

        block_data += str(time.time())
        block_id = Hash.toSHA256(block_data)

        return Block(
            block_id=block_id,
            prev_hash=prev_hash,
            transactions=transactions,
            timestamp=time.time(),
            block_number=block_number
        )

    def getBlockHeader(self) -> dict:
        """Повертає заголовок блоку у вигляді словника"""
        return {
            'block_id': self.block_id,
            'prev_hash': self.prev_hash,
            'timestamp': self.timestamp,
            'block_number': self.block_number,
            'transaction_count': len(self.transactions)
        }

    def calculateMerkleRoot(self) -> str:
        """
        Обчислює корінь дерева Меркла для транзакцій
        (спрощена реалізація)
        """
        if not self.transactions:
            return Hash.toSHA256("")

        tx_hashes = [tx.transaction_id for tx in self.transactions]

        # Простий спосіб обчислення кореня Меркла
        while len(tx_hashes) > 1:
            new_hashes = []
            for i in range(0, len(tx_hashes), 2):
                if i + 1 < len(tx_hashes):
                    combined = tx_hashes[i] + tx_hashes[i + 1]
                else:
                    combined = tx_hashes[i] + tx_hashes[i]
                new_hashes.append(Hash.toSHA256(combined))
            tx_hashes = new_hashes

        return tx_hashes[0] if tx_hashes else Hash.toSHA256("")

    def printBlockInfo(self):
        """Вивід інформації про блок"""
        print(f"\n=== Block #{self.block_number} ===")
        print(f"Block ID: {self.block_id}")
        print(f"Previous Hash: {self.prev_hash}")
        print(f"Timestamp: {time.ctime(self.timestamp)}")
        print(f"Transactions: {len(self.transactions)}")
        print(f"Merkle Root: {self.calculateMerkleRoot()[:15]}...")

        if self.transactions:
            print("Transactions in block:")
            for i, tx in enumerate(self.transactions):
                print(f"  TX #{i}: {tx.transaction_id[:15]}... ({len(tx.operations)} ops)")

    def __str__(self) -> str:
        return f"Block(#{self.block_number}, ID={self.block_id[:10]}..., prev={self.prev_hash[:10]}..., txs={len(self.transactions)})"