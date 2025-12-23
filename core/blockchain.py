# core/blockchain.py
"""Клас Blockchain - головний клас ланцюжка блоків (ETAP 5)"""

import time
from typing import Dict, List, Optional
from .block import Block
from .operation import Transaction, Operation
from .account import Account
from .hash import Hash


class Blockchain:
    """Головний клас блокчейну"""

    def __init__(self, name: str = "MyBlockchain"):
        self.name = name
        self.coin_database: Dict[str, int] = {}  # account_id -> balance
        self.block_history: List[Block] = []
        self.tx_database: Dict[str, Transaction] = {}  # tx_id -> Transaction
        self.faucet_coins: int = 1000000  # Початкові монети для тестування

        # Ініціалізація блокчейну з генезис-блоком
        self.initBlockchain()

    def initBlockchain(self) -> None:
        """Ініціалізація блокчейну з генезис-блоком"""
        genesis_block = Block.createBlock([], "0" * 64, 0)
        self.block_history.append(genesis_block)
        print(f"[{self.name}] Genesis block created: {genesis_block.block_id[:15]}...")

    def getTokenFromFaucet(self, account: Account, amount: int) -> bool:
        """
        Отримання тестових монет з крана

        Args:
            account: Обліковий запис для поповнення
            amount: Сума для отримання

        Returns:
            True якщо успішно, False - якщо ні
        """
        if amount <= 0:
            print(f"[{self.name}] Invalid amount: {amount}")
            return False

        if amount > self.faucet_coins:
            print(f"[{self.name}] Not enough coins in faucet. Available: {self.faucet_coins}, Requested: {amount}")
            return False

        self.faucet_coins -= amount

        # Оновлюємо баланс в базі даних
        if account.account_id in self.coin_database:
            self.coin_database[account.account_id] += amount
        else:
            self.coin_database[account.account_id] = amount

        # Оновлюємо баланс в об'єкті акаунта
        account.updateBalance(amount)

        print(f"[{self.name}] Account {account.account_id[:10]}... received {amount} coins from faucet")
        return True

    def validateBlock(self, block: Block) -> bool:
        """
        Валідація та додавання блоку до ланцюжка

        Args:
            block: Блок для валідації

        Returns:
            True якщо блок валідний та доданий, False - якщо ні
        """
        print(f"\n[{self.name}] Validating block #{block.block_number}...")

        # 1. Перевірка посилання на попередній блок
        last_block = self.block_history[-1]
        if block.prev_hash != last_block.block_id:
            print(
                f"[{self.name}] Invalid previous hash. Expected: {last_block.block_id[:10]}..., Got: {block.prev_hash[:10]}...")
            return False

        # 2. Перевірка унікальності транзакцій
        for tx in block.transactions:
            if tx.transaction_id in self.tx_database:
                print(f"[{self.name}] Transaction {tx.transaction_id[:10]}... already exists")
                return False

        # 3. Перевірка операцій в транзакціях
        temp_balances = self.coin_database.copy()

        for tx in block.transactions:
            if not tx.verifyTransaction(temp_balances):
                print(f"[{self.name}] Transaction verification failed: {tx.transaction_id[:10]}...")
                return False

            # Оновлюємо тимчасові баланси
            for op in tx.operations:
                sender_id = op.sender.account_id
                receiver_id = op.receiver.account_id

                # Зменшуємо баланс відправника
                temp_balances[sender_id] = temp_balances.get(sender_id, 0) - op.amount

                # Збільшуємо баланс отримувача
                temp_balances[receiver_id] = temp_balances.get(receiver_id, 0) + op.amount

        # Якщо всі перевірки пройдено, додаємо блок
        self.block_history.append(block)

        # Оновлюємо бази даних
        for tx in block.transactions:
            self.tx_database[tx.transaction_id] = tx

        # Оновлюємо фактичні баланси
        self.coin_database = temp_balances

        print(f"[{self.name}] Block {block.block_id[:10]}... validated and added to chain")
        return True

    def showCoinDatabase(self):
        """Відображення поточних балансів"""
        print(f"\n[{self.name}] === Coin Database ===")
        print(f"Total accounts: {len(self.coin_database)}")

        if not self.coin_database:
            print("No accounts in database")
            return

        for account_id, balance in self.coin_database.items():
            print(f"  {account_id[:15]}...: {balance} coins")

        print(f"Faucet remaining: {self.faucet_coins} coins")
        print(f"Total coins in circulation: {sum(self.coin_database.values())}")

    def showBlockHistory(self):
        """Відображення історії блоків"""
        print(f"\n[{self.name}] === Block History ===")
        print(f"Total blocks: {len(self.block_history)}")

        for i, block in enumerate(self.block_history):
            print(f"Block #{i}: {block}")

    def verifyDocument(self, document_hash: str) -> Optional[str]:
        """
        Перевірка наявності документу в блокчейні

        Args:
            document_hash: Хеш документу для пошуку

        Returns:
            Інформація про документ або None якщо не знайдено
        """
        print(f"[{self.name}] Searching for document: {document_hash[:15]}...")

        for block in self.block_history:
            for tx in block.transactions:
                for op in tx.operations:
                    if op.document_hash == document_hash:
                        result = f"""
Document found!
- Block: #{block.block_number} ({block.block_id[:15]}...)
- Transaction: {tx.transaction_id[:15]}...
- Timestamp: {time.ctime(block.timestamp)}
- Sender: {op.sender.account_id[:10]}...
- Receiver: {op.receiver.account_id[:10]}...
                        """
                        return result

        print(f"[{self.name}] Document not found in blockchain")
        return None

    def checkBlockchainIntegrity(self) -> bool:
        """
        Перевірка цілісності всього ланцюжка блоків

        Returns:
            True якщо ланцюжок цілісний, False - якщо є проблеми
        """
        print(f"\n[{self.name}] Checking blockchain integrity...")

        if len(self.block_history) < 1:
            print("Blockchain is empty")
            return False

        # Перевіряємо генезис-блок
        genesis = self.block_history[0]
        if genesis.prev_hash != "0" * 64:
            print("Genesis block has invalid previous hash")
            return False

        # Перевіряємо всі наступні блоки
        for i in range(1, len(self.block_history)):
            current_block = self.block_history[i]
            previous_block = self.block_history[i - 1]

            if current_block.prev_hash != previous_block.block_id:
                print(f"Integrity check failed at block #{i}")
                print(f"  Expected prev_hash: {previous_block.block_id[:15]}...")
                print(f"  Actual prev_hash: {current_block.prev_hash[:15]}...")
                return False

        print(f"Blockchain integrity check passed! {len(self.block_history)} blocks are valid.")
        return True

    def getAccountBalance(self, account_id: str) -> int:
        """Отримання балансу облікового запису"""
        return self.coin_database.get(account_id, 0)

    def getBlockCount(self) -> int:
        """Отримання кількості блоків у ланцюжку"""
        return len(self.block_history)

    def getTransactionCount(self) -> int:
        """Отримання кількості транзакцій у ланцюжку"""
        return len(self.tx_database)

    def __str__(self) -> str:
        return f"Blockchain(name={self.name}, blocks={len(self.block_history)}, accounts={len(self.coin_database)}, txs={len(self.tx_database)})"