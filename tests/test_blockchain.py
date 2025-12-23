# tests/test_blockchain.py
"""Тести для перевірки роботи блокчейну"""

import unittest
import sys
import os

# Додаємо батьківську директорію до шляху пошуку модулів
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core import Hash, KeyPair, Signature, Account, Operation, Transaction, Block, Blockchain


class TestHash(unittest.TestCase):
    """Тести для класу Hash"""

    def test_sha256_consistency(self):
        """Тест консистентності SHA-256 хешування"""
        # Однакові дані мають давати однаковий хеш
        data = "test data"
        hash1 = Hash.toSHA256(data)
        hash2 = Hash.toSHA256(data)
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 дає 64 hex символи

    def test_sha256_different_inputs(self):
        """Тест, що різні вхідні дані дають різні хеші"""
        hash1 = Hash.toSHA256("data1")
        hash2 = Hash.toSHA256("data2")
        self.assertNotEqual(hash1, hash2)

    def test_sha1(self):
        """Тест SHA-1 хешування"""
        result = Hash.toSHA1("test")
        expected = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        self.assertEqual(result, expected)
        self.assertEqual(len(result), 40)  # SHA-1 дає 40 hex символів


class TestKeyPair(unittest.TestCase):
    """Тести для класу KeyPair"""

    def test_key_generation(self):
        """Тест генерації ключової пари"""
        keypair = KeyPair()

        # Перевірка, що ключі створені
        self.assertIsNotNone(keypair.getPrivateKey())
        self.assertIsNotNone(keypair.getPublicKey())

        # Перевірка формату PEM
        pem = keypair.getPublicKeyPEM()
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(pem.endswith("-----END PUBLIC KEY-----\n"))

        # Перевірка розміру ключа
        self.assertEqual(keypair.getPrivateKey().size_in_bits(), 2048)

    def test_key_pair_uniqueness(self):
        """Тест, що кожна нова пара ключів унікальна"""
        keypair1 = KeyPair()
        keypair2 = KeyPair()

        # Публічні ключі мають бути різними
        self.assertNotEqual(
            keypair1.getPublicKeyPEM(),
            keypair2.getPublicKeyPEM()
        )


class TestSignature(unittest.TestCase):
    """Тести для класу Signature"""

    def setUp(self):
        """Налаштування перед кожним тестом"""
        self.keypair = KeyPair()
        self.data = "Важливе повідомлення для підпису"

    def test_sign_and_verify(self):
        """Тест підпису та успішної верифікації"""
        # Підпис
        signature = Signature.signData(self.keypair.getPrivateKey(), self.data)
        self.assertTrue(len(signature) > 0)

        # Верифікація
        is_valid = Signature.verifySignature(
            self.keypair.getPublicKey(),
            self.data,
            signature
        )
        self.assertTrue(is_valid, "Підпис має бути валідним")

    def test_verify_wrong_data(self):
        """Тест верифікації з неправильними даними"""
        signature = Signature.signData(self.keypair.getPrivateKey(), self.data)

        # Спроба верифікації з іншими даними
        is_valid = Signature.verifySignature(
            self.keypair.getPublicKey(),
            "інші дані",
            signature
        )
        self.assertFalse(is_valid, "Підпис не має бути валідним для інших даних")

    def test_verify_wrong_signature(self):
        """Тест верифікації з неправильним підписом"""
        # Створюємо випадковий підпис
        wrong_signature = "invalid_signature_base64_encoded=="

        is_valid = Signature.verifySignature(
            self.keypair.getPublicKey(),
            self.data,
            wrong_signature
        )
        self.assertFalse(is_valid)


class TestAccount(unittest.TestCase):
    """Тести для класу Account"""

    def test_account_creation(self):
        """Тест створення облікового запису"""
        account = Account.genAccount()

        # Перевірка основних полів
        self.assertIsNotNone(account.account_id)
        self.assertEqual(len(account.account_id), 64)  # SHA-256 дає 64 символи
        self.assertEqual(account.balance, 0)
        self.assertEqual(len(account.wallet), 1)

        # Перевірка, що account_id - це хеш публічного ключа
        public_key_pem = account.wallet[0].getPublicKeyPEM()
        expected_id = Hash.toSHA256(public_key_pem)
        self.assertEqual(account.account_id, expected_id)

    def test_account_from_keypair(self):
        """Тест створення акаунта з існуючої ключової пари"""
        keypair = KeyPair()
        account = Account.createFromKeyPair(keypair)

        self.assertEqual(len(account.wallet), 1)
        self.assertEqual(account.wallet[0], keypair)

    def test_balance_operations(self):
        """Тест операцій з балансом"""
        account = Account.genAccount()

        # Додавання балансу
        account.updateBalance(100)
        self.assertEqual(account.getBalance(), 100)

        # Віднімання балансу
        account.updateBalance(-30)
        self.assertEqual(account.getBalance(), 70)

        # Додавання від'ємного значення
        account.updateBalance(-100)
        self.assertEqual(account.getBalance(), -30)  # Дозволяємо негативний баланс для тесту

    def test_add_keypair_to_wallet(self):
        """Тест додавання ключової пари до гаманця"""
        account = Account.genAccount()
        initial_keys = len(account.wallet)

        # Додаємо нову ключову пару
        new_keypair = KeyPair()
        account.addKeyPairToWallet(new_keypair)

        self.assertEqual(len(account.wallet), initial_keys + 1)
        self.assertEqual(account.wallet[-1], new_keypair)

    def test_sign_data(self):
        """Тест підпису даних акаунтом"""
        account = Account.genAccount()
        data = "Дані для підпису"

        signature = account.signData(data, 0)
        self.assertTrue(len(signature) > 0)

        # Перевірка підпису
        public_key = account.wallet[0].getPublicKey()
        is_valid = Signature.verifySignature(public_key, data, signature)
        self.assertTrue(is_valid)

    def test_sign_data_invalid_index(self):
        """Тест підпису даних з невірним індексом ключа"""
        account = Account.genAccount()

        with self.assertRaises(IndexError):
            account.signData("test", 10)  # Неіснуючий індекс


class TestOperation(unittest.TestCase):
    """Тести для класу Operation"""

    def setUp(self):
        """Налаштування перед кожним тестом"""
        self.sender = Account.genAccount()
        self.receiver = Account.genAccount()
        self.sender.updateBalance(1000)  # Даємо відправнику кошти

    def test_operation_creation(self):
        """Тест створення операції"""
        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=100,
            document_hash="doc_hash_123",
            key_index=0
        )

        # Перевірка основних полів
        self.assertIsNotNone(operation.operation_id)
        self.assertEqual(operation.sender, self.sender)
        self.assertEqual(operation.receiver, self.receiver)
        self.assertEqual(operation.amount, 100)
        self.assertEqual(operation.document_hash, "doc_hash_123")
        self.assertTrue(len(operation.signature) > 0)

    def test_operation_verification_success(self):
        """Тест успішної верифікації операції"""
        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=100,
            key_index=0
        )

        # Верифікація з достатнім балансом
        is_valid = operation.verifyOperation(200)  # Баланс більший за суму
        self.assertTrue(is_valid)

    def test_operation_verification_insufficient_balance(self):
        """Тест верифікації операції з недостатнім балансом"""
        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=500,
            key_index=0
        )

        # Верифікація з недостатнім балансом
        is_valid = operation.verifyOperation(200)  # Баланс менший за суму
        self.assertFalse(is_valid)

    def test_operation_verification_tampered_data(self):
        """Тест верифікації операції зі зміненими даними"""
        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=100,
            key_index=0
        )

        # Змінюємо отримувача після створення (симулюємо маніпуляцію)
        original_receiver = operation.receiver
        new_account = Account.genAccount()
        operation.receiver = new_account

        # Верифікація має провалитись, бо дані змінені
        is_valid = operation.verifyOperation(200)
        self.assertFalse(is_valid)

        # Повертаємо оригінального отримувача
        operation.receiver = original_receiver


class TestTransaction(unittest.TestCase):
    """Тести для класу Transaction"""

    def setUp(self):
        """Налаштування перед кожним тестом"""
        self.sender = Account.genAccount()
        self.receiver = Account.genAccount()
        self.sender.updateBalance(1000)

    def test_transaction_creation(self):
        """Тест створення транзакції"""
        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=100,
            key_index=0
        )

        transaction = Transaction.createTransaction([operation], nonce=1)

        # Перевірка основних полів
        self.assertIsNotNone(transaction.transaction_id)
        self.assertEqual(len(transaction.operations), 1)
        self.assertEqual(transaction.operations[0], operation)
        self.assertEqual(transaction.nonce, 1)
        self.assertTrue(transaction.timestamp > 0)

    def test_transaction_with_multiple_operations(self):
        """Тест транзакції з кількома операціями"""
        operations = []
        for i in range(3):
            operation = Operation.createOperation(
                sender=self.sender,
                receiver=self.receiver,
                amount=10 * (i + 1),
                key_index=0
            )
            operations.append(operation)

        transaction = Transaction.createTransaction(operations, nonce=2)

        self.assertEqual(len(transaction.operations), 3)
        self.assertEqual(transaction.operations[1].amount, 20)

    def test_transaction_verification(self):
        """Тест верифікації транзакції"""
        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=100,
            key_index=0
        )

        transaction = Transaction.createTransaction([operation], nonce=1)

        # Створюємо баланси для перевірки
        balances = {self.sender.account_id: 200}

        is_valid = transaction.verifyTransaction(balances)
        self.assertTrue(is_valid)

    def test_transaction_verification_fail(self):
        """Тест невдалої верифікації транзакції"""
        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=300,  # Більше ніж баланс
            key_index=0
        )

        transaction = Transaction.createTransaction([operation], nonce=1)

        # Баланс менший за суму операції
        balances = {self.sender.account_id: 200}

        is_valid = transaction.verifyTransaction(balances)
        self.assertFalse(is_valid)


class TestBlock(unittest.TestCase):
    """Тести для класу Block"""

    def setUp(self):
        """Налаштування перед кожним тестом"""
        self.sender = Account.genAccount()
        self.receiver = Account.genAccount()

        operation = Operation.createOperation(
            sender=self.sender,
            receiver=self.receiver,
            amount=100,
            key_index=0
        )

        self.transaction = Transaction.createTransaction([operation], nonce=1)

    def test_block_creation(self):
        """Тест створення блоку"""
        prev_hash = "0" * 64  # Генезис хеш
        block = Block.createBlock([self.transaction], prev_hash, block_number=1)

        # Перевірка основних полів
        self.assertIsNotNone(block.block_id)
        self.assertEqual(block.prev_hash, prev_hash)
        self.assertEqual(len(block.transactions), 1)
        self.assertEqual(block.transactions[0], self.transaction)
        self.assertEqual(block.block_number, 1)
        self.assertTrue(block.timestamp > 0)

    def test_block_header(self):
        """Тест отримання заголовка блоку"""
        block = Block.createBlock([self.transaction], "prev_hash_123", block_number=5)

        header = block.getBlockHeader()

        self.assertEqual(header['block_id'], block.block_id)
        self.assertEqual(header['prev_hash'], block.prev_hash)
        self.assertEqual(header['block_number'], 5)
        self.assertEqual(header['transaction_count'], 1)

    def test_merkle_root_empty(self):
        """Тест обчислення кореня Меркла для порожнього блоку"""
        block = Block.createBlock([], "prev_hash", block_number=1)
        merkle_root = block.calculateMerkleRoot()

        # Для порожнього блоку має бути хеш порожнього рядка
        expected = Hash.toSHA256("")
        self.assertEqual(merkle_root, expected)

    def test_merkle_root_single_transaction(self):
        """Тест обчислення кореня Меркла для блоку з однією транзакцією"""
        block = Block.createBlock([self.transaction], "prev_hash", block_number=1)
        merkle_root = block.calculateMerkleRoot()

        # Для однієї транзакції корінь Меркла має бути хешем від хешу транзакції з самим собою
        tx_hash = self.transaction.transaction_id
        combined = tx_hash + tx_hash
        expected = Hash.toSHA256(combined)

        self.assertEqual(merkle_root, expected)


class TestBlockchain(unittest.TestCase):
    """Тести для класу Blockchain"""

    def setUp(self):
        """Налаштування перед кожним тестом"""
        self.blockchain = Blockchain("TestChain")
        self.account1 = Account.genAccount()
        self.account2 = Account.genAccount()

    def test_initialization(self):
        """Тест ініціалізації блокчейну"""
        # Перевірка генезис-блоку
        self.assertEqual(len(self.blockchain.block_history), 1)

        genesis_block = self.blockchain.block_history[0]
        self.assertEqual(genesis_block.block_number, 0)
        self.assertEqual(genesis_block.prev_hash, "0" * 64)
        self.assertEqual(len(genesis_block.transactions), 0)

        # Перевірка початкових значень
        self.assertEqual(self.blockchain.faucet_coins, 1000000)
        self.assertEqual(len(self.blockchain.coin_database), 0)
        self.assertEqual(len(self.blockchain.tx_database), 0)

    def test_faucet_success(self):
        """Тест успішного отримання монет з крана"""
        initial_faucet = self.blockchain.faucet_coins
        amount = 500

        success = self.blockchain.getTokenFromFaucet(self.account1, amount)

        self.assertTrue(success)
        self.assertEqual(self.blockchain.faucet_coins, initial_faucet - amount)
        self.assertEqual(
            self.blockchain.getAccountBalance(self.account1.account_id),
            amount
        )
        self.assertEqual(self.account1.getBalance(), amount)

    def test_faucet_insufficient_funds(self):
        """Тест спроби отримати більше монет ніж є в крані"""
        # Спробуємо отримати більше, ніж є в крані
        too_much = self.blockchain.faucet_coins + 1000
        success = self.blockchain.getTokenFromFaucet(self.account1, too_much)

        self.assertFalse(success)
        self.assertEqual(self.blockchain.getAccountBalance(self.account1.account_id), 0)

    def test_faucet_invalid_amount(self):
        """Тест спроби отримати від'ємну кількість монет"""
        success = self.blockchain.getTokenFromFaucet(self.account1, -100)
        self.assertFalse(success)

    def test_validate_block_success(self):
        """Тест успішної валідації блоку"""
        # Даємо кошти акаунтам
        self.blockchain.getTokenFromFaucet(self.account1, 1000)
        self.blockchain.getTokenFromFaucet(self.account2, 500)

        # Створюємо операцію
        operation = Operation.createOperation(
            sender=self.account1,
            receiver=self.account2,
            amount=200,
            key_index=0
        )

        # Створюємо транзакцію та блок
        transaction = Transaction.createTransaction([operation], nonce=1)
        prev_hash = self.blockchain.block_history[-1].block_id
        block = Block.createBlock([transaction], prev_hash, block_number=1)

        # Валідуємо блок
        is_valid = self.blockchain.validateBlock(block)
        self.assertTrue(is_valid)

        # Перевірка, що блок додано
        self.assertEqual(len(self.blockchain.block_history), 2)
        self.assertEqual(len(self.blockchain.tx_database), 1)

        # Перевірка оновлених балансів
        self.assertEqual(
            self.blockchain.getAccountBalance(self.account1.account_id),
            800  # 1000 - 200
        )
        self.assertEqual(
            self.blockchain.getAccountBalance(self.account2.account_id),
            700  # 500 + 200
        )

    def test_validate_block_wrong_prev_hash(self):
        """Тест валідації блоку з неправильним попереднім хешем"""
        operation = Operation.createOperation(
            sender=self.account1,
            receiver=self.account2,
            amount=100,
            key_index=0
        )

        transaction = Transaction.createTransaction([operation], nonce=1)
        wrong_prev_hash = "wrong_prev_hash_1234567890"
        block = Block.createBlock([transaction], wrong_prev_hash, block_number=1)

        is_valid = self.blockchain.validateBlock(block)
        self.assertFalse(is_valid)
        self.assertEqual(len(self.blockchain.block_history), 1)  # Тільки генезис

    def test_validate_block_duplicate_transaction(self):
        """Тест валідації блоку з дубльованою транзакцією"""
        # Даємо кошти
        self.blockchain.getTokenFromFaucet(self.account1, 1000)

        # Створюємо та валідуємо перший блок
        operation = Operation.createOperation(
            sender=self.account1,
            receiver=self.account2,
            amount=100,
            key_index=0
        )

        transaction = Transaction.createTransaction([operation], nonce=1)
        prev_hash = self.blockchain.block_history[-1].block_id
        block1 = Block.createBlock([transaction], prev_hash, block_number=1)

        self.blockchain.validateBlock(block1)

        # Спробуємо додати блок з тією ж транзакцією
        block2 = Block.createBlock([transaction], block1.block_id, block_number=2)
        is_valid = self.blockchain.validateBlock(block2)

        self.assertFalse(is_valid)
        self.assertEqual(len(self.blockchain.block_history), 2)  # Тільки генезис + block1

    def test_validate_block_insufficient_balance(self):
        """Тест валідації блоку з операцією, що перевищує баланс"""
        # Даємо мало коштів
        self.blockchain.getTokenFromFaucet(self.account1, 50)

        # Спробуємо переказати більше, ніж є
        operation = Operation.createOperation(
            sender=self.account1,
            receiver=self.account2,
            amount=100,  # Більше ніж 50
            key_index=0
        )

        transaction = Transaction.createTransaction([operation], nonce=1)
        prev_hash = self.blockchain.block_history[-1].block_id
        block = Block.createBlock([transaction], prev_hash, block_number=1)

        is_valid = self.blockchain.validateBlock(block)
        self.assertFalse(is_valid)

    def test_check_blockchain_integrity(self):
        """Тест перевірки цілісності блокчейну"""
        # Пустий блокчейн (тільки генезис)
        is_valid = self.blockchain.checkBlockchainIntegrity()
        self.assertTrue(is_valid)

        # Додаємо кілька блоків
        self.blockchain.getTokenFromFaucet(self.account1, 1000)

        for i in range(3):
            operation = Operation.createOperation(
                sender=self.account1,
                receiver=self.account2,
                amount=100,
                key_index=0
            )

            transaction = Transaction.createTransaction([operation], nonce=i + 1)
            prev_hash = self.blockchain.block_history[-1].block_id
            block = Block.createBlock([transaction], prev_hash, block_number=i + 1)

            self.blockchain.validateBlock(block)

        # Перевірка цілісності після додавання блоків
        is_valid = self.blockchain.checkBlockchainIntegrity()
        self.assertTrue(is_valid)
        self.assertEqual(len(self.blockchain.block_history), 4)  # Генезис + 3 блоки

    def test_verify_document_found(self):
        """Тест пошуку документу, який є в блокчейні"""
        # Даємо кошти
        self.blockchain.getTokenFromFaucet(self.account1, 1000)

        # Реєструємо документ
        doc_hash = Hash.toSHA256("Тестовий документ")
        operation = Operation.createOperation(
            sender=self.account1,
            receiver=self.account2,
            amount=100,
            document_hash=doc_hash,
            key_index=0
        )

        transaction = Transaction.createTransaction([operation], nonce=1)
        prev_hash = self.blockchain.block_history[-1].block_id
        block = Block.createBlock([transaction], prev_hash, block_number=1)

        self.blockchain.validateBlock(block)

        # Шукаємо документ
        result = self.blockchain.verifyDocument(doc_hash)
        self.assertIsNotNone(result)
        self.assertIn("Document found", result)

    def test_verify_document_not_found(self):
        """Тест пошуку документу, якого немає в блокчейні"""
        doc_hash = Hash.toSHA256("Неіснуючий документ")
        result = self.blockchain.verifyDocument(doc_hash)
        self.assertIsNone(result)


class TestIntegration(unittest.TestCase):
    """Інтеграційні тести"""

    def test_full_flow(self):
        """Повний тест потоку роботи блокчейну"""
        blockchain = Blockchain("IntegrationTest")

        # 1. Створення акаунтів
        alice = Account.genAccount()
        bob = Account.genAccount()

        # 2. Поповнення з крана
        blockchain.getTokenFromFaucet(alice, 1000)
        blockchain.getTokenFromFaucet(bob, 500)

        # Перевірка початкових балансів
        self.assertEqual(blockchain.getAccountBalance(alice.account_id), 1000)
        self.assertEqual(blockchain.getAccountBalance(bob.account_id), 500)

        # 3. Створення операцій
        doc1_hash = Hash.toSHA256("Документ 1")
        op1 = Operation.createOperation(
            sender=alice,
            receiver=bob,
            amount=200,
            document_hash=doc1_hash,
            key_index=0
        )

        doc2_hash = Hash.toSHA256("Документ 2")
        op2 = Operation.createOperation(
            sender=bob,
            receiver=alice,
            amount=50,
            document_hash=doc2_hash,
            key_index=0
        )

        # 4. Створення транзакцій
        tx1 = Transaction.createTransaction([op1, op2], nonce=1)

        # 5. Створення та валідація блоку
        prev_hash = blockchain.block_history[-1].block_id
        block = Block.createBlock([tx1], prev_hash, block_number=1)

        is_valid = blockchain.validateBlock(block)
        self.assertTrue(is_valid)

        # 6. Перевірка кінцевих балансів
        self.assertEqual(blockchain.getAccountBalance(alice.account_id), 850)  # 1000 - 200 + 50
        self.assertEqual(blockchain.getAccountBalance(bob.account_id), 650)  # 500 + 200 - 50

        # 7. Перевірка документів
        result1 = blockchain.verifyDocument(doc1_hash)
        self.assertIsNotNone(result1)

        result2 = blockchain.verifyDocument(doc2_hash)
        self.assertIsNotNone(result2)

        # 8. Перевірка цілісності
        integrity = blockchain.checkBlockchainIntegrity()
        self.assertTrue(integrity)


def run_tests():
    """Запуск всіх тестів"""
    # Створюємо тест-сьют
    test_suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

    # Запускаємо тести
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # Вивід результатів
    print(f"\n{'=' * 60}")
    print(f"Результати тестування:")
    print(f"Тестів пройдено: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Тестів провалено: {len(result.failures)}")
    print(f"Помилок: {len(result.errors)}")

    if result.failures:
        print(f"\nПровалені тести:")
        for test, traceback in result.failures:
            print(f"  - {test}")

    if result.errors:
        print(f"\nПомилки:")
        for test, traceback in result.errors:
            print(f"  - {test}")

    return result.wasSuccessful()


if __name__ == '__main__':
    # Запускаємо тести
    success = run_tests()

    # Повертаємо код виходу
    sys.exit(0 if success else 1)