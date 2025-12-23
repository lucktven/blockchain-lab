# demo.py
"""Демонстрація роботи блокчейну"""

import time
from core.hash import Hash
from core.account import Account
from core.operation import Operation, Transaction
from core.block import Block
from core.blockchain import Blockchain
from utils.helpers import *


def demonstrate_blockchain():
    """Демонстрація роботи блокчейну"""
    print_separator("Blockchain Document Timestamping System")
    print("Лабораторна робота №3: Реалізація власного blockchain")
    print("=" * 60)

    # 1. Ініціалізація блокчейну
    print("\n1. Ініціалізація блокчейну...")
    blockchain = Blockchain(name="DocChain")
    time.sleep(1)

    # 2. Створення акаунтів
    print("\n2. Створення облікових записів...")
    alice = Account.genAccount()
    bob = Account.genAccount()
    charlie = Account.genAccount()

    print(f"   Alice: {alice.account_id[:15]}...")
    print(f"   Bob: {bob.account_id[:15]}...")
    print(f"   Charlie: {charlie.account_id[:15]}...")
    time.sleep(1)

    # 3. Отримання монет з крана
    print("\n3. Поповнення рахунків з крана...")
    blockchain.getTokenFromFaucet(alice, 1000)
    blockchain.getTokenFromFaucet(bob, 750)
    blockchain.getTokenFromFaucet(charlie, 500)

    blockchain.showCoinDatabase()
    time.sleep(2)

    # 4. Реєстрація документів
    print_separator("Реєстрація документів у блокчейні")

    print("4.1. Створення документів...")
    documents = [
        ("Договір про надання послуг v1.0", "Contract_Service_2024_v1.pdf"),
        ("Офіційний лист №123", "Official_Letter_123.docx"),
        ("Звіт про виконані роботи", "Work_Report_Q1_2024.pdf"),
        ("Акт виконаних робіт", "Act_of_Completion_001.pdf"),
        ("Довідка про доходи", "Income_Certificate_2024.pdf")
    ]

    doc_hashes = []
    for content, filename in documents:
        doc_hash = generate_document_hash(content)
        doc_hashes.append((doc_hash, filename, content[:30]))
        print(f"   {filename}: {doc_hash[:20]}...")

    time.sleep(1)

    # 5. Створення операцій з документами
    print("\n4.2. Створення операцій з документами...")

    operations = []

    # Операція 1: Alice реєструє договір
    op1 = Operation.createOperation(
        sender=alice,
        receiver=bob,
        amount=0,
        document_hash=doc_hashes[0][0]
    )
    operations.append(op1)
    print(f"   Операція 1: Alice → Bob (договір)")

    # Операція 2: Bob передає лист Charlie з оплатою
    op2 = Operation.createOperation(
        sender=bob,
        receiver=charlie,
        amount=100,
        document_hash=doc_hashes[1][0]
    )
    operations.append(op2)
    print(f"   Операція 2: Bob → Charlie (лист + 100 монет)")

    # Операція 3: Alice передає звіт Bob
    op3 = Operation.createOperation(
        sender=alice,
        receiver=bob,
        amount=50,
        document_hash=doc_hashes[2][0]
    )
    operations.append(op3)
    print(f"   Операція 3: Alice → Bob (звіт + 50 монет)")

    # Операція 4: Charlie передає акт Alice
    op4 = Operation.createOperation(
        sender=charlie,
        receiver=alice,
        amount=25,
        document_hash=doc_hashes[3][0]
    )
    operations.append(op4)
    print(f"   Операція 4: Charlie → Alice (акт + 25 монет)")

    time.sleep(2)

    # 6. Створення транзакцій
    print("\n5. Формування транзакцій...")

    # Транзакція 1: Перші дві операції
    tx1 = Transaction.createTransaction(operations[:2], nonce=1)
    print(f"   Транзакція 1: {tx1.transaction_id[:15]}... ({len(tx1.operations)} операції)")

    # Транзакція 2: Решта операції
    tx2 = Transaction.createTransaction(operations[2:], nonce=2)
    print(f"   Транзакція 2: {tx2.transaction_id[:15]}... ({len(tx2.operations)} операції)")

    time.sleep(1)

    # 7. Створення та валідація блоку
    print_separator("Створення та валідація блоку")

    print("6.1. Створення блоку з транзакціями...")
    block1 = Block.createBlock(
        transactions=[tx1, tx2],
        prev_hash=blockchain.block_history[-1].block_id,
        block_number=1
    )
    print(f"   Створено блок #1: {block1.block_id[:15]}...")

    print("\n6.2. Валідація блоку...")
    if blockchain.validateBlock(block1):
        print("   ✓ Блок успішно валідовано та додано до ланцюжка!")
    else:
        print("   ✗ Помилка валідації блоку!")

    time.sleep(2)

    # 8. Перевірка документів
    print_separator("Перевірка документів у блокчейні")

    print("7. Пошук документів у блокчейні...")

    # Перевірка існуючого документу
    test_doc_hash = doc_hashes[0][0]
    result = blockchain.verifyDocument(test_doc_hash)
    if result:
        print(f"   ✓ Документ знайдено!")
        print(f"   Назва: {doc_hashes[0][1]}")
        print(f"   Контент: {doc_hashes[0][2]}...")
    else:
        print(f"   ✗ Документ не знайдено")

    # Перевірка неіснуючого документу
    fake_hash = generate_document_hash("Неіснуючий документ")
    result = blockchain.verifyDocument(fake_hash)
    if not result:
        print(f"   ✓ Неіснуючий документ не знайдено (коректно)")

    time.sleep(2)

    # 9. Перевірка цілісності ланцюжка
    print_separator("Перевірка цілісності блокчейну")

    print("8. Перевірка ланцюжка блоків...")
    blockchain.checkBlockchainIntegrity()

    # 10. Створення ще одного блоку
    print("\n9. Створення другого блоку...")

    # Додаткові операції
    op5 = Operation.createOperation(
        sender=bob,
        receiver=alice,
        amount=200,
        document_hash=doc_hashes[4][0]
    )

    tx3 = Transaction.createTransaction([op5], nonce=3)
    block2 = Block.createBlock(
        transactions=[tx3],
        prev_hash=blockchain.block_history[-1].block_id,
        block_number=2
    )

    if blockchain.validateBlock(block2):
        print(f"   ✓ Блок #2 успішно додано!")

    time.sleep(1)

    # 11. Фінальний стан
    print_separator("Фінальний стан системи")

    print("10. Статистика блокчейну:")
    print(f"   Назва: {blockchain.name}")
    print(f"   Кількість блоків: {blockchain.getBlockCount()}")
    print(f"   Кількість транзакцій: {blockchain.getTransactionCount()}")
    print(f"   Кількість облікових записів: {len(blockchain.coin_database)}")

    print("\nБаланси облікових записів:")
    blockchain.showCoinDatabase()

    print("\nІсторія блоків:")
    blockchain.showBlockHistory()

    print_separator("Демонстрацію завершено")

    return blockchain


def test_account_functionality():
    """Тестування функціональності облікових записів"""
    print_separator("Тестування функціональності Account")

    # Створення акаунта
    account = Account.genAccount()
    print(f"Створено обліковий запис: {account}")

    # Додавання другого ключа
    print("\nДодавання другої ключової пари...")
    keypair2 = account.wallet[0]  # Для тесту використовуємо ту саму пару
    account.addKeyPairToWallet(keypair2)

    # Оновлення балансу
    print("\nОновлення балансу...")
    account.updateBalance(1000)
    account.printBalance()

    # Підпис даних
    print("\nТестування підпису даних...")
    data = "Важливі дані для підпису"
    signature = account.signData(data, 0)
    print(f"Дані: {data}")
    print(f"Підпис: {signature[:50]}...")

    # Перевірка підпису
    from core.signature import Signature
    public_key = account.wallet[0].getPublicKey()
    is_valid = Signature.verifySignature(public_key, data, signature)
    print(f"Підпис валідний: {'✓' if is_valid else '✗'}")

    print_separator("Тестування завершено")


if __name__ == "__main__":
    # Запуск демонстрації
    blockchain = demonstrate_blockchain()

    # Додаткове тестування (розкоментуйте при потребі)
    # test_account_functionality()

    # Збереження результату для подальшого використання
    print("\nДля подальшої роботи з блокчейном використовуйте об'єкт 'blockchain'")