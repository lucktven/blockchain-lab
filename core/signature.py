# core/signature.py
"""Класи KeyPair та Signature для роботи з криптографією"""

import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class KeyPair:
    """Клас для роботи з ключовою парою RSA (ETAP 2)"""

    def __init__(self):
        self._private_key = None
        self._public_key = None
        self.genKeyPair()

    def genKeyPair(self) -> 'KeyPair':
        """Генерація нової ключової пари RSA 2048 біт"""
        key = RSA.generate(2048)
        self._private_key = key
        self._public_key = key.publickey()
        return self

    def getPrivateKey(self):
        """Повертає приватний ключ"""
        return self._private_key

    def getPublicKey(self):
        """Повертає публічний ключ"""
        return self._public_key

    def getPublicKeyPEM(self) -> str:
        """Повертає публічний ключ у форматі PEM"""
        return self._public_key.export_key().decode()

    def getPrivateKeyPEM(self) -> str:
        """Повертає приватний ключ у форматі PEM"""
        return self._private_key.export_key().decode()

    def printKeyPair(self):
        """Вивід інформації про ключі (додатковий метод)"""
        print(f"Public Key (PEM): {self.getPublicKeyPEM()[:50]}...")
        print(f"Private Key: [PRIVATE - {self._private_key.size_in_bits()} bits]")

    def __str__(self) -> str:
        return f"KeyPair(RSA-{self._private_key.size_in_bits()}, pub={self.getPublicKeyPEM()[:30]}...)"


class Signature:
    """Клас для роботи з цифровими підписами (ETAP 2)"""

    @staticmethod
    def signData(private_key, data: str) -> str:
        """
        Підпис даних приватним ключем

        Args:
            private_key: Приватний ключ RSA
            data: Дані для підпису

        Returns:
            Base64-encoded підпис
        """
        h = SHA256.new(data.encode())
        signature = pkcs1_15.new(private_key).sign(h)
        return base64.b64encode(signature).decode()

    @staticmethod
    def verifySignature(public_key, data: str, signature: str) -> bool:
        """
        Верифікація підпису публічним ключем

        Args:
            public_key: Публічний ключ RSA
            data: Оригінальні дані
            signature: Підпис у форматі Base64

        Returns:
            True якщо підпис валідний, False - якщо ні
        """
        try:
            h = SHA256.new(data.encode())
            sig_bytes = base64.b64decode(signature)
            pkcs1_15.new(public_key).verify(h, sig_bytes)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def printSignature(signature: str):
        """Вивід підпису (додатковий метод)"""
        print(f"Signature (Base64): {signature[:50]}...")

    @staticmethod
    def signDataWithPEM(private_key_pem: str, data: str) -> str:
        """Підпис даних з використанням приватного ключа у форматі PEM"""
        private_key = RSA.import_key(private_key_pem)
        return Signature.signData(private_key, data)

    @staticmethod
    def verifySignatureWithPEM(public_key_pem: str, data: str, signature: str) -> bool:
        """Верифікація підпису з використанням публічного ключа у форматі PEM"""
        public_key = RSA.import_key(public_key_pem)
        return Signature.verifySignature(public_key, data, signature)