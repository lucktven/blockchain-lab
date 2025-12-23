# core/hash.py
"""Клас Hash - обгортка для геш-функцій"""

import hashlib

class Hash:
    """Клас-обгортка для геш-функцій згідно з методичними вказівками"""

    @staticmethod
    def toSHA256(message: str) -> str:
        """Повертає SHA-256 хеш від повідомлення"""
        return hashlib.sha256(message.encode()).hexdigest()

    @staticmethod
    def toSHA1(message: str) -> str:
        """Повертає SHA-1 хеш від повідомлення (для сумісності з UML)"""
        return hashlib.sha1(message.encode()).hexdigest()

    @staticmethod
    def toMD5(message: str) -> str:
        """Повертає MD5 хеш від повідомлення (додатково)"""
        return hashlib.md5(message.encode()).hexdigest()