"""
Безопасное хранение приватного ключа с шифрованием на пароле.
Использует PBKDF2-HMAC-Стрибог-512 и Кузнечик-MGM.
"""
import struct
import os
import secrets
from typing import Union

from gostcrypto import gosthash, gostcipher

def _hmac_streebog(key: bytes, msg: bytes) -> bytes:
    """HMAC на основе Стрибог-512."""
    block_size = 64
    if len(key) > block_size:
        key = gosthash.new('streebog512', data=key).digest()
    key = key.ljust(block_size, b'\x00')
    o_key_pad = bytes(x ^ 0x5c for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    return gosthash.new('streebog512',
                        data=(o_key_pad +
                              gosthash.new('streebog512',
                                           data=i_key_pad + msg).digest())).digest()

def _pbkdf2_streebog(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """PBKDF2 с псевдослучайной функцией HMAC-Стрибог-512."""
    hlen = 64
    num_blocks = (dklen + hlen - 1) // hlen
    result = b''
    for block in range(1, num_blocks + 1):
        U = _hmac_streebog(password, salt + struct.pack(">I", block))
        T = U
        for _ in range(iterations - 1):
            U = _hmac_streebog(password, U)
            T = bytes(a ^ b for a, b in zip(T, U))
        result += T
    return result[:dklen]

def _mgm_encrypt(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b'') -> tuple:
    """Шифрование MGM (Кузнечик). Исправлено: init_vect вместо nonce."""
    cipher = gostcipher.new('kuznechik', key, gostcipher.MODE_MGM,
                            init_vect=nonce, aad=aad)
    ct = cipher.encrypt(pt)
    return ct, cipher.mac

def _mgm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes = b'') -> bytes:
    """Расшифровка MGM с проверкой подлинности."""
    cipher = gostcipher.new('kuznechik', key, gostcipher.MODE_MGM,
                            init_vect=nonce, aad=aad)
    pt = cipher.decrypt(ct)
    if not secrets.compare_digest(cipher.mac, tag):
        raise ValueError("Неверный тег аутентификации")
    return pt

def encrypt_private_key(private_key_bytes: bytes, password: str) -> bytes:
    """
    Шифрует приватный ключ (32 байта) с помощью пароля.
    Возвращает: salt(32) + nonce(16) + tag(16) + ciphertext.
    """
    if not isinstance(private_key_bytes, bytes) or len(private_key_bytes) != 32:
        raise ValueError("Приватный ключ должен быть 32 байта")
    if not password:
        raise ValueError("Пароль не может быть пустым")
    salt = os.urandom(32)
    kek = _pbkdf2_streebog(password.encode('utf-8'), salt, 200000, 32)
    nonce = os.urandom(16)
    ct, tag = _mgm_encrypt(kek, nonce, private_key_bytes)
    return salt + nonce + tag + ct

def decrypt_private_key(encrypted_blob: bytes, password: str) -> bytes:
    """Расшифровывает приватный ключ из блоба."""
    if len(encrypted_blob) < 32 + 16 + 16 + 1:
        raise ValueError("Блоб слишком короткий")
    salt = encrypted_blob[:32]
    nonce = encrypted_blob[32:48]
    tag = encrypted_blob[48:64]
    ct = encrypted_blob[64:]
    kek = _pbkdf2_streebog(password.encode('utf-8'), salt, 200000, 32)
    return _mgm_decrypt(kek, nonce, ct, tag)