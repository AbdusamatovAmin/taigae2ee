import struct
import secrets
from typing import Tuple, Optional

from gostcrypto import gostcipher, gosthash, gostsignature

# ---------- БЛОК СОВМЕСТИМОСТИ с gostcrypto 1.2.5 ----------
# В версии 1.2.5 классы называются GOST34102012, а не GOSTSignatureKey/GOSTPublicKey.
# Чтобы сохранить публичный API библиотеки, создаём псевдонимы.
if not hasattr(gostsignature, 'GOSTSignatureKey'):
    gostsignature.GOSTSignatureKey = gostsignature.GOST34102012
if not hasattr(gostsignature, 'GOSTPublicKey'):
    # Публичный ключ в gostcrypto 1.2.5 представлен тем же классом GOST34102012,
    # но без приватной части. Поэтому просто используем его же.
    gostsignature.GOSTPublicKey = gostsignature.GOST34102012

# ========== Низкоуровневые обёртки ==========

def _kuznechik_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Зашифровать один 128-битный блок Кузнечиком (ECB)."""
    cipher = gostcipher.new('kuznechik', key, gostcipher.MODE_ECB)
    return cipher.encrypt(block)

def _streebog_256(data: bytes) -> bytes:
    """Хэш Стрибог-256."""
    return gosthash.new('streebog256', data=data).digest()

def _streebog_512(data: bytes) -> bytes:
    """Хэш Стрибог-512."""
    return gosthash.new('streebog512', data=data).digest()

def _hmac_streebog256(key: bytes, msg: bytes) -> bytes:
    """HMAC на основе Стрибог-256 (ГОСТ Р 34.11-2012)."""
    block_size = 64  # Размер блока для Стрибог
    if len(key) > block_size:
        key = _streebog_256(key)
    key = key.ljust(block_size, b'\x00')
    o_key_pad = bytes(x ^ 0x5c for x in key)
    i_key_pad = bytes(x ^ 0x36 for x in key)
    return _streebog_256(o_key_pad + _streebog_256(i_key_pad + msg))

def _mgm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                 associated_data: bytes = b'') -> Tuple[bytes, bytes]:
    """
    Режим MGM (ГОСТ Р 34.13-2015) — аутентифицированное шифрование.
    Возвращает (ciphertext, tag).
    """
    cipher = gostcipher.new('kuznechik', key, gostcipher.MODE_MGM,
                            init_vect=nonce, aad=associated_data)
    ct = cipher.encrypt(plaintext)
    tag = cipher.mac
    return ct, tag

def _mgm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                 associated_data: bytes = b'') -> bytes:
    """Расшифровка MGM с проверкой подлинности."""
    cipher = gostcipher.new('kuznechik', key, gostcipher.MODE_MGM,
                            init_vect=nonce, aad=associated_data)
    pt = cipher.decrypt(ciphertext)
    if not secrets.compare_digest(cipher.mac, tag):
        raise ValueError("Неверный тег аутентификации")
    return pt

# ========== Эллиптическая кривая и ECDH ==========

def _generate_keypair() -> Tuple[bytes, bytes]:
    """Генерирует пару ключей ГОСТ Р 34.10-2012 (256 бит).
    Возвращает (приватный_ключ, публичный_ключ) в DER-подобной кодировке (32 и 64 байта соответственно).
    """
    private_key = gostsignature.GOSTSignatureKey(curve='id-tc26-gost-3410-12-256-paramSetA')
    private_key.generate()
    public_key = private_key.public_key
    return private_key.encoded, public_key.encoded

def _ecdh(private_key_bytes: bytes, public_key_bytes: bytes) -> bytes:
    """Вычисляет общий секрет по ECDH (32 байта)."""
    priv = gostsignature.GOSTSignatureKey(curve='id-tc26-gost-3410-12-256-paramSetA',
                                           encoded=private_key_bytes)
    pub = gostsignature.GOSTPublicKey(curve='id-tc26-gost-3410-12-256-paramSetA',
                                      encoded=public_key_bytes)
    shared = priv.dh(pub)
    # shared — это x-координата точки, длина 32 байта
    if len(shared) != 32:
        raise ValueError("Неверная длина общего секрета")
    return shared

# ========== HKDF (на базе HMAC-Стрибог-256) ==========

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """Извлечение псевдослучайного ключа (PRK) по HKDF."""
    if not salt:
        salt = b'\x00' * 32  # HashLen для Стрибог-256 = 32 байта
    return _hmac_streebog256(salt, ikm)

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Расширение PRK до нужной длины."""
    if length > 255 * 32:  # максимальная длина по RFC (L * 255)
        raise ValueError("Запрошен слишком длинный выходной ключ")
    n = (length + 31) // 32
    t = b""
    prev = b""
    for i in range(1, n + 1):
        prev = _hmac_streebog256(prk, prev + info + bytes([i]))
        t += prev
    return t[:length]

def _derive_key(shared_secret: bytes, salt: bytes, info: bytes = b'TaigaE2EE v1') -> bytes:
    """
    Формирует сеансовый ключ (32 байта) на базе HKDF.
    Соль и контекстная строка info обеспечивают привязку к сеансу.
    """
    prk = _hkdf_extract(salt, shared_secret)
    return _hkdf_expand(prk, info, 32)

# ========== Подтверждение ключа ==========

def _make_confirmation(key: bytes, sender_pub: bytes, recipient_pub: bytes) -> bytes:
    """
    Создаёт 8-байтный тег подтверждения ключа.
    Связывает сеансовый ключ с публичными ключами обеих сторон.
    """
    return _streebog_256(b"CONFIRM" + sender_pub + recipient_pub + key)[:8]

# ========== Основной класс пользователя ==========

class TaigaUser:
    """Пользователь протокола сквозного шифрования «Тайга»."""

    def __init__(self):
        self.priv_bytes, self.pub_bytes = _generate_keypair()
        if len(self.priv_bytes) != 32:
            raise ValueError("Приватный ключ должен быть 32 байта")
        if len(self.pub_bytes) != 64:
            raise ValueError("Публичный ключ должен быть 64 байта")

    def clear(self):
        """Затирает приватный ключ в памяти."""
        if self.priv_bytes:
            mask = secrets.token_bytes(len(self.priv_bytes))
            self.priv_bytes = bytes(a ^ b for a, b in zip(self.priv_bytes, mask))
            self.priv_bytes = None

    def encrypt_for(self, recipient_pub_bytes: bytes, plaintext: bytes) -> bytes:
        """Шифрует сообщение для получателя."""
        if not isinstance(recipient_pub_bytes, bytes) or len(recipient_pub_bytes) != 64:
            raise ValueError("Публичный ключ получателя должен быть 64 байта")
        if not isinstance(plaintext, bytes):
            raise TypeError("Открытый текст должен быть в байтах")
        if len(plaintext) == 0:
            raise ValueError("Сообщение не может быть пустым")

        # 1. Эфемерный ключ
        eph_priv, eph_pub = _generate_keypair()
        # 2. Общий секрет
        shared = _ecdh(eph_priv, recipient_pub_bytes)
        # 3. Соль и ключ
        salt = secrets.token_bytes(16)
        key = _derive_key(shared, salt)
        # 4. Подтверждение ключа
        confirm_tag = _make_confirmation(key, self.pub_bytes, recipient_pub_bytes)
        # 5. Nonce
        nonce = secrets.token_bytes(16)

        # 6. Собираем AAD: версия + эфемерный ключ + соль + nonce
        aad = struct.pack(">B", 1) + eph_pub + salt + nonce

        # 7. Шифруем с AAD (пока без len_ct)
        ct, tag = _mgm_encrypt(key, nonce, plaintext, associated_data=aad)

        # 8. Теперь, когда ct известен, вычисляем полный AAD
        len_ct = struct.pack(">H", len(ct))
        full_aad = aad + len_ct

        # 9. Вычисляем отдельный MAC для ПОЛНОГО AAD, чтобы защитить len_ct
        #    Используем HKDF для получения ключа аутентификации и затем HMAC.
        #    Это гарантирует, что изменение длины будет обнаружено.
        prk = _hkdf_extract(salt, shared)
        mac_key = _hkdf_expand(prk, b'TaigaE2EE MAC key', 32)
        aad_mac = _hmac_streebog256(mac_key, full_aad)[:16] # 16-байтный MAC

        # 10. Возвращаем пакет с защищённым AAD
        return full_aad + ct + tag + aad_mac + confirm_tag

    def decrypt_from(self, sender_pub_bytes: bytes, packet: bytes) -> bytes:
        """
        Расшифровывает сообщение от отправителя.
        Ожидает бинарный пакет, созданный encrypt_for.
        """
        if not isinstance(sender_pub_bytes, bytes) or len(sender_pub_bytes) != 64:
            raise ValueError("Публичный ключ отправителя должен быть 64 байта")
        # минимальная длина пакета: aad(99) + tag(16) + aad_mac(16) + confirm(8)
        MIN_PACKET_LEN = 1 + 64 + 16 + 16 + 2 + 16 + 16 + 8
        if not isinstance(packet, bytes) or len(packet) < MIN_PACKET_LEN:
            raise ValueError("Пакет повреждён или неверной длины")

        pos = 0
        version = packet[pos]; pos += 1
        if version != 1:
            raise ValueError("Неизвестная версия пакета")

        eph_pub = packet[pos:pos+64]; pos += 64
        salt = packet[pos:pos+16]; pos += 16
        nonce = packet[pos:pos+16]; pos += 16
        len_ct = struct.unpack(">H", packet[pos:pos+2])[0]; pos += 2

        # Проверка, что оставшаяся длина соответствует заявленной
        # ct + tag(16) + aad_mac(16) + confirm_tag(8)
        if len(packet) - pos != len_ct + 16 + 16 + 8:
            raise ValueError("Неверная длина зашифрованных данных в пакете")

        ct = packet[pos:pos+len_ct]; pos += len_ct
        tag = packet[pos:pos+16]; pos += 16
        aad_mac = packet[pos:pos+16]; pos += 16          # ← новое поле
        confirm_tag = packet[pos:pos+8]; pos += 8

        # Восстанавливаем полный AAD
        aad = packet[:pos - len_ct - 16 - 16 - 8]        # ← обновлён сдвиг

        # 1. Общий секрет и производный ключ
        shared = _ecdh(self.priv_bytes, eph_pub)
        key = _derive_key(shared, salt)

        # 2. Проверка MAC-а для полного AAD (защита len_ct)
        prk = _hkdf_extract(salt, shared)
        mac_key = _hkdf_expand(prk, b'TaigaE2EE MAC key', 32)
        expected_aad_mac = _hmac_streebog256(mac_key, aad)[:16]
        if not secrets.compare_digest(expected_aad_mac, aad_mac):
            raise ValueError("Неверный MAC для ассоциированных данных")

        # 3. Проверка подтверждения ключа
        expected_confirm = _make_confirmation(key, sender_pub_bytes, self.pub_bytes)
        if not secrets.compare_digest(expected_confirm, confirm_tag):
            raise ValueError("Подтверждение ключа не совпало")

        # 4. Расшифровка (проверяет ассоциированные данные и тег)
        return _mgm_decrypt(key, nonce, ct, tag, associated_data=aad)