"""
Простые тесты протокола «Тайга»: шифрование, расшифровка,
корректность подтверждения ключа, обнаружение подмены.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from taigae2ee import TaigaUser

def test_basic_encryption():
    alice = TaigaUser()
    bob = TaigaUser()
    plain = b"Привет, Тайга!"
    packet = alice.encrypt_for(bob.pub_bytes, plain)
    decrypted = bob.decrypt_from(alice.pub_bytes, packet)
    assert decrypted == plain, "Расшифрованный текст не совпадает с исходным"
    print("✓ Базовое шифрование/расшифровка работают")

def test_wrong_recipient_cannot_decrypt():
    alice = TaigaUser()
    bob = TaigaUser()
    eve = TaigaUser()
    packet = alice.encrypt_for(bob.pub_bytes, b"Секрет")
    try:
        eve.decrypt_from(alice.pub_bytes, packet)
        assert False, "Ева смогла расшифровать сообщение!"
    except ValueError:
        print("✓ Ева не может расшифровать сообщение для Боба")

def test_tampered_packet_detected():
    alice = TaigaUser()
    bob = TaigaUser()
    packet = alice.encrypt_for(bob.pub_bytes, b"Test")
    # Портим байт в шифртексте
    tampered = bytearray(packet)
    tampered[100] ^= 0x01
    try:
        bob.decrypt_from(alice.pub_bytes, bytes(tampered))
        assert False, "Подмена не обнаружена"
    except ValueError:
        print("✓ Подмена пакета обнаружена (неверный тег или подтверждение)")

if __name__ == "__main__":
    test_basic_encryption()
    test_wrong_recipient_cannot_decrypt()
    test_tampered_packet_detected()
    print("Все тесты протокола пройдены успешно!")