Проект создан школьником (14 лет) в рамках изучения криптографии.  
Код открыт, замечания и pull request приветствуются!

# Тайга (taigae2ee)

Лёгкая и безопасная библиотека сквозного шифрования (E2EE) на российских криптостандартах.

**Внутри — проверенная библиотека PyGOST.  
Снаружи — простой API.**

## ✨ Особенности

- **ГОСТ Р 34.12-2015** — блочный шифр «Кузнечик»
- **ГОСТ Р 34.11-2012** — хэш-функция «Стрибог» (256/512)
- **ГОСТ Р 34.10-2012** — эллиптическая кривая, ECDH
- **ГОСТ Р 34.13-2015** — режим аутентифицированного шифрования MGM
- Эфемерные ключи (прямая секретность)
- Подтверждение ключа (key confirmation)
- Простая бинарная упаковка сообщений
- Шифрование приватных ключей на пароле (PBKDF2-HMAC-Стрибог)

Пример использования:

from taigae2ee import TaigaUser

alice = TaigaUser()
bob = TaigaUser()

# Алиса шифрует сообщение для Боба
packet = alice.encrypt_for(bob.pub_bytes, b"Привет, Боб!")

# Боб расшифровывает
plain = bob.decrypt_from(alice.pub_bytes, packet)
print(plain.decode('utf-8'))   # Привет, Боб!

Хранение ключей:

from taigae2ee.key_storage import encrypt_private_key, decrypt_private_key

encrypted = encrypt_private_key(alice.priv_bytes, "Пароль")
# ... сохранить encrypted в файл ...

# Восстановление
private_key = decrypt_private_key(encrypted, "Пароль")

## 📦 Установка

```bash
pip install taigae2ee