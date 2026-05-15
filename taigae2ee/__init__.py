"""
Тайга — E2EE‑библиотека на российских криптостандартах (обёртка над PyGOST).
Простой интерфейс для защищённого обмена сообщениями.
"""
from .e2ee import TaigaUser
from .key_storage import encrypt_private_key, decrypt_private_key

__version__ = "0.1.5"
