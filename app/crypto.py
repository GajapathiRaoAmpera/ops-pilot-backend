"""Encryption at rest for integration credentials. Plaintext never leaves this module's callers' scope."""
from cryptography.fernet import Fernet, InvalidToken

from app.config import Settings


class SecretKeyMissing(Exception):
    pass


def _fernet(settings: Settings) -> Fernet:
    if not settings.secret_key:
        raise SecretKeyMissing("OPSPILOT_SECRET_KEY is not configured")
    return Fernet(settings.secret_key.encode())


def encrypt(settings: Settings, plaintext: str) -> str:
    return _fernet(settings).encrypt(plaintext.encode()).decode()


def decrypt(settings: Settings, ciphertext: str) -> str | None:
    """None when the value cannot be decrypted (rotated or wrong key)."""
    try:
        return _fernet(settings).decrypt(ciphertext.encode()).decode()
    except (InvalidToken, SecretKeyMissing, ValueError):  # ValueError: malformed key
        return None
