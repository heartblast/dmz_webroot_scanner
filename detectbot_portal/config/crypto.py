from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


ENCRYPTION_KEY_ENV = "DETECTBOT_SETTINGS_ENCRYPTION_KEY"


class SettingsCryptoError(RuntimeError):
    pass


def _get_fernet() -> Fernet:
    key = os.getenv(ENCRYPTION_KEY_ENV, "").strip()
    if not key:
        raise SettingsCryptoError(
            f"Missing encryption key. Set the `{ENCRYPTION_KEY_ENV}` environment variable."
        )
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise SettingsCryptoError(
            f"Invalid encryption key in `{ENCRYPTION_KEY_ENV}`. It must be a valid Fernet key."
        ) from exc


def encrypt_secret(plain_text: str) -> str:
    if not plain_text:
        return ""
    fernet = _get_fernet()
    return fernet.encrypt(plain_text.encode("utf-8")).decode("utf-8")


def decrypt_secret(cipher_text: str) -> str:
    if not cipher_text:
        return ""
    fernet = _get_fernet()
    try:
        return fernet.decrypt(cipher_text.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise SettingsCryptoError(
            "Failed to decrypt the stored PostgreSQL password. Check the encryption key."
        ) from exc
