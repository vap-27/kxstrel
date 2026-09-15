"""Envelope encryption for stored X session credentials (Fernet/AES-128-CBC).

The key always comes from the CREDENTIAL_ENCRYPTION_KEY environment secret.
Generate one with:  python scripts/setup_account.py --generate-key
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

KEY_ERROR_HINT = (
    "CREDENTIAL_ENCRYPTION_KEY must be a Fernet key "
    "(urlsafe-base64, 32 bytes). Generate one with: "
    "python scripts/setup_account.py --generate-key"
)


class CredentialCrypto:
    def __init__(self, key: str):
        if not key or not key.strip():
            raise ValueError(KEY_ERROR_HINT)
        try:
            self._fernet = Fernet(key.strip().encode("utf-8"))
        except Exception as exc:
            raise ValueError(KEY_ERROR_HINT) from exc

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("cannot decrypt credential (wrong key or corrupt data)") from exc


def generate_key() -> str:
    return Fernet.generate_key().decode("utf-8")
