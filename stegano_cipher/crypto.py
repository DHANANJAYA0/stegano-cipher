from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def _derive_key(password: str, salt: bytes, length: int = 32, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(password: str, plaintext: bytes) -> bytes:
    """Encrypt bytes using AES-256-GCM with PBKDF2-HMAC-SHA256.

    Output format: salt(16) || nonce(12) || ciphertext+tag
    """
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return salt + nonce + ct


def decrypt_bytes(password: str, blob: bytes) -> bytes:
    """Decrypt bytes produced by encrypt_bytes.

    Expect input format: salt(16) || nonce(12) || ciphertext+tag
    """
    if len(blob) < 28:
        raise ValueError("Blob too short for salt+nonce")
    salt = blob[:16]
    nonce = blob[16:28]
    ct = blob[28:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)


def add_length_header(data: bytes) -> bytes:
    """Prefix data with 4-byte big-endian length for extraction."""
    length = len(data)
    return length.to_bytes(4, "big") + data


def strip_length_header(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 4:
        raise ValueError("No length header present")
    length = int.from_bytes(data[:4], "big")
    payload = data[4:4+length]
    if len(payload) != length:
        raise ValueError("Length header mismatch")
    return length, payload