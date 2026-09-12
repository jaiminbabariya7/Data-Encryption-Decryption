"""Envelope encryption (cloud KMS pattern): RSA-OAEP wraps a per-message AES key."""
from __future__ import annotations
from typing import Tuple
from .crypto_utils import aes_decrypt_bytes, aes_encrypt, generate_aes_key, rsa_decrypt_bytes, rsa_encrypt


def envelope_encrypt(plaintext: str | bytes, public_key_pem: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypt with a fresh AES-256-GCM data key wrapped by RSA-OAEP.

    Returns (encrypted_data_key, nonce, ciphertext).
    """
    data_key = generate_aes_key()
    nonce, ciphertext = aes_encrypt(plaintext, data_key)
    return rsa_encrypt(data_key, public_key_pem), nonce, ciphertext


def envelope_decrypt(
    encrypted_key: bytes, nonce: bytes, ciphertext: bytes, private_key_pem: bytes
) -> str:
    """Unwrap the data key with RSA-OAEP and decrypt the payload."""
    data_key = rsa_decrypt_bytes(encrypted_key, private_key_pem)
    return aes_decrypt_bytes(nonce, ciphertext, data_key).decode("utf-8")
