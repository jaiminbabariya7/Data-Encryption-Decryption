"""File encryption/decryption using AES-256-GCM."""
from __future__ import annotations
from pathlib import Path
from .crypto_utils import generate_aes_key, aes_encrypt, aes_decrypt

def encrypt_file(src: str | Path, dst: str | Path, key: bytes | None = None) -> bytes:
    """Encrypt a file with AES-256-GCM. Returns the key used."""
    key = key or generate_aes_key()
    nonce, ct = aes_encrypt(Path(src).read_bytes(), key)
    Path(dst).write_bytes(nonce + ct)
    return key

def decrypt_file(src: str | Path, dst: str | Path, key: bytes) -> None:
    """Decrypt an AES-256-GCM encrypted file."""
    raw = Path(src).read_bytes()
    Path(dst).write_text(aes_decrypt(raw[:12], raw[12:], key))
