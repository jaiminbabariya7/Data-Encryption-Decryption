"""
Cryptographic utilities: AES-256-GCM, RSA-2048, SHA-256, HMAC-SHA256.
"""
from __future__ import annotations
import base64, hashlib, hmac, os
from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_aes_key() -> bytes:
    """Generate a cryptographically random 256-bit AES key."""
    return os.urandom(32)

def aes_encrypt(plaintext: str | bytes, key: bytes) -> Tuple[bytes, bytes]:
    """AES-256-GCM encrypt. Returns (nonce, ciphertext_with_tag)."""
    if isinstance(plaintext, str): plaintext = plaintext.encode("utf-8")
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)

def aes_decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """AES-256-GCM decrypt and verify integrity tag."""
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")

def aes_encrypt_b64(plaintext: str, key: bytes) -> str:
    """Encrypt and return base64(nonce || ciphertext) token."""
    nonce, ct = aes_encrypt(plaintext, key)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")

def aes_decrypt_b64(token: str, key: bytes) -> str:
    """Decrypt a base64 token from aes_encrypt_b64."""
    raw = base64.urlsafe_b64decode(token)
    return aes_decrypt(raw[:12], raw[12:], key)

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """Generate RSA key pair. Returns (private_pem, public_pem)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return (
        priv.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()),
        priv.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo),
    )

def rsa_encrypt(plaintext: str | bytes, public_key_pem: bytes) -> bytes:
    """RSA-OAEP+SHA256 encrypt with public key."""
    if isinstance(plaintext, str): plaintext = plaintext.encode("utf-8")
    return serialization.load_pem_public_key(public_key_pem).encrypt(
        plaintext, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> str:
    """RSA-OAEP+SHA256 decrypt with private key."""
    return serialization.load_pem_private_key(private_key_pem, None).decrypt(
        ciphertext, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    ).decode("utf-8")

def sha256_hash(data: str | bytes) -> str:
    """SHA-256 hex digest."""
    if isinstance(data, str): data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def hmac_sha256(data: str | bytes, secret: str | bytes) -> str:
    """HMAC-SHA256 hex digest."""
    if isinstance(data, str):   data   = data.encode("utf-8")
    if isinstance(secret, str): secret = secret.encode("utf-8")
    return hmac.new(secret, data, digestmod=hashlib.sha256).hexdigest()

def verify_hmac(data: str | bytes, secret: str | bytes, expected: str) -> bool:
    """Constant-time HMAC verification."""
    return hmac.compare_digest(hmac_sha256(data, secret), expected.lower())
