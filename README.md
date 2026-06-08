# Data Encryption & Decryption

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-Authenticated_Encryption-green)
![RSA-2048](https://img.shields.io/badge/RSA--2048-Asymmetric-blue)
![Tests](https://img.shields.io/badge/tests-18%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> Production-grade cryptographic utilities in Python: AES-256-GCM authenticated encryption, RSA-2048 key pairs, SHA-256/HMAC-SHA256 hashing, file-level encryption, and envelope encryption (KMS pattern). No external runtime dependencies beyond `cryptography`.

## Architecture
```
┌─────────────────────────────────────────────────────┐
│               crypto_utils.py                       │
│  ┌────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │ AES-256-GCM│  │  RSA-2048   │  │  SHA-256    │  │
│  │ (symmetric)│  │(asymmetric) │  │  HMAC-SHA   │  │
│  └────────────┘  └─────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────┘
         ↑                  ↑
  file_encryptor.py   envelope_encrypt.py
  (file-level AES)    (RSA wraps AES key — KMS pattern)
```

## Features

| Feature | Algorithm | Use Case |
|---|---|---|
| Symmetric encryption | AES-256-GCM | Data at rest |
| Asymmetric encryption | RSA-2048/OAEP | Key exchange |
| Hashing | SHA-256 | Checksums, fingerprints |
| Message authentication | HMAC-SHA256 | API request signing |
| File encryption | AES-256-GCM | Files on disk |
| Envelope encryption | RSA wraps AES key | Cloud KMS pattern |

## Quick Start
```bash
git clone https://github.com/jaiminbabariya7/Data-Encryption-Decryption
cd Data-Encryption-Decryption && make install
```

### AES-256-GCM (symmetric)
```python
from src.crypto_utils import generate_aes_key, aes_encrypt_b64, aes_decrypt_b64

key   = generate_aes_key()                       # 32 random bytes
token = aes_encrypt_b64("sensitive data", key)   # base64 token
plain = aes_decrypt_b64(token, key)              # "sensitive data"
```

### RSA-2048 (asymmetric)
```python
from src.crypto_utils import generate_rsa_keypair, rsa_encrypt, rsa_decrypt

priv, pub = generate_rsa_keypair()
ct        = rsa_encrypt("secret", pub)
plain     = rsa_decrypt(ct, priv)
```

### Envelope Encryption (cloud KMS pattern)
```python
from src.envelope_encrypt import envelope_encrypt, envelope_decrypt

enc_key, nonce, ct = envelope_encrypt("large payload", pub)
plain = envelope_decrypt(enc_key, nonce, ct, priv)
```

## Security Notes
- **Nonces**: AES-GCM uses 96-bit random nonces — a fresh one per call. Never reuse a nonce with the same key.
- **Key storage**: Use environment variables, HashiCorp Vault, or a cloud KMS — never hardcode keys.
- **RSA payload limit**: RSA-2048/OAEP encrypts at most ~190 bytes. Use envelope encryption for larger data.
- **Tamper detection**: AES-GCM's 128-bit auth tag raises `InvalidTag` on any ciphertext modification.

## Testing
```bash
make test    # 18 unit tests with coverage report
make lint    # flake8 + black check
```

## Skills Demonstrated
`Python` · `Cryptography` · `AES-256-GCM` · `RSA-2048` · `HMAC` · `Security Engineering` · `TDD`
