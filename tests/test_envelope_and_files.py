"""Unit tests for envelope encryption and file-level encryption."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.crypto_utils import generate_rsa_keypair
from src.envelope_encrypt import envelope_encrypt, envelope_decrypt
from src.file_encryptor import encrypt_file, decrypt_file


class TestEnvelopeEncryption(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)

    def test_roundtrip(self):
        enc_key, nonce, ct = envelope_encrypt("large payload", self.pub)
        self.assertEqual(envelope_decrypt(enc_key, nonce, ct, self.priv), "large payload")

    def test_payload_larger_than_rsa_limit(self):
        payload = "x" * 10_000
        enc_key, nonce, ct = envelope_encrypt(payload, self.pub)
        self.assertEqual(envelope_decrypt(enc_key, nonce, ct, self.priv), payload)

    def test_wrong_private_key_raises(self):
        other_priv, _ = generate_rsa_keypair(2048)
        enc_key, nonce, ct = envelope_encrypt("secret", self.pub)
        with self.assertRaises(Exception):
            envelope_decrypt(enc_key, nonce, ct, other_priv)


class TestFileEncryption(unittest.TestCase):
    def test_binary_file_roundtrip(self):
        data = os.urandom(2048)
        with tempfile.TemporaryDirectory() as tmp:
            src, enc, dec = Path(tmp) / "a.bin", Path(tmp) / "a.enc", Path(tmp) / "a.out"
            src.write_bytes(data)
            key = encrypt_file(src, enc)
            self.assertNotEqual(enc.read_bytes(), data)
            decrypt_file(enc, dec, key)
            self.assertEqual(dec.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
