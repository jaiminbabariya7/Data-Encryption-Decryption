"""Unit tests for crypto_utils module."""
import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__),'..'))
from src.crypto_utils import (
    generate_aes_key, aes_encrypt, aes_decrypt, aes_encrypt_b64, aes_decrypt_b64,
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    sha256_hash, hmac_sha256, verify_hmac,
)

class TestAES(unittest.TestCase):
    def setUp(self): self.key = generate_aes_key()
    def test_key_32_bytes(self):  self.assertEqual(len(self.key), 32)
    def test_roundtrip(self):
        n,ct = aes_encrypt("hello", self.key)
        self.assertEqual(aes_decrypt(n, ct, self.key), "hello")
    def test_unique_nonces(self):
        n1,_ = aes_encrypt("x", self.key); n2,_ = aes_encrypt("x", self.key)
        self.assertNotEqual(n1, n2)
    def test_tamper_raises(self):
        from cryptography.exceptions import InvalidTag
        n,ct = aes_encrypt("x", self.key)
        with self.assertRaises(InvalidTag): aes_decrypt(n, ct[:-1]+bytes([ct[-1]^0xFF]), self.key)
    def test_b64_roundtrip(self):
        t = aes_encrypt_b64("test", self.key)
        self.assertEqual(aes_decrypt_b64(t, self.key), "test")
    def test_wrong_key_raises(self):
        from cryptography.exceptions import InvalidTag
        n,ct = aes_encrypt("x", self.key)
        with self.assertRaises(InvalidTag): aes_decrypt(n, ct, generate_aes_key())

class TestRSA(unittest.TestCase):
    def setUp(self): self.priv,self.pub = generate_rsa_keypair(2048)
    def test_pem_format(self):
        self.assertIn(b"PRIVATE KEY", self.priv)
        self.assertIn(b"PUBLIC KEY",  self.pub)
    def test_roundtrip(self):
        ct = rsa_encrypt("hello", self.pub)
        self.assertEqual(rsa_decrypt(ct, self.priv), "hello")
    def test_wrong_key_raises(self):
        priv2,_ = generate_rsa_keypair(2048)
        with self.assertRaises(Exception): rsa_decrypt(rsa_encrypt("x",self.pub), priv2)

class TestHashing(unittest.TestCase):
    def test_sha256_length(self):    self.assertEqual(len(sha256_hash("hello")), 64)
    def test_sha256_deterministic(self): self.assertEqual(sha256_hash("a"), sha256_hash("a"))
    def test_sha256_different(self): self.assertNotEqual(sha256_hash("a"), sha256_hash("b"))
    def test_hmac_deterministic(self): self.assertEqual(hmac_sha256("m","k"), hmac_sha256("m","k"))
    def test_verify_valid(self):   self.assertTrue(verify_hmac("d","k", hmac_sha256("d","k")))
    def test_verify_invalid(self): self.assertFalse(verify_hmac("d","k", "deadbeef"*8))

if __name__ == "__main__": unittest.main()
