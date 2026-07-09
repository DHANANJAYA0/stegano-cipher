import pytest
from stegano_cipher.crypto import encrypt_bytes, decrypt_bytes, _derive_key

def test_derive_key():
    k1 = _derive_key("password", b"1234567890123456")
    k2 = _derive_key("password", b"1234567890123456")
    assert k1 == k2
    k3 = _derive_key("wrong", b"1234567890123456")
    assert k1 != k3

def test_encrypt_decrypt():
    password = "super-secret-password"
    plaintext = b"Hello, World! This is a test message to ensure our crypto pipeline (including RS ECC) works properly."
    
    blob = encrypt_bytes(password, plaintext)
    
    # Check that we can decrypt
    decrypted = decrypt_bytes(password, blob)
    assert decrypted == plaintext

def test_wrong_password():
    blob = encrypt_bytes("correct", b"Secret data")
    with pytest.raises(Exception):
        decrypt_bytes("wrong", blob)

def test_ecc_recovery():
    blob = encrypt_bytes("pwd", b"This should survive minor corruption")
    blob_bytearray = bytearray(blob)
    # Corrupt a few bytes
    blob_bytearray[5] ^= 0xFF
    blob_bytearray[10] ^= 0xFF
    blob_bytearray[15] ^= 0xFF
    
    corrupted_blob = bytes(blob_bytearray)
    # ECC should recover it
    decrypted = decrypt_bytes("pwd", corrupted_blob)
    assert decrypted == b"This should survive minor corruption"
