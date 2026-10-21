"""HiveAesCipher: AES-256-CBC/PKCS7, random 16-byte IV prepended to the ciphertext."""
import base64
import binascii
import hashlib
import zlib

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_LEN = 32
IV_LEN = 16


class KeyParseError(ValueError):
    pass


def parse_key(s: str) -> bytes:
    """Accept hex, base64/base64url, or a Dart list literal like [1, 2, ...]."""
    s = s.strip()
    candidates = []
    if s.startswith("["):
        try:
            candidates.append(bytes(int(x) for x in s.strip("[]").split(",") if x.strip()))
        except ValueError:
            pass
    try:
        candidates.append(bytes.fromhex(s.removeprefix("0x")))
    except ValueError:
        pass
    for dec in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            candidates.append(dec(s + "=" * (-len(s) % 4)))
        except (binascii.Error, ValueError):
            pass
    for c in candidates:
        if len(c) == KEY_LEN:
            return c
    raise KeyParseError(f"could not parse a {KEY_LEN}-byte key from input (hex, base64 or [int, ...])")


def key_crc(key: bytes) -> int:
    """CRC seed Hive uses for frame checksums of encrypted boxes."""
    return zlib.crc32(hashlib.sha256(key).digest())


def decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) < IV_LEN + 16 or (len(data) - IV_LEN) % 16:
        raise ValueError(f"encrypted value has invalid length {len(data)}")
    iv, ct = data[:IV_LEN], data[IV_LEN:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()
