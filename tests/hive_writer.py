"""Minimal Hive writer mirroring BinaryWriterImpl, used to build test fixtures."""
import struct
import zlib
from dataclasses import dataclass

from hive_explorer import crypto


@dataclass
class Obj:
    """Generated-adapter object; type_id is the user typeId (0..223)."""
    type_id: int
    fields: dict


@dataclass
class Raw:
    """Arbitrary adapter output: on-disk type id + payload."""
    type_id: int
    payload: bytes


def f64(v) -> bytes:
    return struct.pack("<d", float(v))


def s(v: str) -> bytes:
    b = v.encode()
    return struct.pack("<I", len(b)) + b


def key(k) -> bytes:
    if isinstance(k, int):
        return b"\x00" + struct.pack("<I", k)
    b = k.encode()
    return b"\x01" + bytes([len(b)]) + b


def value(v) -> bytes:
    n = lambda x: struct.pack("<I", len(x))
    match v:
        case None:
            return b"\x00"
        case bool():
            return b"\x03" + bytes([v])
        case int():
            return b"\x01" + f64(v)
        case float():
            return b"\x02" + f64(v)
        case str():
            return b"\x04" + s(v)
        case bytes():
            return b"\x05" + n(v) + v
        case list() if v and all(isinstance(x, str) for x in v):
            return b"\x09" + n(v) + b"".join(s(x) for x in v)
        case list() if v and all(type(x) is int for x in v):
            return b"\x06" + n(v) + b"".join(f64(x) for x in v)
        case list():
            return b"\x0a" + n(v) + b"".join(value(x) for x in v)
        case dict():
            return b"\x0b" + n(v) + b"".join(value(k) + value(x) for k, x in v.items())
        case Obj():
            body = bytes([len(v.fields)]) + b"".join(bytes([i]) + value(x) for i, x in v.fields.items())
            return bytes([v.type_id + 32]) + body
        case Raw():
            return bytes([v.type_id]) + v.payload
    raise TypeError(v)


def frame(k, v=..., enc_key: bytes | None = None, iv: bytes = b"\x11" * 16) -> bytes:
    body = key(k)
    if v is not ...:
        val = value(v)
        body += crypto.encrypt(enc_key, val, iv) if enc_key else val
    length = 4 + len(body) + 4
    head = struct.pack("<I", length) + body
    seed = crypto.key_crc(enc_key) if enc_key else 0
    return head + struct.pack("<I", zlib.crc32(head, seed))
