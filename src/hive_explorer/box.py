"""Frame-level parser for Hive box files (append-only log of key/value frames)."""
import struct
import zlib
from pathlib import Path

from . import crypto
from .reader import BinaryReader, HiveParseError
from .types import BoxDump, Frame, Unknown
from .values import decode_value, read_key

# len(4) + string key with empty name(2) + crc(4)
MIN_FRAME_LEN = 10
# Hive rejects frames above this size
MAX_FRAME_LEN = 0x7FFFFFFF


def _frame_at(data: bytes, pos: int, seed: int) -> tuple[int, bool] | None:
    """Return (length, crc_ok) if a structurally valid frame starts at pos."""
    if len(data) - pos < MIN_FRAME_LEN:
        return None
    length = struct.unpack_from("<I", data, pos)[0]
    if length < MIN_FRAME_LEN or length > MAX_FRAME_LEN or pos + length > len(data):
        return None
    crc = struct.unpack_from("<I", data, pos + length - 4)[0]
    return length, zlib.crc32(data[pos:pos + length - 4], seed) == crc


def _resync(data: bytes, pos: int, seed: int) -> int | None:
    for p in range(pos + 1, len(data) - MIN_FRAME_LEN + 1):
        hit = _frame_at(data, p, seed)
        if hit and hit[1]:
            return p
    return None


def _scan(data: bytes, seed: int, recover: bool, errors: list[str]) -> list[tuple[int, int, bool]]:
    spans = []
    pos = 0
    while pos < len(data):
        hit = _frame_at(data, pos, seed)
        if hit is None:
            errors.append(f"invalid frame at offset {pos:#x} ({len(data) - pos} bytes left)")
            nxt = _resync(data, pos, seed) if recover else None
            if nxt is None:
                break
            errors.append(f"resynced at offset {nxt:#x} (skipped {nxt - pos} bytes)")
            pos = nxt
            continue
        length, crc_ok = hit
        spans.append((pos, length, crc_ok))
        pos += length
    return spans


def parse_box(path: str | Path, key: bytes | None = None, recover: bool = False) -> BoxDump:
    path = Path(path)
    data = path.read_bytes()
    dump = BoxDump(str(path), len(data), encrypted=key is not None)
    seed = crypto.key_crc(key) if key else 0
    spans = _scan(data, seed, recover, dump.errors)

    if spans and not any(ok for _, _, ok in spans):
        if key is None:
            dump.errors.append("CRC fails on every frame: box is likely encrypted, supply --key")
            dump.encrypted = True
        elif all(_frame_at(data, p, 0)[1] for p, _, _ in spans):
            # plaintext box among encrypted ones: parse without the key
            return parse_box(path, None, recover)
        else:
            dump.errors.append("CRC fails on every frame with the supplied key: wrong key")
            return dump

    for pos, length, crc_ok in spans:
        r = BinaryReader(data, pos + 4, pos + length - 4)
        try:
            k = read_key(r)
        except HiveParseError as e:
            dump.errors.append(f"frame {pos:#x}: {e}")
            continue
        frame = Frame(pos, length, k, crc_ok=crc_ok, encrypted=dump.encrypted)
        if not crc_ok and not (dump.encrypted and key is None):
            frame.error = "CRC mismatch"
        raw = r.read(r.remaining)
        if not raw:
            frame.deleted = True
        elif dump.encrypted and key is None:
            frame.value = Unknown(-1, raw)
        else:
            if key:
                try:
                    raw = crypto.decrypt(key, raw)
                except ValueError as e:
                    frame.value = Unknown(-1, raw)
                    frame.error = f"decryption failed: {e}"
                    dump.frames.append(frame)
                    continue
            frame.value, err = decode_value(raw)
            if err:
                frame.error = f"partial decode: {err}" if frame.error is None else f"{frame.error}; {err}"
        dump.frames.append(frame)
    return dump


def find_boxes(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            out.extend(sorted(x for x in p.rglob("*") if x.is_file() and x.suffix in (".hive", ".hivec")))
        else:
            out.append(p)
    return out
