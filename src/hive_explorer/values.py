"""Decoder for Hive's typed value encoding (BinaryWriterImpl.write)."""
from datetime import datetime, timedelta, timezone
from typing import Any

from .reader import BinaryReader, HiveParseError
from .types import RESERVED_TYPE_IDS, HiveListRef, HiveObject, HiveSet, Unknown

NULL, INT, DOUBLE, BOOL, STRING, BYTE_LIST = 0, 1, 2, 3, 4, 5
INT_LIST, DOUBLE_LIST, BOOL_LIST, STRING_LIST, LIST, MAP, HIVE_LIST = 6, 7, 8, 9, 10, 11, 12
INT_SET, DOUBLE_SET, STRING_SET = 13, 14, 15
DATETIME, BIGINT, DATETIME_TZ = 16, 17, 18
# hive_ce: type ids that don't fit a byte are written as 0xFF + uint16
EXTENDED_TYPE_ID = 0xFF

KEY_INT, KEY_STRING = 0, 1

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _int(r: BinaryReader) -> int | float:
    # Dart ints are serialized as float64
    v = r.f64()
    return int(v) if v.is_integer() else v


def _str(r: BinaryReader) -> str:
    return r.utf8(r.u32())


def _datetime(ms: int | float) -> datetime | int | float:
    try:
        return _EPOCH + timedelta(milliseconds=ms)
    except (OverflowError, ValueError):
        return ms


def read_key(r: BinaryReader) -> int | str:
    kind = r.u8()
    if kind == KEY_INT:
        return r.u32()
    if kind == KEY_STRING:
        raw = r.read(r.u8())
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    raise HiveParseError(f"unknown key type {kind} at offset {r.pos - 1}")


def read_type_id(r: BinaryReader) -> int:
    tid = r.u8()
    return r.u16() if tid == EXTENDED_TYPE_ID else tid


def read_value(r: BinaryReader) -> Any:
    tid = read_type_id(r)
    match tid:
        case 0:
            return None
        case 1:
            return _int(r)
        case 2:
            return r.f64()
        case 3:
            return r.u8() != 0
        case 4:
            return _str(r)
        case 5:
            return r.read(r.u32())
        case 6:
            return [_int(r) for _ in range(r.u32())]
        case 7:
            return [r.f64() for _ in range(r.u32())]
        case 8:
            return [r.u8() != 0 for _ in range(r.u32())]
        case 9:
            return [_str(r) for _ in range(r.u32())]
        case 10:
            return [read_value(r) for _ in range(r.u32())]
        case 11:
            return {_hashable(read_value(r)): read_value(r) for _ in range(r.u32())}
        case 12:
            n = r.u32()
            box = r.read(r.u8()).decode("latin-1")
            return [HiveListRef(box, read_key(r)) for _ in range(n)]
        case 13:
            return HiveSet([_int(r) for _ in range(r.u32())])
        case 14:
            return HiveSet([r.f64() for _ in range(r.u32())])
        case 15:
            return HiveSet([_str(r) for _ in range(r.u32())])
        case 16:
            return _datetime(_int(r))
        case 17:
            return int(r.utf8(r.u8()))
        case 18:
            ms = _int(r)
            r.u8()  # isUtc
            return _datetime(ms)
        case _ if tid >= RESERVED_TYPE_IDS:
            return _read_generated_object(r, tid)
        case _:
            raise HiveParseError(f"unsupported built-in type id {tid} at offset {r.pos - 1}")


def _read_generated_object(r: BinaryReader, tid: int) -> HiveObject:
    # hive_generator layout: writeByte(nFields) then (writeByte(index), write(value))*
    n = r.u8()
    fields = {}
    for _ in range(n):
        idx = r.u8()
        fields[idx] = read_value(r)
    return HiveObject(tid, fields)


def _hashable(v: Any) -> Any:
    if isinstance(v, list):
        return tuple(_hashable(x) for x in v)
    if isinstance(v, dict):
        return tuple((k, _hashable(x)) for k, x in v.items())
    if isinstance(v, (HiveObject, HiveSet, HiveListRef, Unknown)):
        return repr(v)
    return v


def decode_value(data: bytes) -> tuple[Any, str | None]:
    """Decode a full frame value. Falls back to Unknown when the bytes can't be
    consumed exactly (hand-written adapters, generated enums, unknown ids)."""
    r = BinaryReader(data)
    try:
        v = read_value(r)
        if r.remaining:
            raise HiveParseError(f"{r.remaining} trailing bytes after value")
        return v, None
    except HiveParseError as e:
        if not data:
            return Unknown(-1, b""), "empty value"
        rr = BinaryReader(data)
        try:
            tid = read_type_id(rr)
        except HiveParseError:
            tid, rr.pos = data[0], 1
        return Unknown(tid, data[rr.pos:]), str(e)
