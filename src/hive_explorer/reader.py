import struct


class HiveParseError(Exception):
    pass


class BinaryReader:
    """Bounds-checked little-endian reader over a bytes buffer."""

    def __init__(self, data: bytes, offset: int = 0, end: int | None = None):
        self.data = data
        self.pos = offset
        self.end = len(data) if end is None else end

    @property
    def remaining(self) -> int:
        return self.end - self.pos

    def read(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise HiveParseError(f"read of {n} bytes at offset {self.pos} past end ({self.end})")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def f64(self) -> float:
        return struct.unpack("<d", self.read(8))[0]

    def utf8(self, n: int) -> str:
        raw = self.read(n)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise HiveParseError(f"invalid UTF-8 at offset {self.pos - n}: {e}") from None
