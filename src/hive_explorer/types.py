from dataclasses import dataclass, field
from typing import Any

# Hive reserves type ids 0..31 for built-ins; user adapters are stored as typeId + 32.
RESERVED_TYPE_IDS = 32


@dataclass
class HiveObject:
    """Custom object decoded with the hive_generator layout (nFields, (idx, value)*)."""
    type_id: int
    fields: dict[int, Any]

    @property
    def user_type_id(self) -> int:
        return self.type_id - RESERVED_TYPE_IDS


@dataclass
class Unknown:
    """Value whose adapter layout could not be inferred; raw holds the undecoded bytes."""
    type_id: int
    raw: bytes


@dataclass
class HiveSet:
    items: list


@dataclass
class HiveListRef:
    """HiveList entry: reference to a key in another box."""
    box: str
    key: int | str


@dataclass
class Frame:
    offset: int
    length: int
    key: int | str
    value: Any = None
    deleted: bool = False
    crc_ok: bool = True
    encrypted: bool = False
    error: str | None = None


@dataclass
class BoxDump:
    path: str
    size: int
    frames: list[Frame] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    encrypted: bool = False

    @property
    def entries(self) -> dict[int | str, Frame]:
        """Final box state: last frame per key wins, deletes remove the key."""
        out: dict[int | str, Frame] = {}
        for f in self.frames:
            if f.deleted:
                out.pop(f.key, None)
            else:
                out[f.key] = f
        return out

    @property
    def deleted_count(self) -> int:
        return sum(f.deleted for f in self.frames)

    @property
    def custom_type_ids(self) -> set[int]:
        ids: set[int] = set()

        def walk(v):
            if isinstance(v, (HiveObject, Unknown)) and v.type_id >= 0:
                ids.add(v.type_id)
            if isinstance(v, HiveObject):
                for x in v.fields.values():
                    walk(x)
            elif isinstance(v, dict):
                for k, x in v.items():
                    walk(k)
                    walk(x)
            elif isinstance(v, (list, tuple)):
                for x in v:
                    walk(x)
            elif isinstance(v, HiveSet):
                walk(v.items)

        for f in self.frames:
            walk(f.value)
        return ids
