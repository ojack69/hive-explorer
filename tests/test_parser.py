import base64
import json
import struct
from datetime import datetime, timezone

import pytest

from hive_explorer.box import parse_box
from hive_explorer.cli import main
from hive_explorer.crypto import parse_key
from hive_explorer.types import HiveObject, Unknown

from hive_writer import Obj, Raw, f64, frame

KEY = bytes(range(32))


@pytest.fixture
def write(tmp_path):
    def _w(*frames, name="box.hive"):
        p = tmp_path / name
        p.write_bytes(b"".join(frames))
        return p
    return _w


def test_scalars_and_collections(write):
    vals = {
        "null": None, "int": 42, "neg": -7, "double": 3.5, "bool": True, "str": "héllo",
        "bytes": b"\x00\x01secret", "strlist": ["a", "b"], "intlist": [1, 2, 3],
        "list": [1, "x", None], "map": {"token": "eyJ...", "n": 1, 5: [1.5]},
    }
    box = parse_box(write(*(frame(k, v) for k, v in vals.items())))
    assert not box.errors
    assert {k: f.value for k, f in box.entries.items()} == vals


def test_int_keys_override_delete(write):
    box = parse_box(write(frame(0, "a"), frame(1, "b"), frame(0, "a2"), frame(1)))
    assert {k: f.value for k, f in box.entries.items()} == {0: "a2"}
    assert box.deleted_count == 1
    assert len(box.frames) == 4


def test_builtin_adapters(write):
    ms = 1_700_000_000_000
    box = parse_box(write(
        frame("dt", Raw(16, f64(ms))),
        frame("dttz", Raw(18, f64(ms) + b"\x01")),
        frame("big", Raw(17, bytes([5]) + b"12345")),
        frame("set", Raw(15, struct.pack("<I", 1) + struct.pack("<I", 1) + b"z")),
        frame("hl", Raw(12, struct.pack("<I", 2) + b"\x05users" + b"\x00\x01\x00\x00\x00" + b"\x01\x01k")),
    ))
    e = box.entries
    expected = datetime.fromtimestamp(ms / 1000, timezone.utc)
    assert e["dt"].value == expected and e["dttz"].value == expected
    assert e["big"].value == 12345
    assert e["set"].value.items == ["z"]
    assert [(r.box, r.key) for r in e["hl"].value] == [("users", 1), ("users", "k")]


def test_generated_object(write):
    user = Obj(3, {0: "alice", 1: 30, 2: Obj(4, {0: ["admin"]})})
    box = parse_box(write(frame("u", user)))
    v = box.entries["u"].value
    assert isinstance(v, HiveObject) and v.user_type_id == 3
    assert v.fields[0] == "alice" and v.fields[2].fields[0] == ["admin"]
    assert box.custom_type_ids == {35, 36}


def test_undecodable_custom_falls_back(write):
    # generated enum adapter writes a single index byte -> not the object layout
    box = parse_box(write(frame("e", Raw(40, b"\x05")), frame("after", "ok")))
    v = box.entries["e"].value
    assert isinstance(v, Unknown) and v.type_id == 40 and v.raw == b"\x05"
    assert box.entries["after"].value == "ok"


def test_corrupt_tail_and_recover(write):
    good, bad = frame("a", 1), bytearray(frame("b", 2))
    bad[-1] ^= 0xFF
    p = write(good, bytes(bad), b"\xde\xad\xbe\xef\x00", frame("c", 3))
    box = parse_box(p)
    assert box.entries["a"].value == 1
    assert not box.entries["b"].crc_ok
    assert box.errors and "c" not in box.entries
    assert parse_box(p, recover=True).entries["c"].value == 3


def test_encrypted(write):
    p = write(frame("tok", "s3cr3t", KEY), frame(7, {"a": 1}, KEY, iv=b"\x22" * 16))
    plain = parse_box(p)
    assert plain.encrypted and "likely encrypted" in plain.errors[0]
    box = parse_box(p, KEY)
    assert not box.errors
    assert box.entries["tok"].value == "s3cr3t" and box.entries[7].value == {"a": 1}
    wrong = parse_box(p, bytes(32))
    assert "wrong key" in wrong.errors[0] and not wrong.frames


def test_key_ignored_for_plaintext_box(write):
    box = parse_box(write(frame("a", 1)), KEY)
    assert not box.errors and not box.encrypted and box.entries["a"].value == 1


def test_parse_key_formats():
    assert parse_key(KEY.hex()) == KEY
    assert parse_key(base64.b64encode(KEY).decode()) == KEY
    assert parse_key(base64.urlsafe_b64encode(KEY).decode().rstrip("=")) == KEY
    assert parse_key(str(list(KEY))) == KEY


def test_cli_json(write, capsys):
    p = write(frame("k", b"\xff\x00"), frame("k2", "v"), frame("k2"))
    assert main(["dump", str(p), "--json", "--all-frames"]) == 0
    doc = json.loads(capsys.readouterr().out)[0]
    assert doc["entries"] == {"k": {"__bytes_hex": "ff00", "__bytes_b64": "/wA="}}
    assert [f["status"] for f in doc["frames"]] == ["live", "overwritten", "deleted"]


def test_cli_pretty_and_info(write, capsys):
    p = write(frame("u", Obj(1, {0: "x"})), frame("e", Raw(40, b"\x05")))
    assert main(["dump", str(p.parent), "--all-frames"]) == 0
    assert main(["info", str(p)]) == 0
    out = capsys.readouterr().out
    assert "HiveObject typeId=1" in out and "undecoded typeId=40" in out
