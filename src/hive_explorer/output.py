import base64
import json
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.tree import Tree

from .types import BoxDump, Frame, HiveListRef, HiveObject, HiveSet, Unknown

HEX_PREVIEW = 64


def _printable_utf8(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if s and all(c.isprintable() or c in "\r\n\t" for c in s) else None


# ---------- JSON ----------

def to_jsonable(v: Any) -> Any:
    match v:
        case None | bool() | int() | float() | str():
            return v
        case bytes():
            out = {"__bytes_hex": v.hex(), "__bytes_b64": base64.b64encode(v).decode()}
            if (s := _printable_utf8(v)) is not None:
                out["__utf8"] = s
            return out
        case datetime():
            return v.isoformat()
        case HiveObject():
            return {"__type_id": v.type_id, "__user_type_id": v.user_type_id,
                    "fields": {str(k): to_jsonable(x) for k, x in v.fields.items()}}
        case Unknown():
            return {"__type_id": v.type_id, "__raw_hex": v.raw.hex()}
        case HiveSet():
            return {"__set": [to_jsonable(x) for x in v.items]}
        case HiveListRef():
            return {"__box": v.box, "__key": v.key}
        case dict():
            return {k if isinstance(k, str) else json.dumps(to_jsonable(k)): to_jsonable(x) for k, x in v.items()}
        case list() | tuple():
            return [to_jsonable(x) for x in v]
    return repr(v)


def _frame_json(f: Frame, status: str | None = None) -> dict:
    d = {"offset": f.offset, "length": f.length, "key": f.key, "crc_ok": f.crc_ok}
    if status:
        d["status"] = status
    if not f.deleted:
        d["value"] = to_jsonable(f.value)
    if f.error:
        d["error"] = f.error
    return d


def box_json(box: BoxDump, all_frames: bool) -> dict:
    entries = box.entries
    out = {
        "path": box.path,
        "size": box.size,
        "encrypted": box.encrypted,
        "frame_count": len(box.frames),
        "live_keys": len(entries),
        "deleted_frames": box.deleted_count,
        "errors": box.errors,
        "entries": {str(k): to_jsonable(f.value) for k, f in entries.items()},
    }
    if all_frames:
        out["frames"] = [_frame_json(f, frame_status(f, entries)) for f in box.frames]
    return out


def frame_status(f: Frame, entries: dict) -> str:
    if f.deleted:
        return "deleted"
    return "live" if entries.get(f.key) is f else "overwritten"


# ---------- rich ----------

def _hex(b: bytes, raw: bool) -> str:
    if raw or len(b) <= HEX_PREVIEW:
        return b.hex()
    return f"{b[:HEX_PREVIEW].hex()}… (+{len(b) - HEX_PREVIEW} bytes)"


def _scalar(v: Any, raw: bool) -> str | None:
    match v:
        case None:
            return "[dim]null[/]"
        case bool():
            return f"[magenta]{v}[/]"
        case int() | float():
            return f"[cyan]{v}[/]"
        case str():
            return f"[green]{escape(json.dumps(v, ensure_ascii=False))}[/]"
        case datetime():
            return f"[yellow]{v.isoformat()}[/]"
        case bytes():
            s = _printable_utf8(v)
            extra = f"  [dim]utf8:[/] [green]{escape(json.dumps(s, ensure_ascii=False))}[/]" if s else ""
            return f"[blue]bytes[{len(v)}][/] {_hex(v, raw)}{extra}"
        case HiveListRef():
            return f"[blue]→ {escape(v.box)}[{escape(repr(v.key))}][/]"
        case Unknown():
            what = "encrypted/undecoded" if v.type_id < 0 else f"undecoded typeId={v.type_id}"
            return f"[red]{what}[/] {_hex(v.raw, raw)}"
    return None


def _key_label(k: int | str) -> str:
    return f"[bold]{escape(json.dumps(k, ensure_ascii=False))}[/]"


def _add(tree: Tree, label: str, v: Any, raw: bool) -> None:
    if (s := _scalar(v, raw)) is not None:
        tree.add(f"{label}: {s}")
        return
    match v:
        case dict():
            node = tree.add(f"{label} [dim]Map({len(v)})[/]")
            for k, x in v.items():
                label = _key_label(k) if isinstance(k, (int, str)) else f"[bold]{escape(repr(k))}[/]"
                _add(node, label, x, raw)
        case list() | tuple():
            node = tree.add(f"{label} [dim]List({len(v)})[/]")
            for i, x in enumerate(v):
                _add(node, f"[dim]\\[{i}][/]", x, raw)
        case HiveSet():
            node = tree.add(f"{label} [dim]Set({len(v.items)})[/]")
            for x in v.items:
                _add(node, "[dim]·[/]", x, raw)
        case HiveObject():
            node = tree.add(f"{label} [blue]HiveObject typeId={v.user_type_id}[/] [dim](raw {v.type_id})[/]")
            for idx, x in v.fields.items():
                _add(node, f"[dim]field[/] {idx}", x, raw)
        case _:
            tree.add(f"{label}: {escape(repr(v))}")


def render_box(console: Console, box: BoxDump, all_frames: bool, raw: bool) -> None:
    entries = box.entries
    enc = " [red]encrypted[/]" if box.encrypted else ""
    tree = Tree(
        f"[bold underline]{escape(box.path)}[/]{enc} [dim]{box.size} B · {len(box.frames)} frames · "
        f"{len(entries)} live · {box.deleted_count} deleted[/]"
    )
    for err in box.errors:
        tree.add(f"[red]! {escape(err)}[/]")
    for k, f in entries.items():
        _add(tree, _key_label(k), f.value, raw)
        if f.error:
            tree.add(f"  [red]! {escape(str(k))}: {escape(f.error)}[/]")
    console.print(tree)

    if all_frames:
        t = Table("offset", "key", "status", "crc", "value", title="frames", show_lines=False)
        style = {"live": "green", "overwritten": "yellow", "deleted": "red"}
        for f in box.frames:
            st = frame_status(f, entries)
            val = "" if f.deleted else escape(json.dumps(to_jsonable(f.value), ensure_ascii=False))
            if not raw and len(val) > 120:
                val = val[:120] + "…"
            t.add_row(f"{f.offset:#x}", escape(str(f.key)), f"[{style[st]}]{st}[/]",
                      "ok" if f.crc_ok else "[red]bad[/]", val)
        console.print(t)
    console.print()


def render_info(console: Console, boxes: list[BoxDump]) -> None:
    t = Table("box", "size", "frames", "live", "deleted", "encrypted", "custom typeIds", "errors")
    for b in boxes:
        ids = ", ".join(str(i - 32) if i >= 32 else f"raw:{i}" for i in sorted(b.custom_type_ids)) or "-"
        t.add_row(escape(b.path), str(b.size), str(len(b.frames)), str(len(b.entries)),
                  str(b.deleted_count), "yes" if b.encrypted else "no", ids,
                  f"[red]{len(b.errors)}[/]" if b.errors else "0")
    console.print(t)
