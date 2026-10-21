import argparse
import json
import sys

from rich.console import Console

from .box import find_boxes, parse_box
from .crypto import KeyParseError, parse_key
from .output import box_json, render_box, render_info


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hive-explorer", description="Dump Flutter Hive (.hive) box files")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("paths", nargs="+", help=".hive file(s) or directories (recursed for *.hive)")
    common.add_argument("--key", help="HiveAesCipher key: 32 bytes as hex, base64 or [int, ...]")
    common.add_argument("--recover", action="store_true", help="resync past corrupt frames instead of stopping")

    d = sub.add_parser("dump", parents=[common], help="dump box contents")
    d.add_argument("--json", nargs="?", const="-", metavar="FILE", help="write JSON (stdout if FILE omitted)")
    d.add_argument("--all-frames", action="store_true", help="include overwritten and deleted frames")
    d.add_argument("--raw", action="store_true", help="don't truncate hex / long values")

    sub.add_parser("info", parents=[common], help="per-box summary")

    args = ap.parse_args(argv)
    err = Console(stderr=True)

    key = None
    if args.key:
        try:
            key = parse_key(args.key)
        except KeyParseError as e:
            err.print(f"[red]{e}[/]")
            return 2

    paths = find_boxes(args.paths)
    if not paths:
        err.print("[red]no .hive files found[/]")
        return 1

    boxes = []
    for p in paths:
        try:
            boxes.append(parse_box(p, key, args.recover))
        except OSError as e:
            err.print(f"[red]{p}: {e}[/]")

    if args.cmd == "info":
        render_info(Console(), boxes)
    elif args.json:
        doc = json.dumps([box_json(b, args.all_frames) for b in boxes], indent=2, ensure_ascii=False)
        if args.json == "-":
            print(doc)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(doc + "\n")
            err.print(f"wrote {args.json}")
    else:
        console = Console()
        for b in boxes:
            render_box(console, b, args.all_frames, args.raw)
    return 1 if any(b.errors for b in boxes) else 0


if __name__ == "__main__":
    sys.exit(main())
