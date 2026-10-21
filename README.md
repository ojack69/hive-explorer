# flutter-hive-explorer

Parse and dump Flutter [Hive](https://pub.dev/packages/hive) / [hive_ce](https://pub.dev/packages/hive_ce) box files (`*.hive`) offline, including encrypted boxes and overwritten/deleted records that are still on disk.

Typical locations once pulled from a device:

- Android: `/data/data/<pkg>/app_flutter/*.hive`
- iOS: `<app container>/Documents/*.hive`

## Install

```sh
uv sync
uv run hive-explorer --help
```

## Usage

```
hive-explorer dump <file|dir...> [--key K] [--json [FILE]] [--all-frames] [--raw] [--recover]
hive-explorer info <file|dir...> [--key K] [--recover]
```

Directories are searched recursively for `*.hive` and `*.hivec`. The exit code is 1 if any box had parse errors.

### Summarise every box in a pulled app directory

```sh
uv run hive-explorer info ./app_flutter
```

Prints one row per box: size, frame count, live keys, deleted frames, whether it's encrypted, the custom type IDs it uses, and the error count.

### Dump the current contents of a box

```sh
uv run hive-explorer dump ./app_flutter/session.hive
```

```
./app_flutter/session.hive 175 B · 5 frames · 2 live · 1 deleted
├── "jwt": "eyJnew.a.b"
└── "user" HiveObject typeId=2 (raw 34)
    ├── field 0: "alice"
    └── field 1 Map(2)
        ├── "roles" List(1)
        │   └── [0]: "admin"
        └── "pin": 1234
```

### Recover overwritten and deleted values

Hive only appends to the file, so old and deleted values remain until the box is compacted. `--all-frames` adds a table of every record with its offset and status (`live`, `overwritten` or `deleted`):

```sh
uv run hive-explorer dump ./app_flutter/session.hive --all-frames
```

```
│ 0x0    │ jwt  │ overwritten │ ok  │ "eyJhbGciOi.x.y"                                   │
│ 0x6a   │ jwt  │ live        │ ok  │ "eyJnew.a.b"                                       │
│ 0x86   │ tmp  │ overwritten │ ok  │ {"__bytes_hex": "70773d...", "__utf8": "pw=hunter2"} │
│ 0xa2   │ tmp  │ deleted     │ ok  │                                                    │
```

Add `--raw` to stop long values and hex from being truncated.

### Encrypted boxes

Boxes opened with `HiveAesCipher` need the 32-byte key, which apps usually keep in `flutter_secure_storage`. The key can be hex, base64/base64url, or a Dart list literal:

```sh
uv run hive-explorer dump vault.hive --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
uv run hive-explorer dump vault.hive --key 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
uv run hive-explorer dump vault.hive --key '[0, 1, 2, 3, ..., 31]'
```

- The key is checked against the frame checksums, so a wrong key reports `wrong key` instead of printing garbage.
- Without a key, an encrypted box is detected and its values are shown as raw encrypted bytes.
- Passing a key for a directory that mixes encrypted and plain boxes is fine: plain boxes are read without it.

### JSON export

```sh
uv run hive-explorer dump ./app_flutter --json > dump.json
uv run hive-explorer dump ./app_flutter --json dump.json --all-frames

# every live entry of every box
jq '.[] | {path, entries}' dump.json
# string values that look like JWTs, including overwritten/deleted ones
jq -r '.[].frames[]? | select(.value|type=="string" and startswith("eyJ")) | "\(.status)\t\(.key)\t\(.value)"' dump.json
```

How values map to JSON:

| Hive value | JSON |
|---|---|
| `Uint8List` | `{"__bytes_hex", "__bytes_b64", "__utf8"?}` (`__utf8` only when the bytes are printable text) |
| `DateTime` | ISO 8601 string (UTC) |
| custom object | `{"__type_id", "__user_type_id", "fields": {"<index>": value}}` |
| undecodable / encrypted value | `{"__type_id", "__raw_hex"}` (`__type_id` is `-1` when encrypted) |
| `Set` | `{"__set": [...]}` |
| `HiveList` entry | `{"__box", "__key"}` |
| non-string map key | JSON-encoded as a string |

### Corrupt or truncated files

By default parsing stops at the first record that isn't structurally valid, the same way Hive does when it opens a box. `--recover` skips ahead to the next record with a valid checksum and keeps going:

```sh
uv run hive-explorer dump broken.hive --recover
```

Records whose checksum fails but whose structure is intact are still decoded and flagged `crc: bad`.

## Limitations

- **Custom objects:** decoded assuming the standard `hive_generator` layout. Field names aren't stored in the file, so fields appear by index. Hand-written adapters and generated enums fall back to raw hex for that value only; later records still parse. An enum with index 0 shows up as an empty object.
- **Encryption:** assumes Hive 2.x / hive_ce, i.e. AES-256-CBC/PKCS7 with a 16-byte IV stored in front of each value. Hive 1.x boxes may use a different scheme and won't decrypt.
- **hive_ce extras:** the set types (IDs 13–15) and the encoding for type IDs above 223 are best-effort. If they don't match, those values fall back to raw hex.

## Tests

```sh
uv run pytest
```

The tests build fixtures with `tests/hive_writer.py`, a small Python Hive writer.
