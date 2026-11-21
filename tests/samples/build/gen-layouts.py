#!/usr/bin/env python3
"""Generates `src/upstream/layouts.rs`: how every Inno Setup release whose
source is available lays out the setup-0 records, read from that release's
own `Struct.pas` / `Shared.Struct.pas`.

`SECompressedBlockWrite` (every release from 1.3 on) writes a record as its
`String` fields (u32 byte length + data), then its `AnsiString` fields
(likewise), then the remaining `SizeOf(record) - fields * SizeOf(Pointer)`
bytes of the packed record verbatim. 1.2.x (`SEDeflateBlockWrite`) writes the
same, `PChar` fields for strings, after a u32 holding the size of the rest. So for each record and each SetupID
marker this script emits:

  - the string fields in declaration order, with their kind,
  - the size of the raw tail: the packed size of every other field,
  - every named `set` field: its byte offset within the tail and its
    members in order, which is the bit order on disk,
  - every enumerated field, likewise: member `i` is the stored byte `i`.

A release is evaluated once per build it shipped as: ANSI (`Char` is one
byte, `{$IFNDEF UNICODE}` blocks kept) for everything before 6.0, Unicode
(`Char` is two bytes, `{$IFDEF UNICODE}` blocks kept) from 5.2.5, the first
`(u)` marker, and for 1.2.x a 32-bit (`WIN32` defined) and a 16-bit build
(Delphi 1: `Integer` and `Cardinal` are two bytes, a three-byte set is not
rounded up to four, `{$IFNDEF WIN32}` blocks kept). Where a release defines `Setup*Strings` / `Setup*AnsiStrings`
constants, the parsed string counts must match them, a check on this parser.

Usage:

  gen-layouts.py <issrc checkout> <directory of unzipped archives> > out.rs
  gen-layouts.py --fields <issrc> <archives> <origin> <TRecord> ansi|unicode|16bit

The second form prints one record's tail field by field (offset, size,
type) for one source, e.g. `issrc-4.1.0` or `is-6_5_2`.

where the second directory holds one `issrc-<version>/Struct.pas` per
`issrc-<version>.zip` from files.jrsoftware.org/is/<major>/ (1.2.16's, from
/is/1.2/, is `PROJECTS/STRUCT.PAS` in its archive).

Releases that share a SetupID normally lay out every record the same way.
Flags appended to a set within its existing bytes do not change the layout
(the older release just never sets them), so such releases share one
variant listing the longer set. When a later release changed a record in a
way that does, the marker gets one variant per layout, in release order, so
the ambiguity is recorded rather than hidden.
"""

import pathlib
import re
import subprocess
import sys

RECORDS = [
    "TSetupHeader",
    "TSetupLanguageEntry",
    "TSetupCustomMessageEntry",
    "TSetupPermissionEntry",
    "TSetupTypeEntry",
    "TSetupComponentEntry",
    "TSetupTaskEntry",
    "TSetupDirEntry",
    "TSetupISSigKeyEntry",
    "TSetupFileEntry",
    "TSetupFileLocationEntry",
    "TSetupIconEntry",
    "TSetupIniEntry",
    "TSetupRegistryEntry",
    "TSetupDeleteEntry",
    "TSetupRunEntry",
]

# Upstream's string-count constants, by record.
COUNT_CONSTS = {
    "TSetupHeader": "SetupHeader",
    "TSetupLanguageEntry": "SetupLanguageEntry",
    "TSetupCustomMessageEntry": "SetupCustomMessageEntry",
    "TSetupPermissionEntry": "SetupPermissionEntry",
    "TSetupTypeEntry": "SetupTypeEntry",
    "TSetupComponentEntry": "SetupComponentEntry",
    "TSetupTaskEntry": "SetupTaskEntry",
    "TSetupDirEntry": "SetupDirEntry",
    "TSetupISSigKeyEntry": "SetupISSigKeyEntry",
    "TSetupFileEntry": "SetupFileEntry",
    "TSetupFileLocationEntry": "SetupFileLocationEntry",
    "TSetupIconEntry": "SetupIconEntry",
    "TSetupIniEntry": "SetupIniEntry",
    "TSetupRegistryEntry": "SetupRegistryEntry",
    "TSetupDeleteEntry": "SetupDeleteEntry",
    "TSetupRunEntry": "SetupRunEntry",
}

STRING_TYPES = {"string": "Str", "unicodestring": "Str", "ansistring": "Ansi", "pchar": "Str"}

# Delphi 1, the 16-bit compiler of 1.2.x, where these are two bytes.
SCALARS_16 = {"integer": 2, "cardinal": 2}

# Sizes of the scalar types the records use, in the 32-bit compilers that
# write every format. `Char` depends on the build and is handled apart.
SCALARS = {
    "byte": 1, "shortint": 1, "boolean": 1, "bytebool": 1, "ansichar": 1,
    "word": 2, "smallint": 2, "wordbool": 2, "widechar": 2,
    "integer": 4, "longint": 4, "cardinal": 4, "longword": 4, "dword": 4,
    "uint32": 4, "int32": 4, "longbool": 4, "hkey": 4, "tcolor": 4, "lcid": 4,
    "int64": 8, "uint64": 8, "integer64": 8, "tfiletime": 8, "single": 4,
    "double": 8,
    # From units other than Struct.pas.
    "tmd5digest": 16, "tsha1digest": 20, "tsha256digest": 32, "tguid": 16,
}


class Unsupported(Exception):
    pass


def preprocess(text: str, defines: set[str]) -> str:
    """Evaluates `{$IFDEF}` / `{$IFNDEF}` / `{$ELSE}` / `{$ENDIF}` against
    `defines` and strips comments and other directives."""
    out = []
    keep = [True]
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "'":
            j = text.index("'", i + 1)
            if keep[-1]:
                out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("{$", i):
            j = text.index("}", i)
            body = text[i + 2:j].strip().split()
            name = body[0].upper() if body else ""
            arg = body[1].upper() if len(body) > 1 else ""
            if name == "IFDEF":
                keep.append(keep[-1] and arg in defines)
            elif name == "IFNDEF":
                keep.append(keep[-1] and arg not in defines)
            elif name == "ELSE":
                parent = keep[-2] if len(keep) > 1 else True
                keep[-1] = parent and not keep[-1]
            elif name == "ENDIF":
                keep.pop()
            i = j + 1
        elif c == "{":
            i = text.index("}", i) + 1
        elif text.startswith("(*", i):
            i = text.index("*)", i) + 2
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        else:
            if keep[-1]:
                out.append(c)
            i += 1
    return "".join(out)


class Types:
    def __init__(self, text: str, unicode: bool, bits16: bool = False):
        self.unicode = unicode
        self.bits16 = bits16
        self.decls: dict[str, str] = {}
        self.consts: dict[str, int] = {}
        for m in re.finditer(r"\b(\w+)\s*=\s*(packed\s+)?record\b(.*?)\bend\s*;", text, re.S | re.I):
            self.decls[m.group(1).lower()] = ("record", bool(m.group(2)), m.group(3))
        rest = re.sub(r"\b\w+\s*=\s*(packed\s+)?record\b.*?\bend\s*;", ";", text, flags=re.S | re.I)
        for m in re.finditer(r"\b(\w+)\s*=\s*([^;]+);", rest):
            name, body = m.group(1).lower(), m.group(2).strip()
            if name not in self.decls:
                self.decls[name] = ("alias", False, body)
            if re.fullmatch(r"\d+", body):
                self.consts[name] = int(body)

    def ordinal_range(self, spec: str) -> tuple[int, int, list[str]]:
        """Ordinal bounds and member names of an enum or subrange."""
        spec = spec.strip()
        if spec.startswith("("):
            members, value, top = [], -1, 0
            for part in spec[1:spec.rindex(")")].split(","):
                part = part.strip()
                if "=" in part:
                    name, v = part.split("=")
                    value = self.int(v)
                    name = name.strip()
                else:
                    name = part
                    value += 1
                members.append((value, name))
                top = max(top, value)
            ordered = [n for _, n in sorted(members)]
            return 0, top, ordered
        if ".." in spec:
            lo, hi = spec.split("..")
            return self.int(lo), self.int(hi), []
        key = spec.lower()
        if key in ("boolean",):
            return 0, 1, ["False", "True"]
        if key in ("ansichar", "byte") or (key == "char" and not self.unicode):
            return 0, 255, []
        if key == "char":
            return 0, 65535, []
        kind, _, body = self.decls.get(key, (None, None, None))
        if kind == "alias":
            return self.ordinal_range(body)
        raise Unsupported(f"ordinal type {spec}")

    def int(self, s: str) -> int:
        s = s.strip()
        if re.fullmatch(r"-?\d+", s):
            return int(s)
        if s.lower() in self.consts:
            return self.consts[s.lower()]
        raise Unsupported(f"constant {s}")

    def size(self, spec: str) -> int:
        spec = spec.strip()
        low = spec.lower()
        if self.bits16 and low in SCALARS_16:
            return SCALARS_16[low]
        if low in SCALARS:
            return SCALARS[low]
        if low == "char":
            return 2 if self.unicode else 1
        if low.startswith("(") or (".." in low and not low.startswith("array")):
            lo, hi, _ = self.ordinal_range(spec)
            return 1 if hi < 256 else 2 if hi < 65536 else 4
        m = re.fullmatch(r"(packed\s+)?set\s+of\s+(.+)", spec, re.S | re.I)
        if m:
            lo, hi, _ = self.ordinal_range(m.group(2))
            n = hi // 8 - lo // 8 + 1
            # The 32-bit Delphi rounds a three-byte set up to four.
            return 4 if n == 3 and not self.bits16 else n
        m = re.fullmatch(r"array\s*\[(.+?)\]\s*of\s+(.+)", spec, re.S | re.I)
        if m:
            count = 1
            for dim in m.group(1).split(","):
                lo, hi, _ = self.ordinal_range(dim)
                count *= hi - lo + 1
            return count * self.size(m.group(2))
        if low in self.decls:
            kind, packed, body = self.decls[low]
            if kind == "alias":
                return self.size(body)
            return self.record_size(body, packed)
        raise Unsupported(f"type {spec}")

    def fields(self, body: str) -> list[tuple[str, str]]:
        out = []
        for decl in split_top(body, ";"):
            if ":" not in decl:
                continue
            names, spec = decl.split(":", 1)
            for name in names.split(","):
                out.append((name.strip(), " ".join(spec.split())))
        return out

    def record_size(self, body: str, packed: bool) -> int:
        total, align_max = 0, 1
        for _, spec in self.fields(body):
            if spec.lower() in STRING_TYPES:
                size, align = 4, 4
            else:
                size = self.size(spec)
                align = min(size, 8) if size in (1, 2, 4, 8) else 1
            if not packed and total % align:
                total += align - total % align
            total += size
            align_max = max(align_max, align)
        if not packed and total % align_max:
            total += align_max - total % align_max
        return total

    def flat(self, body: str, prefix: str = "") -> list[tuple[str, str]]:
        """The record's fields with nested records expanded, since
        `SECompressedBlockWrite` sees only the record's memory."""
        out = []
        for name, spec in self.fields(body):
            low = spec.lower()
            if low in self.decls and self.decls[low][0] == "record":
                out.extend(self.flat(self.decls[low][2], f"{prefix}{name}."))
            else:
                out.append((prefix + name, spec))
        return out

    def layout(self, record: str):
        _, _, body = self.decls[record.lower()]
        strings, tail, sets, enums = [], 0, [], []
        for name, spec in self.flat(body):
            low = spec.lower()
            if low in STRING_TYPES:
                if tail:
                    raise Unsupported(f"{record}.{name}: a string after the leading run")
                strings.append((name, STRING_TYPES[low]))
                continue
            set_spec = spec
            if low in self.decls and self.decls[low][0] == "alias":
                set_spec = self.decls[low][2]
            m = re.fullmatch(r"(packed\s+)?set\s+of\s+(.+)", set_spec, re.S | re.I)
            if m:
                _, _, members = self.ordinal_range(m.group(2))
                if members:
                    sets.append((name, tail, members))
            elif set_spec.startswith("("):
                _, _, members = self.ordinal_range(set_spec)
                enums.append((name, tail, members))
            tail += self.size(spec)
        return strings, tail, sets, enums


def split_top(s: str, sep: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for c in s:
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if c == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur))
    return parts


def setup_id(text: str):
    m = re.search(r"SetupID\s*:\s*TSetupID\s*=\s*'Inno Setup Setup Data \(([^)]*)\)", text)
    if m:
        return m.group(1)
    # 1.2.x: `'i1.2.10--16'#26` / `'i1.2.10--32'#26`, the same version.
    m = re.search(r"SetupID\s*:\s*TSetupID\s*=.*?'i(\d+\.\d+\.\d+)--", text, re.S)
    return m.group(1) if m else None


def version_key(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:4])


def sources(issrc: pathlib.Path, archives: pathlib.Path):
    for d in sorted(archives.glob("issrc-*")):
        struct = d / "Struct.pas"
        if struct.is_file():
            yield d.name, struct.read_text(encoding="latin-1")
    git = ["git", "-C", str(issrc)]
    tags = subprocess.run(git + ["tag", "--list", "is-*"], check=True,
                          capture_output=True, text=True).stdout.split()
    for tag in tags:
        files = subprocess.run(git + ["ls-tree", "-r", "--name-only", tag], check=True,
                               capture_output=True, text=True).stdout.split()
        struct = next((f for f in files if re.search(r"(^|/)(Shared\.)?Struct\.pas$", f)), None)
        if struct is not None:
            text = subprocess.run(git + ["show", f"{tag}:{struct}"], check=True,
                                  capture_output=True).stdout.decode("latin-1")
            yield tag, text


def builds(marker: str) -> list[tuple[bool, bool]]:
    """The builds a marker shipped as: `(unicode, bits16)` pairs."""
    v = version_key(marker)
    if v < (1, 3, 0):
        return [(False, False), (False, True)]
    out = []
    if v < (6, 0, 0):
        out.append((False, False))
    if v >= (5, 2, 5):
        out.append((True, False))
    return out


def defines_for(unicode: bool, bits16: bool) -> set[str]:
    return (set() if bits16 else {"WIN32"}) | ({"UNICODE"} if unicode else set())


def evaluate(origin: str, raw: str, unicode: bool, bits16: bool):
    text = preprocess(raw, defines_for(unicode, bits16))
    types = Types(text, unicode, bits16)
    out = []
    for record in RECORDS:
        if record.lower() not in types.decls:
            continue
        strings, tail, sets, enums = types.layout(record)
        prefix = COUNT_CONSTS[record]
        declared = {}
        for suffix in ("Strings", "AnsiStrings"):
            m = re.search(rf"\b{prefix}{suffix}\s*=\s*(\d+)\s*;", text)
            if m:
                declared[suffix] = int(m.group(1))
        n_str = sum(1 for _, k in strings if k == "Str")
        n_ansi = len(strings) - n_str
        # Before `*AnsiStrings` existed every string field, `AnsiString`
        # included, was counted (and written, in declaration order) as one.
        if "AnsiStrings" in declared:
            expect = {"Strings": n_str, "AnsiStrings": n_ansi}
        else:
            expect = {"Strings": n_str + n_ansi}
        for suffix, count in declared.items():
            if expect.get(suffix) != count:
                raise SystemExit(f"{origin}: {record} declares {count} {suffix}, parsed {expect.get(suffix)}")
        out.append((record, strings, tail, sets, enums))
    return out


def merge(a, b):
    """One layout covering both, or None when they conflict. Two releases
    agree when every string field and tail size matches and each set's
    members in one are a prefix of the other's: flags appended within the
    same bytes leave every existing bit's meaning alone, so the longer list
    describes both."""
    if [u for u, _ in a] != [u for u, _ in b]:
        return None
    out = []
    for (build, ra), (_, rb) in zip(a, b):
        if [r[0] for r in ra] != [r[0] for r in rb]:
            return None
        records = []
        for (name, sa, ta, seta, ea), (_, sb, tb, setb, eb) in zip(ra, rb):
            if sa != sb or ta != tb or [(n, o) for n, o, _ in seta] != [(n, o) for n, o, _ in setb]:
                return None
            if [(n, o) for n, o, _ in ea] != [(n, o) for n, o, _ in eb]:
                return None
            enums = []
            for (field, offset, ma), (_, _, mb) in zip(ea, eb):
                short, long_ = sorted((ma, mb), key=len)
                if long_[:len(short)] != short:
                    return None
                enums.append((field, offset, long_))
            sets = []
            for (field, offset, ma), (_, _, mb) in zip(seta, setb):
                short, long_ = sorted((ma, mb), key=len)
                if long_[:len(short)] != short:
                    return None
                sets.append((field, offset, long_))
            records.append((name, sa, ta, sets, enums))
        out.append((build, records))
    return out


def rust_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def show_fields(issrc, archives, origin_wanted, record, unicode, bits16):
    """Prints one record's tail field by field: offset, size, type."""
    for origin, raw in sources(issrc, archives):
        if origin != origin_wanted:
            continue
        types = Types(preprocess(raw, defines_for(unicode, bits16)), unicode, bits16)
        offset = 0
        for name, spec in types.flat(types.decls[record.lower()][2]):
            if spec.lower() in STRING_TYPES:
                print(f"  string  {name}: {spec}")
                continue
            size = types.size(spec)
            print(f"  {offset:4} {size:4}  {name}: {spec[:70]}")
            offset += size
        print(f"  tail {offset}")
        return
    raise SystemExit(f"no source {origin_wanted}")


def main() -> None:
    if sys.argv[1] == "--fields":
        _, _, issrc, archives, origin, record, build = sys.argv
        show_fields(pathlib.Path(issrc), pathlib.Path(archives), origin, record,
                    build == "unicode", build == "16bit")
        return
    issrc, archives = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    markers: dict[str, list] = {}
    for origin, raw in sorted(sources(issrc, archives), key=lambda s: version_key(s[0])):
        marker = setup_id(raw)
        if marker is None:
            continue
        layout = [(build, evaluate(origin, raw, *build)) for build in builds(marker)]
        variants = markers.setdefault(marker, [])
        for i, (known, origins) in enumerate(variants):
            merged = merge(known, layout)
            if merged is not None:
                variants[i] = (merged, origins + [origin])
                break
        else:
            variants.append((layout, [origin]))

    print("// @generated by tests/samples/build/gen-layouts.py - do not edit.")
    print("// Included by `src/upstream.rs`, which defines the types used here.")
    print("//")
    print("// How each SetupID marker lays out the setup-0 records, per build,")
    print("// read from the releases' own `Struct.pas`. A marker with more than")
    print("// one variant is ambiguous: a later release changed a record without")
    print("// changing the SetupID.")
    print()
    print("pub const MARKERS: &[Marker] = &[")
    for marker in sorted(markers, key=version_key):
        print(f"    Marker {{ id: {rust_str(marker)}, variants: &[")
        for layout, origins in markers[marker]:
            print(f"        Variant {{ origins: {rust_str(' '.join(origins))}, builds: &[")
            for (unicode, bits16), records in layout:
                print(f"            Build {{ unicode: {str(unicode).lower()}, bits16: {str(bits16).lower()}, records: &[")
                for record, strings, tail, sets, enums in records:
                    print(f"                Record {{ name: {rust_str(record)}, tail: {tail}, strings: &[")
                    for name, kind in strings:
                        print(f"                    ({rust_str(name)}, {kind}),")
                    print("                ], sets: &[")
                    for name, offset, members in sets:
                        joined = ", ".join(rust_str(m) for m in members)
                        print(f"                    Set {{ field: {rust_str(name)}, offset: {offset}, members: &[{joined}] }},")
                    print("                ], enums: &[")
                    for name, offset, members in enums:
                        joined = ", ".join(rust_str(m) for m in members)
                        print(f"                    Set {{ field: {rust_str(name)}, offset: {offset}, members: &[{joined}] }},")
                    print("                ] },")
                print("            ] },")
            print("        ] },")
        print("    ] },")
    print("];")


if __name__ == "__main__":
    main()
