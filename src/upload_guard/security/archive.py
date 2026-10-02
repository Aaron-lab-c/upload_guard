"""Archive inspection: zip bombs, tar bombs, Zip Slip / Tar Slip, overlapping
entries and nested archives — all with hard memory/CPU bounds.

Nothing here extracts to disk.  ZIP inspection reads the central directory
(and optionally streams entries through the decompressor with a cap); gzip,
bzip2, xz and tar streams are walked through a bounded decompressor that
never buffers more than a small chunk at a time.
"""
from __future__ import annotations

import bz2
import io
import lzma
import posixpath
import re
import zipfile
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Callable, List, Optional, Tuple

from ..types import ArchiveReport, Finding, Severity

ARCHIVE_EXTENSIONS = frozenset({"zip", "jar", "war", "ear", "apk", "xpi", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "7z", "rar", "tar", "zst", "lz", "lz4", "cab", "iso", "arj", "z"})
_NESTED_RE = re.compile(r"\.(%s)$" % "|".join(sorted(ARCHIVE_EXTENSIONS)), re.IGNORECASE)
_CHUNK = 64 * 1024


@dataclass(frozen=True)
class ArchiveLimits:
    """Bounds applied while inspecting archives."""

    max_total_uncompressed: int = 512 * 1024 * 1024  # 512 MiB across all entries (and nested ones)
    max_ratio: float = 100.0  # uncompressed / compressed
    ratio_min_uncompressed: int = 1024 * 1024  # ratio only enforced above this size (tiny files compress absurdly well)
    max_entries: int = 10_000
    max_nesting: int = 1  # how many levels of nested archives to open (0 = never)
    max_nested_bytes: int = 32 * 1024 * 1024  # nested archive must be smaller than this to be opened in memory
    verify_sizes: bool = False  # ZIP: actually decompress entries to confirm declared sizes
    allow_encrypted: bool = True
    allow_symlinks: bool = False


DEFAULT_LIMITS = ArchiveLimits()


class BombDetected(Exception):
    """Internal signal: a bound was exceeded while streaming."""


# ---------------------------------------------------------------------------
# Bounded streaming decompressor
# ---------------------------------------------------------------------------
class BoundedReader:
    """Read decompressed bytes from a compressed stream, never producing more
    than ``cap`` bytes in total and never holding more than a chunk or two.

    ``factory`` builds a decompressor object (``zlib.decompressobj``,
    ``bz2.BZ2Decompressor`` or ``lzma.LZMADecompressor``); ``None`` means the
    source is already uncompressed (plain tar).
    """

    def __init__(self, source: BinaryIO, factory: Optional[Callable[[], object]], cap: int) -> None:
        self._source = source
        self._factory = factory
        self._decomp = factory() if factory else None
        self._cap = cap
        self._buffer = b""
        self._pending = b""
        self._eof = False
        self.total_out = 0
        self.total_in = 0

    def _emit(self, out: bytes) -> None:
        if out:
            self._buffer += out
            self.total_out += len(out)
            if self.total_out > self._cap:
                raise BombDetected("decompressed output exceeded %d bytes" % self._cap)

    def _feed(self) -> bool:
        """Produce some more output. Returns False once the stream is exhausted."""
        if self._eof:
            return False
        if self._decomp is None:  # passthrough
            chunk = self._source.read(_CHUNK)
            if not chunk:
                self._eof = True
                return False
            self.total_in += len(chunk)
            self._emit(chunk)
            return True
        d = self._decomp
        is_zlib = hasattr(d, "unconsumed_tail")
        if self._pending:
            data, self._pending = self._pending, b""
        elif not is_zlib and not d.needs_input:  # type: ignore[union-attr]
            data = b""  # decompressor still holds buffered input
        else:
            data = self._source.read(_CHUNK)
            if not data:
                self._eof = True
                if is_zlib and not d.eof:  # type: ignore[union-attr]
                    out = d.flush()  # type: ignore[union-attr]
                    self._emit(out)
                    return bool(out)
                return False
            self.total_in += len(data)
        out = d.decompress(data, _CHUNK)  # type: ignore[union-attr]
        if is_zlib:
            if d.unconsumed_tail:  # type: ignore[union-attr]
                self._pending = d.unconsumed_tail  # type: ignore[union-attr]
            elif d.eof and d.unused_data[:2] == b"\x1f\x8b":  # type: ignore[union-attr]
                self._pending = d.unused_data  # multi-member gzip  # type: ignore[union-attr]
                self._decomp = self._factory()  # type: ignore[misc]
            elif d.eof:  # type: ignore[union-attr]
                self._eof = True
        elif d.eof:  # type: ignore[union-attr]
            if d.unused_data:  # type: ignore[union-attr]
                self._pending = d.unused_data  # type: ignore[union-attr]
                self._decomp = self._factory()  # type: ignore[misc]
            else:
                self._eof = True
        self._emit(out)
        return True

    def read(self, n: int) -> bytes:
        while len(self._buffer) < n and not self._eof:
            self._feed()
        out, self._buffer = self._buffer[:n], self._buffer[n:]
        return out

    def push_back(self, data: bytes) -> None:
        self._buffer = data + self._buffer

    def skip(self, n: int) -> int:
        remaining = n
        while remaining > 0:
            chunk = self.read(min(remaining, _CHUNK))
            if not chunk:
                break
            remaining -= len(chunk)
        return n - remaining

    def drain(self) -> int:
        while self.read(_CHUNK):
            pass
        return self.total_out


def _gzip_factory() -> object:
    return zlib.decompressobj(wbits=31)


def _bz2_factory() -> object:
    return bz2.BZ2Decompressor()


def _xz_factory() -> object:
    return lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)


# ---------------------------------------------------------------------------
# Path safety shared by zip and tar
# ---------------------------------------------------------------------------
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def is_unsafe_member_path(name: str) -> bool:
    """True for names that would escape the extraction directory."""
    if not name:
        return False
    if "\x00" in name:
        return True
    n = name.replace("\\", "/")
    if n.startswith("/") or n.startswith("//") or _DRIVE_RE.match(n):
        return True
    parts = [p for p in n.split("/") if p not in ("", ".")]
    depth = 0
    for p in parts:
        if p == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


def is_unsafe_link_target(member: str, target: str) -> bool:
    if not target:
        return False
    if "\x00" in target:
        return True
    t = target.replace("\\", "/")
    if t.startswith("/") or _DRIVE_RE.match(t):
        return True
    base = posixpath.dirname(member.replace("\\", "/"))
    joined = posixpath.normpath(posixpath.join(base, t))
    return joined.startswith("../") or joined == ".."


def _nested_name(name: str) -> bool:
    return bool(_NESTED_RE.search(name))


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------
def inspect_zip(stream: BinaryIO, limits: ArchiveLimits = DEFAULT_LIMITS, _depth: int = 0) -> Tuple[ArchiveReport, List[Finding]]:
    report = ArchiveReport(format="zip", max_depth=_depth)
    findings: List[Finding] = []
    pos = stream.tell()
    try:
        stream.seek(0)
        try:
            zf = zipfile.ZipFile(stream)
        except (zipfile.BadZipFile, OSError, ValueError, EOFError, NotImplementedError) as exc:
            findings.append(Finding("archive.corrupt", Severity.HIGH, "ZIP archive could not be read: %s" % exc))
            return report, findings
        with zf:
            infos = zf.infolist()
            report.entry_count = len(infos)
            if len(infos) > limits.max_entries:
                findings.append(Finding("archive.too_many_entries", Severity.HIGH, "Archive has %d entries (limit %d)" % (len(infos), limits.max_entries), {"entries": len(infos)}))
                report.truncated = True
                infos = infos[: limits.max_entries]

            # overlapping local headers → quine / overlapping-entry bomb
            spans = sorted(((i.header_offset, i.compress_size, len(i.filename.encode("utf-8", "surrogateescape"))) for i in infos), key=lambda s: s[0])
            for (off_a, size_a, name_a), (off_b, _, _) in zip(spans, spans[1:]):
                if off_b < off_a + 30 + name_a + size_a:
                    findings.append(Finding("archive.overlapping_entries", Severity.CRITICAL, "ZIP entries overlap (overlapping-file zip bomb)"))
                    break

            encrypted = 0
            budget = limits.max_total_uncompressed
            for info in infos:
                name = info.filename
                is_dir = name.endswith("/") or (info.external_attr >> 16) & 0o170000 == 0o040000
                is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
                report.total_uncompressed += info.file_size
                report.total_compressed += info.compress_size
                if info.flag_bits & 0x1:
                    encrypted += 1
                if is_unsafe_member_path(name):
                    report.unsafe_paths.append(name)
                if is_symlink:
                    target = None
                    if info.file_size <= 4096 and not (info.flag_bits & 0x1):
                        try:
                            target = zf.read(info).decode("utf-8", "replace")
                        except Exception:  # noqa: BLE001 - corrupt entry; treat as unknown target
                            target = None
                    if not limits.allow_symlinks:
                        findings.append(Finding("archive.symlink", Severity.HIGH, "Archive contains a symlink: %s" % name, {"target": target}))
                    elif target is not None and is_unsafe_link_target(name, target):
                        report.unsafe_paths.append(name)
                        findings.append(Finding("archive.symlink_escape", Severity.CRITICAL, "Symlink %s points outside the archive (%s)" % (name, target)))
                if report.total_uncompressed > budget:
                    report.truncated = True
                    break
                if not is_dir and _nested_name(name):
                    report.nested_archives.append(name)
                    if _depth < limits.max_nesting and name.lower().endswith((".zip", ".jar", ".apk", ".xpi", ".war")) and not (info.flag_bits & 0x1):
                        if info.file_size > limits.max_nested_bytes or info.compress_size > limits.max_nested_bytes:
                            findings.append(Finding("archive.nested_too_large", Severity.MEDIUM, "Nested archive %s too large to inspect" % name))
                        else:
                            nested_bytes = _read_capped(zf, info, limits.max_nested_bytes)
                            if nested_bytes is None:
                                findings.append(Finding("archive.size_mismatch", Severity.CRITICAL, "Entry %s is larger than its declared size" % name))
                                report.truncated = True
                                break
                            sub_report, sub_findings = inspect_zip(io.BytesIO(nested_bytes), limits, _depth + 1)
                            report.total_uncompressed += sub_report.total_uncompressed
                            report.entry_count += sub_report.entry_count
                            report.max_depth = max(report.max_depth, sub_report.max_depth)
                            report.nested_archives.extend("%s!/%s" % (name, n) for n in sub_report.nested_archives)
                            report.unsafe_paths.extend("%s!/%s" % (name, n) for n in sub_report.unsafe_paths)
                            findings.extend(sub_findings)
                            if sub_report.truncated:
                                report.truncated = True
                                break
                    elif _depth >= limits.max_nesting:
                        findings.append(Finding("archive.nested_uninspected", Severity.MEDIUM, "Nested archive %s was not inspected (nesting limit %d)" % (name, limits.max_nesting)))

            if encrypted:
                findings.append(Finding("archive.encrypted", Severity.LOW if limits.allow_encrypted else Severity.HIGH, "%d encrypted entries cannot be inspected" % encrypted, {"count": encrypted}))

            if limits.verify_sizes and not report.truncated:
                report.verified = True
                for info in infos:
                    if info.is_dir() or info.flag_bits & 0x1:
                        continue
                    actual = _measure_entry(zf, info, limits.max_total_uncompressed)
                    if actual is None:
                        findings.append(Finding("archive.size_mismatch", Severity.CRITICAL, "Entry %s decompresses beyond its declared size (header lies)" % info.filename))
                        break
                    if actual < 0:
                        findings.append(Finding("archive.corrupt", Severity.HIGH, "Entry %s is corrupt" % info.filename))
                        break
    finally:
        stream.seek(pos)

    _apply_bomb_findings(report, limits, findings)
    return report, findings


def _read_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> Optional[bytes]:
    out = bytearray()
    try:
        with zf.open(info) as fh:
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                out += chunk
                if len(out) > cap or len(out) > info.file_size:
                    return None
    except (zipfile.BadZipFile, zlib.error, OSError, EOFError, RuntimeError, NotImplementedError):
        return None
    return bytes(out)


def _measure_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, cap: int) -> Optional[int]:
    total = 0
    try:
        with zf.open(info) as fh:
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > info.file_size or total > cap:
                    return None
    except zipfile.BadZipFile:
        # zipfile stops at the declared size and then fails the CRC check:
        # the header does not describe the real content.
        return None
    except (zlib.error, EOFError, OSError, RuntimeError, NotImplementedError):
        return -1
    return total


def _apply_bomb_findings(report: ArchiveReport, limits: ArchiveLimits, findings: List[Finding]) -> None:
    if report.total_uncompressed > limits.max_total_uncompressed:
        findings.append(Finding(
            "archive.bomb_size", Severity.CRITICAL,
            "Archive expands to at least %d bytes (limit %d)" % (report.total_uncompressed, limits.max_total_uncompressed),
            {"total_uncompressed": report.total_uncompressed},
        ))
    if report.total_uncompressed >= limits.ratio_min_uncompressed and report.ratio > limits.max_ratio:
        findings.append(Finding(
            "archive.bomb_ratio", Severity.CRITICAL,
            "Compression ratio %.0f:1 exceeds limit %.0f:1" % (report.ratio, limits.max_ratio),
            {"ratio": None if report.ratio == float("inf") else round(report.ratio, 1)},
        ))
    if report.unsafe_paths:
        findings.append(Finding(
            "archive.path_traversal", Severity.CRITICAL,
            "%d entries would extract outside the target directory (Zip Slip)" % len(report.unsafe_paths),
            {"paths": report.unsafe_paths[:20]},
        ))


# ---------------------------------------------------------------------------
# TAR (plain or inside gzip/bz2/xz)
# ---------------------------------------------------------------------------
def _tar_checksum_ok(header: bytes) -> bool:
    try:
        stored = int(header[148:156].split(b"\x00", 1)[0].strip() or b"0", 8)
    except ValueError:
        return False
    unsigned = sum(header[:148]) + 8 * 32 + sum(header[156:512])
    signed = sum(b - 256 if b > 127 else b for b in header[:148]) + 8 * 32 + sum(b - 256 if b > 127 else b for b in header[156:512])
    return stored in (unsigned, signed)


def looks_like_tar(head: bytes) -> bool:
    if len(head) < 512:
        return False
    if head[257:262] == b"ustar":
        return True
    return _tar_checksum_ok(head[:512]) and any(head[:100])


def _tar_number(field: bytes) -> int:
    if field and field[0] & 0x80:  # GNU base-256
        value = 0
        for b in field[1:]:
            value = (value << 8) | b
        return value
    text = field.split(b"\x00", 1)[0].strip()
    if not text:
        return 0
    return int(text, 8)


def _parse_pax(data: bytes) -> dict:
    result = {}
    pos = 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space == -1:
            break
        try:
            length = int(data[pos:space])
        except ValueError:
            break
        record = data[space + 1 : pos + length]
        key, _, value = record.rstrip(b"\n").partition(b"=")
        result[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
        pos += max(length, 1)
    return result


def walk_tar(reader: BoundedReader, limits: ArchiveLimits, report: ArchiveReport, findings: List[Finding]) -> None:
    pending_long_name: Optional[str] = None
    pending_long_link: Optional[str] = None
    pax: dict = {}
    zero_blocks = 0
    while True:
        header = reader.read(512)
        if len(header) < 512:
            break
        if header == b"\x00" * 512:
            zero_blocks += 1
            if zero_blocks >= 2:
                break
            continue
        zero_blocks = 0
        if not _tar_checksum_ok(header):
            findings.append(Finding("archive.corrupt", Severity.HIGH, "tar header checksum mismatch"))
            report.truncated = True
            break
        typeflag = header[156:157]
        try:
            size = _tar_number(header[124:136])
        except ValueError:
            findings.append(Finding("archive.corrupt", Severity.HIGH, "tar header has an invalid size field"))
            report.truncated = True
            break
        padded = (size + 511) // 512 * 512
        if typeflag in (b"L", b"K"):  # GNU long name / long link
            data = reader.read(padded)[:size]
            if typeflag == b"L":
                pending_long_name = data.rstrip(b"\x00").decode("utf-8", "replace")
            else:
                pending_long_link = data.rstrip(b"\x00").decode("utf-8", "replace")
            continue
        if typeflag in (b"x", b"g"):  # PAX headers
            data = reader.read(padded)[:size]
            pax.update(_parse_pax(data))
            continue

        name = header[0:100].split(b"\x00", 1)[0].decode("utf-8", "replace")
        prefix = header[345:500].split(b"\x00", 1)[0].decode("utf-8", "replace") if header[257:262] == b"ustar" else ""
        if prefix:
            name = prefix + "/" + name
        if pending_long_name:
            name = pending_long_name
        if "path" in pax:
            name = pax["path"]
        linkname = header[157:257].split(b"\x00", 1)[0].decode("utf-8", "replace")
        if pending_long_link:
            linkname = pending_long_link
        if "linkpath" in pax:
            linkname = pax["linkpath"]
        if "size" in pax:
            try:
                size = int(pax["size"])
                padded = (size + 511) // 512 * 512
            except ValueError:
                pass
        pending_long_name = pending_long_link = None
        pax = {}

        report.entry_count += 1
        if typeflag in (b"0", b"\x00", b"7", b""):
            report.total_uncompressed += size
        if is_unsafe_member_path(name):
            report.unsafe_paths.append(name)
        if typeflag in (b"1", b"2"):
            if not limits.allow_symlinks:
                findings.append(Finding("archive.symlink", Severity.HIGH, "tar contains a %s: %s" % ("hard link" if typeflag == b"1" else "symlink", name), {"target": linkname}))
            elif is_unsafe_link_target(name, linkname):
                report.unsafe_paths.append(name)
                findings.append(Finding("archive.symlink_escape", Severity.CRITICAL, "Link %s points outside the archive (%s)" % (name, linkname)))
        elif typeflag in (b"3", b"4"):
            findings.append(Finding("archive.device_file", Severity.HIGH, "tar contains a device node: %s" % name))
        if _nested_name(name) and typeflag in (b"0", b"\x00"):
            report.nested_archives.append(name)
            if limits.max_nesting <= report.max_depth:
                findings.append(Finding("archive.nested_uninspected", Severity.MEDIUM, "Nested archive %s was not inspected" % name))
        if report.entry_count > limits.max_entries:
            findings.append(Finding("archive.too_many_entries", Severity.HIGH, "Archive has more than %d entries" % limits.max_entries))
            report.truncated = True
            break
        if report.total_uncompressed > limits.max_total_uncompressed:
            report.truncated = True
            break
        skipped = reader.skip(padded)
        if skipped < padded:
            break


def inspect_compressed(stream: BinaryIO, compression: str, limits: ArchiveLimits = DEFAULT_LIMITS, size_hint: Optional[int] = None) -> Tuple[ArchiveReport, List[Finding]]:
    """Inspect gzip / bzip2 / xz (optionally wrapping a tar) or a plain tar.

    ``compression`` is one of ``"gzip"``, ``"bzip2"``, ``"xz"``, ``"tar"``.
    """
    factories = {"gzip": _gzip_factory, "bzip2": _bz2_factory, "xz": _xz_factory, "tar": None}
    if compression not in factories:
        raise ValueError("unsupported compression: %r" % compression)
    report = ArchiveReport(format=compression)
    findings: List[Finding] = []
    pos = stream.tell()
    try:
        stream.seek(0)
        if size_hint is None:
            stream.seek(0, 2)
            size_hint = stream.tell()
            stream.seek(0)
        report.total_compressed = size_hint
        reader = BoundedReader(stream, factories[compression], limits.max_total_uncompressed)
        try:
            head = reader.read(512)
            if looks_like_tar(head):
                report.format = "tar" if compression == "tar" else "tar+" + compression
                reader.push_back(head)
                walk_tar(reader, limits, report, findings)
                reader.drain()  # still enforces the cap on whatever follows the last header
            elif compression == "tar":
                findings.append(Finding("archive.corrupt", Severity.HIGH, "Not a valid tar archive"))
            else:
                reader.drain()
                report.entry_count = 1
                report.total_uncompressed = reader.total_out
                if compression == "gzip":
                    inner = head
                    if inner[:4] == b"PK\x03\x04" or inner[:2] == b"\x1f\x8b" or inner[:3] == b"BZh" or inner[:6] == b"\xfd7zXZ\x00":
                        report.nested_archives.append("<gzip payload>")
                        findings.append(Finding("archive.nested_uninspected", Severity.MEDIUM, "gzip payload is itself an archive"))
            report.verified = True
        except BombDetected as exc:
            report.truncated = True
            report.total_uncompressed = max(report.total_uncompressed, reader.total_out)
            findings.append(Finding("archive.bomb_size", Severity.CRITICAL, "Decompression aborted: %s" % exc, {"total_uncompressed": reader.total_out}))
        except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError) as exc:
            findings.append(Finding("archive.corrupt", Severity.HIGH, "Compressed stream is corrupt: %s" % exc))
    finally:
        stream.seek(pos)
    if not any(f.code == "archive.bomb_size" for f in findings):
        _apply_bomb_findings(report, limits, findings)
    else:
        if report.unsafe_paths:
            findings.append(Finding("archive.path_traversal", Severity.CRITICAL, "%d entries would extract outside the target directory" % len(report.unsafe_paths), {"paths": report.unsafe_paths[:20]}))
    return report, findings


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
ZIP_BASED_MIMES = frozenset({
    "application/zip", "application/java-archive", "application/vnd.android.package-archive", "application/x-xpinstall",
    "application/epub+zip", "application/vnd.ms-xpsdocument", "application/vnd.openxmlformats-officedocument",
})


def archive_kind(mime: str, head: bytes = b"") -> Optional[str]:
    """Map a detected MIME type to an inspection strategy, or None."""
    if mime in ZIP_BASED_MIMES or mime.startswith("application/vnd.openxmlformats-officedocument") or mime.startswith("application/vnd.oasis.opendocument") or mime.startswith("application/vnd.ms-visio"):
        return "zip"
    if head[:4] == b"PK\x03\x04":
        return "zip"
    return {
        "application/gzip": "gzip",
        "application/x-gzip": "gzip",
        "application/x-bzip2": "bzip2",
        "application/x-xz": "xz",
        "application/x-tar": "tar",
    }.get(mime)


def inspect_archive(stream: BinaryIO, mime: str, limits: ArchiveLimits = DEFAULT_LIMITS, head: bytes = b"") -> Tuple[Optional[ArchiveReport], List[Finding]]:
    """Inspect ``stream`` according to its detected ``mime``.

    Returns ``(None, [])`` for types that are not inspectable archives.
    """
    kind = archive_kind(mime, head)
    if kind is None:
        return None, []
    if kind == "zip":
        return inspect_zip(stream, limits)
    return inspect_compressed(stream, kind, limits)


def gunzip_capped(stream: BinaryIO, cap: int) -> Optional[bytes]:
    """Decompress a gzip stream fully, returning None if it exceeds ``cap`` bytes."""
    pos = stream.tell()
    try:
        stream.seek(0)
        reader = BoundedReader(stream, _gzip_factory, cap)
        out = bytearray()
        try:
            while True:
                chunk = reader.read(_CHUNK)
                if not chunk:
                    break
                out += chunk
        except (BombDetected, zlib.error, OSError, EOFError):
            return None
        return bytes(out)
    finally:
        stream.seek(pos)
