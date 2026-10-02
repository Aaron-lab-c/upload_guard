"""Polyglot and appended-payload detection.

A *polyglot* file is valid as two formats at once (GIF+JAR, PDF+ZIP, PNG with
PHP appended, ...).  Such files pass naive magic-number checks yet are later
interpreted as something else by a browser, an archive tool or a server-side
include.  This module looks for secondary format signatures inside the file
and for data trailing the format's own end-of-file marker.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import BinaryIO, Dict, List, Optional, Sequence, Tuple

from ..types import DetectedType, Finding, Severity


@dataclass(frozen=True)
class Marker:
    pattern: bytes
    name: str
    severity: Severity
    case_insensitive: bool = False
    min_offset: int = 1  # ignore matches before this offset (0 would be the primary type itself)


_TEXT_FOLLOW = rb"[\s>/]"

MARKERS: Tuple[Marker, ...] = (
    Marker(b"%PDF-", "pdf", Severity.HIGH),
    Marker(b"PK\x03\x04", "zip", Severity.MEDIUM),
    Marker(b"\x7fELF", "elf", Severity.HIGH),
    Marker(b"This program cannot be run in DOS mode", "pe", Severity.HIGH),
    Marker(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2", Severity.MEDIUM),
    Marker(b"Rar!\x1a\x07", "rar", Severity.MEDIUM),
    Marker(b"7z\xbc\xaf\x27\x1c", "7z", Severity.MEDIUM),
    Marker(b"<?php", "php", Severity.CRITICAL, case_insensitive=True, min_offset=0),
    Marker(b"<%", "asp", Severity.LOW, min_offset=0),
    Marker(b"<script", "html_script", Severity.HIGH, case_insensitive=True, min_offset=0),
    Marker(b"<iframe", "html_iframe", Severity.HIGH, case_insensitive=True, min_offset=0),
    Marker(b"<html", "html", Severity.MEDIUM, case_insensitive=True, min_offset=0),
    Marker(b"<svg", "svg", Severity.MEDIUM, case_insensitive=True, min_offset=0),
    Marker(b"<!doctype html", "html", Severity.MEDIUM, case_insensitive=True, min_offset=0),
    Marker(b"javascript:", "javascript_uri", Severity.LOW, case_insensitive=True, min_offset=0),
    Marker(b"#!/", "shebang", Severity.MEDIUM, min_offset=0),
    Marker(b"\xca\xfe\xba\xbe", "java_class", Severity.MEDIUM),
)

#: Which markers matter for which primary category.
_CATEGORY_MARKERS: Dict[str, Sequence[str]] = {
    "image": ("pdf", "zip", "elf", "pe", "ole2", "rar", "7z", "php", "asp", "html_script", "html_iframe", "html", "svg", "shebang", "java_class"),
    "font": ("pdf", "zip", "elf", "pe", "php", "html_script", "html_iframe", "shebang"),
    "audio": ("pdf", "zip", "elf", "pe", "php", "html_script", "html_iframe", "shebang"),
    "video": ("pdf", "zip", "elf", "pe", "php", "html_script", "html_iframe", "shebang"),
    "document": ("elf", "pe", "php", "zip", "html_script", "html_iframe", "shebang"),
    "data": ("elf", "pe", "php", "html_script"),
    "unknown": ("php", "html_script", "html_iframe", "pe", "elf"),
}
# Document types that are legitimately zip-based or legitimately contain script.
_SKIP_MIMES = frozenset({"application/rtf"})

_TEXT_MARKERS = frozenset({"php", "asp", "html_script", "html_iframe", "html", "svg", "javascript_uri"})


def _compile(marker: Marker) -> "re.Pattern[bytes]":
    pat = re.escape(marker.pattern)
    if marker.name in _TEXT_MARKERS and marker.name not in ("php", "javascript_uri", "asp"):
        pat += _TEXT_FOLLOW
    return re.compile(pat, re.IGNORECASE if marker.case_insensitive else 0)


_COMPILED = {m.name: (_compile(m), m) for m in MARKERS}


def scan_embedded(data: bytes, detected: DetectedType, markers: Optional[Sequence[str]] = None) -> List[Finding]:
    """Search ``data`` for signatures of *other* formats."""
    if detected.category in ("archive", "text", "script", "executable") or detected.mime in _SKIP_MIMES:
        return []
    if detected.mime == "image/svg+xml":  # markup: handled by the dedicated SVG scanner
        return []
    if detected.mime.startswith("application/vnd.openxmlformats") or detected.mime.startswith("application/vnd.oasis") or detected.mime == "application/epub+zip":
        return []
    names = markers if markers is not None else _CATEGORY_MARKERS.get(detected.category, _CATEGORY_MARKERS["unknown"])
    findings: List[Finding] = []
    for name in names:
        regex, marker = _COMPILED[name]
        for m in regex.finditer(data):
            if m.start() < marker.min_offset:
                continue
            if name == "pdf" and detected.mime == "application/pdf":
                continue
            if name == "svg" and detected.mime == "image/svg+xml":
                continue
            if name in ("html", "html_script", "html_iframe") and detected.mime == "text/html":
                continue
            findings.append(Finding(
                "polyglot.embedded_%s" % name, marker.severity,
                "%s signature found inside %s at offset %d" % (name.upper().replace("_", " "), detected.description or detected.mime, m.start()),
                {"offset": m.start(), "marker": name},
            ))
            break  # one finding per marker type
    return findings


# ---------------------------------------------------------------------------
# Trailing data after the format's EOF marker
# ---------------------------------------------------------------------------
_PNG_IEND = b"IEND\xae\x42\x60\x82"
_JPEG_PAD = frozenset(b"\x00\xff\n\r\t ")


def check_trailing(stream: BinaryIO, detected: DetectedType, size: int, tail_size: int = 64 * 1024) -> List[Finding]:
    """Detect bytes appended after the natural end of an image/PDF."""
    if size <= 0:
        return []
    mime = detected.mime
    if mime not in ("image/png", "image/jpeg", "image/gif", "application/pdf"):
        return []
    pos = stream.tell()
    try:
        start = max(0, size - tail_size)
        stream.seek(start)
        tail = stream.read(size - start) or b""
    except (OSError, ValueError):
        return []
    finally:
        try:
            stream.seek(pos)
        except (OSError, ValueError):
            pass
    if not tail:
        return []

    trailing: Optional[int] = None
    truncated = False
    if mime == "image/png":
        if tail.endswith(_PNG_IEND):
            return []
        idx = tail.rfind(_PNG_IEND)
        if idx == -1:
            truncated = True
        else:
            trailing = len(tail) - (idx + len(_PNG_IEND))
    elif mime == "image/jpeg":
        stripped = tail.rstrip(bytes(_JPEG_PAD))
        if stripped.endswith(b"\xff\xd9") and len(tail) - len(stripped) <= 64:
            return []
        idx = tail.rfind(b"\xff\xd9")
        if idx == -1:
            truncated = True
        else:
            trailing = len(tail) - (idx + 2)
    elif mime == "image/gif":
        if tail.endswith(b"\x3b"):
            return []
        idx = tail.rfind(b"\x00\x3b")
        if idx == -1:
            truncated = True
        else:
            trailing = len(tail) - (idx + 2)
    elif mime == "application/pdf":
        stripped = tail.rstrip(b"\r\n\t \x00")
        if stripped.endswith(b"%%EOF"):
            return []
        idx = tail.rfind(b"%%EOF")
        if idx == -1:
            return [Finding("polyglot.no_eof_marker", Severity.LOW, "PDF does not end with %%EOF")]
        trailing = len(tail) - (idx + 5)
        if trailing < 1024:  # linearized/incremental PDFs may carry small trailers
            return [Finding("polyglot.trailing_data", Severity.INFO, "%d bytes after final %%%%EOF" % trailing, {"trailing_bytes": trailing})]

    if truncated:
        return [Finding("polyglot.missing_eof", Severity.LOW, "%s has no end-of-file marker in its last %d bytes (truncated or large trailer)" % (detected.description, len(tail)), {"tail_scanned": len(tail)})]
    if trailing:
        payload = tail[-trailing:]
        sev = Severity.MEDIUM
        looks_text = all(32 <= b < 127 or b in (9, 10, 13) for b in payload[:256]) and trailing > 8
        if looks_text:
            sev = Severity.HIGH  # readable script/HTML appended to an image is the classic web-shell trick
        return [Finding(
            "polyglot.trailing_data", sev,
            "%d bytes of %sdata appended after the %s end marker" % (trailing, "text " if looks_text else "", detected.description),
            {"trailing_bytes": trailing, "preview": payload[:32].decode("latin-1")},
        )]
    return []
