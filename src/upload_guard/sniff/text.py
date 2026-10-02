"""Heuristics for text-based formats (SVG, HTML, XML, JSON, scripts, ...).

These run only when no binary magic number matched.  The emphasis is on the
*security-relevant* distinctions a browser or server would make: is this
something that will be rendered as HTML/SVG, executed as a script, or is it
inert text?
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

from ..types import DetectedType
from . import signatures as S

_BOM_UTF8 = b"\xef\xbb\xbf"
_BOM_UTF16_LE = b"\xff\xfe"
_BOM_UTF16_BE = b"\xfe\xff"

# Bytes that almost never appear in text. \x1b (ESC) is allowed for ANSI logs.
_CONTROL_BYTES = frozenset(range(0x00, 0x09)) | frozenset({0x0B, 0x0C, 0x0E, 0x0F}) | frozenset(range(0x10, 0x1B)) | frozenset(range(0x1C, 0x20)) | {0x7F}

_HTML_TAGS = (
    "html", "head", "body", "script", "iframe", "frameset", "object", "embed", "title", "meta", "link",
    "style", "div", "span", "p", "a", "img", "table", "form", "input", "br", "h1", "h2", "h3", "font",
    "base", "svg:script",
)
_HTML_TAG_RE = re.compile(r"<(?:!doctype\s+html|(?:%s)[\s>/])" % "|".join(re.escape(t) for t in _HTML_TAGS), re.IGNORECASE)
_FIRST_TAG_RE = re.compile(r"<([A-Za-z_][\w.\-]*)(?::([A-Za-z_][\w.\-]*))?")
_XML_PROLOG_RE = re.compile(r"<\?xml[^>]*\?>", re.IGNORECASE)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE\s+([A-Za-z_][\w.\-:]*)", re.IGNORECASE)
_JSON_RE = re.compile(r'^[\[{]\s*(?:["\]\}]|-?\d|true|false|null|\[|\{)')
_SHEBANG_RE = re.compile(r"^#![^\n]*")


def decode_header(head: bytes) -> Tuple[Optional[str], str]:
    """Return (text, encoding) or (None, "") when ``head`` does not look like text."""
    if head.startswith(_BOM_UTF16_LE) or head.startswith(_BOM_UTF16_BE):
        enc = "utf-16-le" if head.startswith(_BOM_UTF16_LE) else "utf-16-be"
        body = head[2:]
        if len(body) % 2:
            body = body[:-1]
        try:
            return body.decode(enc, "replace"), enc
        except (UnicodeDecodeError, LookupError):  # pragma: no cover - replace never raises
            return None, ""
    if head.startswith(_BOM_UTF8):
        head = head[3:]
    if not head:
        return "", "utf-8"
    if b"\x00" in head:
        return None, ""
    sample = head[:1024]
    control = sum(1 for b in sample if b in _CONTROL_BYTES)
    if control > max(2, len(sample) // 20):  # >5% control bytes → binary
        return None, ""
    return head.decode("utf-8", "replace"), "utf-8"


def _strip_markup_prolog(text: str) -> Tuple[str, Optional[str], bool]:
    """Skip <?xml ?>, comments, DOCTYPE and PIs. Returns (rest, doctype_name, had_xml_decl)."""
    rest = text.lstrip()
    doctype: Optional[str] = None
    had_xml_decl = False
    for _ in range(32):
        if rest.startswith("<?xml"):
            m = _XML_PROLOG_RE.match(rest)
            had_xml_decl = True
            rest = rest[m.end() :].lstrip() if m else ""
        elif rest.startswith("<?"):
            end = rest.find("?>")
            rest = rest[end + 2 :].lstrip() if end != -1 else ""
        elif rest.startswith("<!--"):
            end = rest.find("-->")
            rest = rest[end + 3 :].lstrip() if end != -1 else ""
        elif rest[:9].upper() == "<!DOCTYPE":
            m = _DOCTYPE_RE.match(rest)
            if m:
                doctype = m.group(1).lower()
            # a DOCTYPE may contain an internal subset [...]
            bracket = rest.find("[")
            close = rest.find(">")
            if bracket != -1 and (close == -1 or bracket < close):
                end = rest.find("]>")
                rest = rest[end + 2 :].lstrip() if end != -1 else ""
            else:
                rest = rest[close + 1 :].lstrip() if close != -1 else ""
        else:
            break
    return rest, doctype, had_xml_decl


def detect_markup(text: str) -> Optional[DetectedType]:
    """Classify text that starts with a tag (after any prolog)."""
    rest, doctype, had_xml_decl = _strip_markup_prolog(text)
    if doctype == "html":
        return S.HTML
    if doctype == "svg":
        return S.SVG
    m = _FIRST_TAG_RE.match(rest)
    if not m:
        if had_xml_decl or doctype:
            return S.XML
        return None
    prefix, local = m.group(1), m.group(2)
    name = (local or prefix).lower()
    lowered_head = rest[:2048].lower()
    if name == "svg":
        return S.SVG
    if name == "html":
        if "<hta:application" in lowered_head:
            return S.HTA
        return S.HTML
    if name in ("rss", "rdf"):
        return S.RSS
    if name == "feed":
        return S.ATOM
    if name in ("job", "package") and "<script" in lowered_head:
        return S.WINDOWS_SCRIPT
    if name in _HTML_TAGS:
        return S.HTML
    if had_xml_decl or doctype or (local is not None) or ("xmlns" in rest[: m.end() + 256]):
        return S.XML
    # bare unknown tag: treat as XML only if it looks like an element with a closing bracket
    if ">" in rest[:512]:
        return S.XML
    return None


def detect_text(head: bytes) -> Optional[DetectedType]:
    text, _enc = decode_header(head)
    if text is None:
        return None
    if not text.strip():
        return S.PLAIN
    stripped = text.lstrip()
    lowered = stripped[:1024].lower()

    # scripts / executables disguised as text
    if "<?php" in lowered or lowered.startswith("<?="):
        return S.PHP
    if stripped.startswith("#!"):
        first_line = _SHEBANG_RE.match(stripped).group(0).lower()  # type: ignore[union-attr]
        if re.search(r"\b(ba|z|k|da|c|tc)?sh\b", first_line):
            return S.SHELL
        return S.SCRIPT
    if lowered.startswith("windows registry editor") or lowered.startswith("regedit4"):
        return S.REG

    # structured text
    if stripped.startswith("-----BEGIN "):
        return S.PEM
    if lowered.startswith("begin:vcard"):
        return S.VCARD
    if lowered.startswith("begin:vcalendar"):
        return S.ICAL
    if re.match(r"(from|return-path|received|mime-version|delivered-to|x-mailer):", lowered):
        return S.EMAIL

    # markup
    if stripped.startswith("<"):
        markup = detect_markup(stripped)
        if markup is not None:
            return markup
    # HTML can hide behind leading text; browsers still sniff it.
    if _HTML_TAG_RE.search(stripped[:1024]):
        return S.HTML
    if "<svg" in lowered and re.search(r"<svg[\s>]", lowered):
        return S.SVG

    if _JSON_RE.match(stripped):
        return S.JSON
    return S.PLAIN
