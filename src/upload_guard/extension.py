"""Extension handling: normalisation, aliases, declared-vs-detected comparison
and allow-list rules such as ``"image/*"``, ``"application/pdf"`` or ``".docx"``."""
from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .types import DetectedType

# Alternative spellings that should be treated as the same extension.
EXTENSION_ALIASES: Dict[str, str] = {
    "jpeg": "jpg", "jpe": "jpg", "jfif": "jpg", "pjpeg": "jpg",
    "tiff": "tif",
    "htm": "html", "xhtml": "html",
    "yml": "yaml",
    "mpeg": "mpg", "mpe": "mpg",
    "midi": "mid",
    "markdown": "md",
    "text": "txt",
    "gzip": "gz",
    "sqlite3": "sqlite",
    "aiff": "aif",
    "wave": "wav",
    "heif": "heic",
    "tar.gz": "tgz",
}

_EXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-+~]{0,15}$")


def normalize_extension(ext: Optional[str]) -> str:
    """``".JPG "`` → ``"jpg"``. Returns ``""`` for empty/None."""
    if not ext:
        return ""
    return ext.strip().lstrip(".").strip().lower()


def canonical_extension(ext: Optional[str]) -> str:
    norm = normalize_extension(ext)
    return EXTENSION_ALIASES.get(norm, norm)


def split_filename(filename: Optional[str]) -> Tuple[str, Optional[str]]:
    """Return ``(stem, extension)`` using the *last* dot; extension is lower-case without the dot.

    Trailing dots/spaces are ignored (``"a.txt. "`` → ``("a", "txt")``). A leading
    dot alone (``".bashrc"``) is not an extension.
    """
    if not filename:
        return "", None
    name = os.path.basename(filename.replace("\\", "/")).rstrip(". ")
    if "." not in name:
        return name, None
    stem, _, ext = name.rpartition(".")
    if not stem:  # ".bashrc"
        return name, None
    ext = ext.lower()
    if not _EXT_RE.match(ext):
        return name, None
    return stem, ext


def all_extensions(filename: Optional[str]) -> List[str]:
    """Every dotted suffix: ``"a.tar.gz"`` → ``["tar", "gz"]``."""
    if not filename:
        return []
    name = os.path.basename(filename.replace("\\", "/")).rstrip(". ").lstrip(".")
    parts = name.split(".")
    if len(parts) < 2:
        return []
    return [p.lower() for p in parts[1:] if _EXT_RE.match(p)]


def extension_matches(ext: Optional[str], detected: DetectedType) -> bool:
    """True when ``ext`` is one of the extensions that ``detected`` may legitimately use."""
    canon = canonical_extension(ext)
    if not canon:
        return False
    return canon in {canonical_extension(e) for e in detected.extensions}


# ---------------------------------------------------------------------------
# Registry of every known type (for reverse look-ups and double-extension checks)
# ---------------------------------------------------------------------------
def _all_known_types() -> List[DetectedType]:
    from .sniff import containers, signatures

    seen: Dict[Tuple[str, Tuple[str, ...]], DetectedType] = {}
    for module in (signatures, containers):
        for value in vars(module).values():
            if isinstance(value, DetectedType):
                seen.setdefault((value.mime, value.extensions), value)
    return list(seen.values())


_KNOWN_TYPES: Optional[List[DetectedType]] = None


def known_types() -> List[DetectedType]:
    global _KNOWN_TYPES
    if _KNOWN_TYPES is None:
        _KNOWN_TYPES = _all_known_types()
    return _KNOWN_TYPES


def known_extensions() -> frozenset:
    return frozenset(canonical_extension(e) for t in known_types() for e in t.extensions)


def types_for_extension(ext: Optional[str]) -> List[DetectedType]:
    canon = canonical_extension(ext)
    if not canon:
        return []
    return [t for t in known_types() if canon in {canonical_extension(e) for e in t.extensions}]


def mime_for_extension(ext: Optional[str]) -> Optional[str]:
    types = types_for_extension(ext)
    return types[0].mime if types else None


# ---------------------------------------------------------------------------
# Allow-list rules
# ---------------------------------------------------------------------------
_MIME_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/(\*|[a-z0-9!#$&^_.+-]+)$", re.IGNORECASE)


class TypeRule:
    """One allow/deny rule: a MIME type, a MIME wildcard (``image/*``), an extension
    (``.pdf`` / ``pdf``) or a category (``category:image``)."""

    __slots__ = ("kind", "value", "raw")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        text = raw.strip().lower()
        if not text:
            raise ValueError("empty type rule")
        if text.startswith("category:"):
            self.kind, self.value = "category", text.split(":", 1)[1].strip()
        elif "/" in text:
            if not _MIME_RE.match(text):
                raise ValueError("invalid MIME type rule: %r" % raw)
            if text.endswith("/*"):
                self.kind, self.value = "mime_prefix", text[:-1]  # "image/"
            else:
                self.kind, self.value = "mime", text
        else:
            self.kind, self.value = "ext", canonical_extension(text)
            if not self.value:
                raise ValueError("invalid extension rule: %r" % raw)

    def matches(self, detected: DetectedType) -> bool:
        if self.kind == "mime":
            return detected.mime.lower() == self.value
        if self.kind == "mime_prefix":
            return detected.mime.lower().startswith(self.value)
        if self.kind == "category":
            return detected.category == self.value
        return any(canonical_extension(e) == self.value for e in detected.extensions)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "TypeRule(%r)" % self.raw


RuleInput = Union[str, TypeRule, Iterable[Union[str, TypeRule]], None]


def compile_rules(rules: RuleInput) -> List[TypeRule]:
    if rules is None:
        return []
    if isinstance(rules, (str, TypeRule)):
        rules = [rules]
    return [r if isinstance(r, TypeRule) else TypeRule(r) for r in rules]


def any_rule_matches(rules: Sequence[TypeRule], detected: DetectedType) -> bool:
    return any(r.matches(detected) for r in rules)
