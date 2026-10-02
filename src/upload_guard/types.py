"""Core data types shared across upload_guard."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class Severity(enum.IntEnum):
    """How serious a finding is. Ordered so that comparisons work."""

    INFO = 0
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Finding:
    """A single observation produced by a check.

    ``code`` is a stable machine-readable identifier (e.g. ``svg.script``),
    ``severity`` drives the accept/reject decision, ``remediated`` is set when
    the problem was fixed automatically (e.g. an SVG was sanitized) so it no
    longer counts against the upload.
    """

    code: str
    severity: Severity
    message: str
    detail: Dict[str, Any] = field(default_factory=dict)
    remediated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.name,
            "message": self.message,
            "detail": dict(self.detail),
            "remediated": self.remediated,
        }


@dataclass(frozen=True)
class DetectedType:
    """Result of magic-number detection."""

    mime: str
    extensions: Tuple[str, ...] = ()
    description: str = ""
    category: str = "unknown"  # image, document, archive, executable, script, audio, video, font, text, data, unknown

    @property
    def extension(self) -> Optional[str]:
        """The canonical (first) extension, without a leading dot."""
        return self.extensions[0] if self.extensions else None

    @property
    def is_unknown(self) -> bool:
        return self.mime == "application/octet-stream" and self.category == "unknown"

    def matches_extension(self, ext: Optional[str]) -> bool:
        from .extension import normalize_extension  # local import to avoid a cycle

        if not ext:
            return False
        norm = normalize_extension(ext)
        return norm in self.extensions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mime": self.mime,
            "extensions": list(self.extensions),
            "description": self.description,
            "category": self.category,
        }


UNKNOWN_TYPE = DetectedType("application/octet-stream", (), "Unknown binary data", "unknown")


@dataclass
class ArchiveEntry:
    name: str
    size: int
    compressed_size: int
    is_dir: bool = False
    is_symlink: bool = False
    link_target: Optional[str] = None


@dataclass
class ArchiveReport:
    """Summary of a ZIP/TAR/gzip inspection."""

    format: str
    entry_count: int = 0
    total_uncompressed: int = 0
    total_compressed: int = 0
    max_depth: int = 0
    nested_archives: List[str] = field(default_factory=list)
    unsafe_paths: List[str] = field(default_factory=list)
    truncated: bool = False  # inspection stopped early because a limit was hit
    verified: bool = False  # sizes were verified by actually decompressing

    @property
    def ratio(self) -> float:
        if self.total_compressed <= 0:
            return float("inf") if self.total_uncompressed > 0 else 0.0
        return self.total_uncompressed / self.total_compressed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format,
            "entry_count": self.entry_count,
            "total_uncompressed": self.total_uncompressed,
            "total_compressed": self.total_compressed,
            "ratio": None if self.ratio == float("inf") else round(self.ratio, 2),
            "max_depth": self.max_depth,
            "nested_archives": list(self.nested_archives),
            "unsafe_paths": list(self.unsafe_paths),
            "truncated": self.truncated,
            "verified": self.verified,
        }


@dataclass
class ScanResult:
    """Everything upload_guard learned about one upload."""

    ok: bool
    filename: Optional[str]
    safe_filename: Optional[str]
    declared_extension: Optional[str]
    declared_content_type: Optional[str]
    detected: DetectedType
    size: Optional[int]
    findings: List[Finding] = field(default_factory=list)
    archive: Optional[ArchiveReport] = None
    sanitized: Optional[bytes] = None  # cleaned content (SVG) when sanitizing was enabled

    @property
    def mime(self) -> str:
        return self.detected.mime

    @property
    def extension(self) -> Optional[str]:
        """Extension that should be used when storing the file (detected, else declared)."""
        return self.detected.extension or self.declared_extension

    @property
    def errors(self) -> List[Finding]:
        """Findings that caused (or would cause) rejection."""
        return [f for f in self.findings if not f.remediated and f.severity >= self._threshold]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.remediated or f.severity < self._threshold]

    _threshold: Severity = field(default=Severity.MEDIUM, repr=False, compare=False)

    def highest_severity(self) -> Optional[Severity]:
        active = [f.severity for f in self.findings if not f.remediated]
        return max(active) if active else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "filename": self.filename,
            "safe_filename": self.safe_filename,
            "declared_extension": self.declared_extension,
            "declared_content_type": self.declared_content_type,
            "detected": self.detected.to_dict(),
            "size": self.size,
            "findings": [f.to_dict() for f in self.findings],
            "archive": self.archive.to_dict() if self.archive else None,
            "sanitized": self.sanitized is not None,
        }
