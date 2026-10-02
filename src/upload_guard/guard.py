"""The :class:`UploadGuard` orchestrator: policy + all checks → :class:`ScanResult`."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, FrozenSet, List, Optional, Sequence, Union

from .adapters import FileSource
from .exceptions import UploadRejected
from .extension import (
    TypeRule,
    any_rule_matches,
    canonical_extension,
    compile_rules,
    extension_matches,
    known_extensions,
    split_filename,
    types_for_extension,
)
from .security.archive import DEFAULT_LIMITS, ArchiveLimits, archive_kind, gunzip_capped, inspect_archive
from .security.filename import DANGEROUS_EXTENSIONS, check_filename, sanitize_filename
from .security.polyglot import check_trailing, scan_embedded
from .security.svg import DEFAULT_POLICY as DEFAULT_SVG_POLICY
from .security.svg import SvgPolicy, sanitize_svg, scan_svg
from .sniff import HEADER_SIZE, detect
from .types import DetectedType, Finding, ScanResult, Severity

_GENERIC_CONTENT_TYPES = frozenset({"", "application/octet-stream", "binary/octet-stream", "application/unknown", "application/x-unknown", "unknown/unknown", "multipart/form-data"})


@dataclass(frozen=True)
class Policy:
    """Everything that decides whether an upload is accepted.

    ``allowed`` / ``blocked`` take rules such as ``"image/*"``,
    ``"application/pdf"``, ``".docx"`` or ``"category:archive"`` and are
    evaluated against the *detected* type, never the declared one.
    """

    allowed: Optional[Sequence[Union[str, TypeRule]]] = None
    blocked: Sequence[Union[str, TypeRule]] = ("category:executable", "category:script")
    max_size: Optional[int] = None
    min_size: int = 1
    require_extension: bool = True
    strict_extension: bool = True
    check_content_type: bool = True
    allow_unknown: bool = False
    sanitize_svg: bool = True
    svg_policy: SvgPolicy = DEFAULT_SVG_POLICY
    inspect_archives: bool = True
    archive_limits: ArchiveLimits = DEFAULT_LIMITS
    polyglot_scan_limit: int = 1024 * 1024  # bytes searched for embedded signatures (0 disables)
    check_trailing_data: bool = True
    dangerous_extensions: FrozenSet[str] = DANGEROUS_EXTENSIONS
    flag_browser_active_extensions: bool = False
    filename_max_length: int = 255
    reject_threshold: Severity = Severity.MEDIUM
    filename_replacement: str = "_"
    ascii_filenames: bool = False

    def with_(self, **changes: Any) -> "Policy":
        return replace(self, **changes)


class UploadGuard:
    """Validate uploads against a :class:`Policy`.

    ::

        guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=10 * 1024 * 1024)
        result = guard.check(upload_file)        # raises UploadRejected on failure
        result = guard.scan(upload_file)         # never raises; inspect result.ok
    """

    def __init__(self, policy: Optional[Policy] = None, **overrides: Any) -> None:
        base = policy or Policy()
        self.policy = base.with_(**overrides) if overrides else base
        self._allowed = compile_rules(self.policy.allowed)
        self._blocked = compile_rules(self.policy.blocked)

    # -- public API -----------------------------------------------------------------
    def check(self, source: Any, *, filename: Optional[str] = None, content_type: Optional[str] = None, raise_on_fail: bool = True) -> ScanResult:
        result = self.scan(source, filename=filename, content_type=content_type)
        if raise_on_fail and not result.ok:
            raise UploadRejected(result)
        return result

    def scan(self, source: Any, *, filename: Optional[str] = None, content_type: Optional[str] = None) -> ScanResult:
        p = self.policy
        max_read = p.max_size if p.max_size is not None else None
        src = FileSource.from_any(source, filename=filename, content_type=content_type, max_read=max_read)
        try:
            return self._scan_source(src)
        finally:
            src.close()

    def is_safe(self, source: Any, **kw: Any) -> bool:
        return self.scan(source, **kw).ok

    # -- pipeline -------------------------------------------------------------------
    def _scan_source(self, src: FileSource) -> ScanResult:
        p = self.policy
        findings: List[Finding] = []
        name = src.filename
        declared_ext = split_filename(name)[1] if name else None
        declared_ct = _normalize_content_type(src.content_type)

        # 1. size
        size = src.size
        if src.oversized:
            findings.append(Finding("size.too_large", Severity.HIGH, "Upload exceeds the maximum size of %d bytes" % (p.max_size or 0), {"max_size": p.max_size}))
        elif size is not None:
            if size < p.min_size:
                findings.append(Finding("size.empty" if size == 0 else "size.too_small", Severity.HIGH, "Upload is empty" if size == 0 else "Upload is smaller than %d bytes" % p.min_size, {"size": size}))
            if p.max_size is not None and size > p.max_size:
                findings.append(Finding("size.too_large", Severity.HIGH, "Upload is %d bytes, larger than the limit of %d" % (size, p.max_size), {"size": size, "max_size": p.max_size}))

        # 2. magic-number detection
        head = src.read_head(HEADER_SIZE)
        detected = detect(head, src.stream)

        # 3. filename
        fn_findings = check_filename(name, dangerous_extensions=p.dangerous_extensions, max_length=p.filename_max_length, flag_browser_active=p.flag_browser_active_extensions)
        for f in fn_findings:
            if f.code == "filename.no_extension":
                if p.require_extension:
                    findings.append(Finding("extension.missing", Severity.HIGH, "Filename has no extension"))
                else:
                    findings.append(f)
            elif f.code == "filename.empty" and not p.require_extension:
                findings.append(Finding("filename.empty", Severity.INFO, f.message))
            else:
                findings.append(f)

        # 4. type / extension consistency
        if detected.is_unknown:
            if not p.allow_unknown:
                findings.append(Finding("type.unknown", Severity.HIGH, "File type could not be identified from its content", {"head": head[:16].hex()}))
        elif declared_ext and p.strict_extension and not extension_matches(declared_ext, detected):
            if detected.mime == "text/plain" and canonical_extension(declared_ext) not in known_extensions():
                findings.append(Finding("extension.unknown", Severity.LOW, "Extension '.%s' is not known; content is plain text" % declared_ext, {"declared": declared_ext}))
            else:
                findings.append(Finding(
                    "extension.mismatch", Severity.HIGH,
                    "Extension '.%s' does not match detected type %s (expected .%s)" % (declared_ext, detected.mime, "/.".join(detected.extensions[:3]) or "?"),
                    {"declared": declared_ext, "detected_mime": detected.mime, "expected": list(detected.extensions)},
                ))

        if p.check_content_type and declared_ct and declared_ct not in _GENERIC_CONTENT_TYPES and not detected.is_unknown:
            if not _content_type_compatible(declared_ct, detected):
                findings.append(Finding("content_type.mismatch", Severity.LOW, "Declared Content-Type %s does not match detected %s" % (declared_ct, detected.mime), {"declared": declared_ct, "detected": detected.mime}))

        # 5. allow / block lists
        if self._blocked and any_rule_matches(self._blocked, detected):
            findings.append(Finding("type.blocked", Severity.HIGH, "%s (%s) is blocked by policy" % (detected.description or detected.mime, detected.mime), {"mime": detected.mime}))
        if self._allowed and not any_rule_matches(self._allowed, detected):
            findings.append(Finding("type.not_allowed", Severity.HIGH, "%s (%s) is not in the allowed types" % (detected.description or detected.mime, detected.mime), {"mime": detected.mime}))

        # 6. content-specific checks
        sanitized: Optional[bytes] = None
        archive_report = None
        if size is None or size > 0:
            svg_bytes = self._svg_payload(src, detected, declared_ext)
            if svg_bytes is not None:
                sanitized = self._check_svg(svg_bytes, findings)
            if p.inspect_archives and archive_kind(detected.mime, head):
                archive_report, arch_findings = inspect_archive(src.stream, detected.mime, p.archive_limits, head)
                findings.extend(arch_findings)
            if p.polyglot_scan_limit and detected.category in ("image", "document", "font", "audio", "video", "data", "unknown") and not archive_kind(detected.mime, head):
                chunk = src.read_head(p.polyglot_scan_limit)
                findings.extend(scan_embedded(chunk, detected))
            if p.check_trailing_data and size:
                findings.extend(check_trailing(src.stream, detected, size))

        ok = not any(f.severity >= p.reject_threshold and not f.remediated for f in findings)
        safe_name = self._safe_filename(name, declared_ext, detected)
        result = ScanResult(
            ok=ok,
            filename=name,
            safe_filename=safe_name,
            declared_extension=declared_ext,
            declared_content_type=src.content_type,
            detected=detected,
            size=size,
            findings=findings,
            archive=archive_report,
            sanitized=sanitized,
        )
        result._threshold = p.reject_threshold
        return result

    # -- helpers --------------------------------------------------------------------
    def _svg_payload(self, src: FileSource, detected: DetectedType, declared_ext: Optional[str]) -> Optional[bytes]:
        cap = self.policy.svg_policy.max_bytes
        if detected.mime != "image/svg+xml":
            return None
        if "svgz" in detected.extensions:  # gzip-compressed SVG: inflate with a hard cap first
            return gunzip_capped(src.stream, cap)
        return src.read_all(cap)

    def _check_svg(self, data: Optional[bytes], findings: List[Finding]) -> Optional[bytes]:
        p = self.policy
        if data is None:
            findings.append(Finding("svg.too_large", Severity.HIGH, "SVG larger than %d bytes" % p.svg_policy.max_bytes))
            return None
        if p.sanitize_svg:
            res = sanitize_svg(data, p.svg_policy)
            findings.extend(res.findings)
            return res.sanitized
        findings.extend(scan_svg(data, p.svg_policy))
        return None

    def _safe_filename(self, name: Optional[str], declared_ext: Optional[str], detected: DetectedType) -> Optional[str]:
        p = self.policy
        safe = sanitize_filename(name, replacement=p.filename_replacement, max_length=p.filename_max_length, ascii_only=p.ascii_filenames)
        _, ext = split_filename(safe)
        if ext is None and detected.extension:
            safe = safe + "." + detected.extension
        return safe


def _normalize_content_type(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return value.split(";", 1)[0].strip().lower()


def _content_type_compatible(declared: str, detected: DetectedType) -> bool:
    if declared == detected.mime.lower():
        return True
    aliases = {
        "image/jpg": "image/jpeg", "image/pjpeg": "image/jpeg", "image/x-png": "image/png",
        "application/x-pdf": "application/pdf", "text/xml": "application/xml", "application/x-zip-compressed": "application/zip",
        "application/x-gzip": "application/gzip", "audio/x-wav": "audio/wav", "audio/wave": "audio/wav", "audio/mp3": "audio/mpeg",
        "image/vnd.microsoft.icon": "image/x-icon", "application/x-rar-compressed": "application/vnd.rar",
        "application/vnd.ms-excel.sheet.macroenabled.12": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-word.document.macroenabled.12": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "video/x-m4v": "video/mp4", "audio/x-m4a": "audio/mp4", "application/x-tar": "application/x-tar", "application/javascript": "text/javascript",
    }
    if aliases.get(declared) == detected.mime.lower():
        return True
    # declared type belongs to a type that shares an extension with the detected one
    if detected.category == "text" and declared.startswith("text/"):
        return True
    for ext in detected.extensions:
        for t in types_for_extension(ext):
            if t.mime.lower() == declared or aliases.get(declared) == t.mime.lower():
                return True
    return False


def check(source: Any, *, filename: Optional[str] = None, content_type: Optional[str] = None, raise_on_fail: bool = True, **policy: Any) -> ScanResult:
    """One-shot convenience: ``check(data, filename="x.png", allowed=["image/*"])``."""
    return UploadGuard(**policy).check(source, filename=filename, content_type=content_type, raise_on_fail=raise_on_fail)


def scan(source: Any, *, filename: Optional[str] = None, content_type: Optional[str] = None, **policy: Any) -> ScanResult:
    return UploadGuard(**policy).scan(source, filename=filename, content_type=content_type)


def detect_type(source: Any) -> DetectedType:
    """Detect the type of bytes / a path / a file object / an upload object."""
    src = FileSource.from_any(source)
    try:
        return detect(src.read_head(HEADER_SIZE), src.stream)
    finally:
        src.close()
