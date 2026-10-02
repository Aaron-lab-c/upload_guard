"""upload_guard: pure-Python upload validation.

Quick start::

    from upload_guard import UploadGuard, UploadRejected

    guard = UploadGuard(allowed=["image/*", "application/pdf"], max_size=10 * 1024 * 1024)
    try:
        result = guard.check(upload)          # bytes, path, file object, FastAPI/Django/Flask upload
    except UploadRejected as exc:
        print(exc.codes)                      # e.g. ['extension.mismatch']
    else:
        print(result.mime, result.safe_filename, result.sanitized)
"""
from ._version import __version__
from .exceptions import UnsupportedSource, UploadGuardError, UploadRejected
from .extension import TypeRule, canonical_extension, extension_matches, normalize_extension, split_filename
from .guard import Policy, UploadGuard, check, detect_type, scan
from .security.archive import ArchiveLimits, inspect_archive, inspect_compressed, inspect_zip
from .security.filename import DANGEROUS_EXTENSIONS, check_filename, sanitize_filename
from .security.polyglot import check_trailing, scan_embedded
from .security.svg import SvgPolicy, SvgResult, sanitize_svg, scan_svg
from .sniff import HEADER_SIZE, detect, detect_stream
from .types import ArchiveReport, DetectedType, Finding, ScanResult, Severity

__all__ = [
    "__version__",
    # core
    "UploadGuard", "Policy", "check", "scan", "detect_type",
    "ScanResult", "Finding", "Severity", "DetectedType", "ArchiveReport",
    "UploadGuardError", "UploadRejected", "UnsupportedSource",
    # sniffing
    "detect", "detect_stream", "HEADER_SIZE",
    # extensions
    "TypeRule", "canonical_extension", "normalize_extension", "extension_matches", "split_filename",
    # security
    "check_filename", "sanitize_filename", "DANGEROUS_EXTENSIONS",
    "SvgPolicy", "SvgResult", "scan_svg", "sanitize_svg",
    "ArchiveLimits", "inspect_archive", "inspect_zip", "inspect_compressed",
    "scan_embedded", "check_trailing",
]
