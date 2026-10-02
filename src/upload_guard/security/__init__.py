"""Security checks: filenames, SVG, archives, polyglots."""
from .archive import ArchiveLimits, inspect_archive, inspect_compressed, inspect_zip
from .filename import DANGEROUS_EXTENSIONS, check_filename, sanitize_filename
from .polyglot import check_trailing, scan_embedded
from .svg import SvgPolicy, SvgResult, sanitize_svg, scan_svg

__all__ = [
    "ArchiveLimits", "inspect_archive", "inspect_zip", "inspect_compressed",
    "DANGEROUS_EXTENSIONS", "check_filename", "sanitize_filename",
    "check_trailing", "scan_embedded",
    "SvgPolicy", "SvgResult", "sanitize_svg", "scan_svg",
]
