"""Filename safety: path traversal, null bytes, Unicode spoofing, reserved names,
dangerous and double extensions, plus a conservative sanitiser."""
from __future__ import annotations

import re
import unicodedata
from typing import FrozenSet, Iterable, List, Optional

from ..extension import all_extensions, canonical_extension, known_extensions, split_filename
from ..types import Finding, Severity

#: Extensions that a web server, OS or office suite may *execute*.
DANGEROUS_EXTENSIONS: FrozenSet[str] = frozenset({
    # Windows executables / installers
    "exe", "dll", "com", "scr", "pif", "msi", "msp", "mst", "cpl", "sys", "drv", "ocx", "efi",
    "bat", "cmd", "ps1", "psm1", "psd1", "ps1xml", "ps2", "psc1", "vbs", "vbe", "js", "jse", "ws", "wsf",
    "wsc", "wsh", "hta", "msc", "lnk", "inf", "reg", "scf", "url", "application", "gadget", "appx",
    "msix", "appref-ms", "chm", "hlp", "jar", "jnlp", "class", "iso", "img", "vhd", "vhdx", "apk",
    # Unix
    "sh", "bash", "zsh", "ksh", "csh", "fish", "run", "elf", "so", "deb", "rpm", "pkg", "dmg",
    "app", "command", "desktop", "action", "workflow", "service", "osx",
    # Server-side scripts
    "php", "php3", "php4", "php5", "php7", "php8", "phps", "phtml", "phar", "pht", "phpt",
    "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx", "axd", "cer", "config", "cshtml", "vbhtml",
    "jsp", "jspx", "jsw", "jsv", "jspf", "do", "cgi", "pl", "pm", "py", "pyc", "pyo", "pyw",
    "rb", "erb", "cfm", "cfml", "cfc", "shtml", "shtm", "stm", "htaccess", "htpasswd", "swf",
    # Office macro formats
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm",
    # Others that execute code when opened
    "pkl", "pickle", "dex", "wasm", "ipa", "xpi", "crx",
})

#: Extensions that are *rendered by browsers as active content*.
BROWSER_ACTIVE_EXTENSIONS: FrozenSet[str] = frozenset({"html", "htm", "xhtml", "xht", "svg", "svgz", "mht", "mhtml", "xml", "xsl", "xslt", "shtml"})

WINDOWS_RESERVED_NAMES: FrozenSet[str] = frozenset(
    {"con", "prn", "aux", "nul", "clock$", "config$"} | {"com%d" % i for i in range(1, 10)} | {"lpt%d" % i for i in range(1, 10)}
)

SERVER_CONFIG_FILES: FrozenSet[str] = frozenset({".htaccess", ".htpasswd", "web.config", ".user.ini", "php.ini", ".env", "wp-config.php", "nginx.conf", ".git", ".svn", ".ds_store"})

_BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩؜‎‏]")
_INVISIBLE = re.compile("[​-‍⁠﻿­᠎ㅤᅟᅠﾠ]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_DRIVE = re.compile(r"^[A-Za-z]:")
_UNC = re.compile(r"^\\\\|^//")
_UNSAFE_CHARS = re.compile(r'[<>:"/\\|?*]')
_MULTI_UNDERSCORE = re.compile(r"_{2,}")


def check_filename(
    filename: Optional[str],
    *,
    dangerous_extensions: Iterable[str] = DANGEROUS_EXTENSIONS,
    max_length: int = 255,
    flag_browser_active: bool = False,
) -> List[Finding]:
    """Inspect a client-supplied filename and return findings (never raises)."""
    findings: List[Finding] = []
    if filename is None or filename == "":
        return [Finding("filename.empty", Severity.HIGH, "No filename was provided")]
    dangerous = {canonical_extension(e) for e in dangerous_extensions}

    if "\x00" in filename:
        findings.append(Finding("filename.null_byte", Severity.CRITICAL, "Filename contains a null byte (extension truncation attack)"))
    if _CONTROL.sub("", filename.replace("\x00", "")) != filename.replace("\x00", ""):
        findings.append(Finding("filename.control_chars", Severity.HIGH, "Filename contains control characters"))
    if _BIDI_CONTROLS.search(filename):
        findings.append(Finding("filename.bidi_override", Severity.CRITICAL, "Filename contains Unicode bidirectional override characters (extension spoofing, e.g. RTLO)"))
    if _INVISIBLE.search(filename):
        findings.append(Finding("filename.invisible_chars", Severity.MEDIUM, "Filename contains zero-width/invisible characters"))

    normalized = filename.replace("\\", "/")
    components = normalized.split("/")
    if any(c == ".." for c in components) or normalized in (".", ".."):
        findings.append(Finding("filename.path_traversal", Severity.CRITICAL, "Filename contains a path traversal sequence ('..')"))
    if "/" in normalized:
        findings.append(Finding("filename.path_separator", Severity.HIGH, "Filename contains a path separator", {"components": len(components)}))
    if _DRIVE.match(filename) or _UNC.match(filename) or normalized.startswith("/"):
        findings.append(Finding("filename.absolute_path", Severity.HIGH, "Filename is an absolute path"))

    base = components[-1] if components else filename
    stem, ext = split_filename(base)
    lowered = base.lower()

    if lowered in SERVER_CONFIG_FILES:
        findings.append(Finding("filename.server_config", Severity.HIGH, "Filename is a server configuration file (%s)" % base))
    elif base.startswith("."):
        findings.append(Finding("filename.hidden", Severity.LOW, "Filename is a hidden dot-file"))

    reserved_stem = lowered.split(".")[0]
    if reserved_stem in WINDOWS_RESERVED_NAMES:
        findings.append(Finding("filename.reserved_name", Severity.MEDIUM, "Filename uses a Windows reserved device name (%s)" % reserved_stem.upper()))
    if base != base.rstrip(". ") and base.strip():
        findings.append(Finding("filename.trailing_dot_space", Severity.LOW, "Filename ends with a dot or space (stripped by Windows)"))
    if len(filename) > max_length:
        findings.append(Finding("filename.too_long", Severity.MEDIUM, "Filename is longer than %d characters" % max_length, {"length": len(filename)}))

    if ext is None:
        findings.append(Finding("filename.no_extension", Severity.INFO, "Filename has no extension"))
    else:
        canon = canonical_extension(ext)
        if canon in dangerous:
            findings.append(Finding("filename.dangerous_extension", Severity.HIGH, "Extension '.%s' is executable or otherwise dangerous" % ext, {"extension": ext}))
        elif flag_browser_active and canon in BROWSER_ACTIVE_EXTENSIONS:
            findings.append(Finding("filename.browser_active", Severity.MEDIUM, "Extension '.%s' is rendered as active content by browsers" % ext, {"extension": ext}))
        exts = all_extensions(base)
        if len(exts) >= 2:
            inner = [canonical_extension(e) for e in exts[:-1]]
            known = known_extensions()
            if any(e in dangerous for e in inner):
                findings.append(Finding("filename.double_extension", Severity.MEDIUM, "Filename has an executable inner extension (%s)" % ".".join(exts), {"extensions": exts}))
            elif any(e in known for e in inner):
                findings.append(Finding("filename.double_extension", Severity.INFO, "Filename has multiple extensions (%s)" % ".".join(exts), {"extensions": exts}))
    return findings


def sanitize_filename(
    filename: Optional[str],
    *,
    replacement: str = "_",
    max_length: int = 255,
    default: str = "upload",
    ascii_only: bool = False,
    keep_extension: bool = True,
) -> str:
    """Return a filename that is safe to use on any filesystem.

    - takes the last path component (both ``/`` and ``\\``)
    - drops null bytes, control, bidi-override and invisible characters
    - NFKC-normalises Unicode (optionally transliterates to ASCII)
    - replaces ``<>:"/\\|?*`` with ``replacement``
    - strips leading/trailing dots and spaces, avoids Windows reserved names
    - truncates to ``max_length`` bytes while keeping the extension
    """
    if not filename:
        return default
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL.sub("", name)
    name = _BIDI_CONTROLS.sub("", name)
    name = _INVISIBLE.sub("", name)
    name = unicodedata.normalize("NFKC", name)
    if ascii_only:
        name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    name = _UNSAFE_CHARS.sub(replacement, name)
    name = re.sub(r"\s+", " ", name).strip()
    name = name.strip(". ")
    if replacement:
        name = re.sub(re.escape(replacement) + "{2,}", replacement, name)
    if not name:
        return default

    stem, ext = split_filename(name)
    if ext and not keep_extension:
        stem, ext = name, None
    stem = stem.strip(". ") or default
    if stem.lower().split(".")[0] in WINDOWS_RESERVED_NAMES:
        stem = "_" + stem

    suffix = "." + name[len(name) - len(ext) :] if ext else ""  # keep the original case of the extension
    budget = max_length - len(suffix.encode("utf-8"))
    if budget < 1:
        return default
    encoded = stem.encode("utf-8")
    if len(encoded) > budget:
        stem = encoded[:budget].decode("utf-8", "ignore").rstrip(". ")
    if not stem:
        stem = default
    return stem + suffix
