"""Second-stage refinement for container formats and weak signatures.

A signature such as ``RIFF`` or ``PK\\x03\\x04`` only tells us the *container*;
the real type lives a little deeper (``WEBP`` at offset 8, ``word/document.xml``
inside the zip, ...).  Functions here take the already-read header (and an
optional seekable stream for cheap deeper peeks) and either return a more
precise :class:`DetectedType`, the original type, or ``None`` when the
signature turned out to be a false positive and matching should continue.
"""
from __future__ import annotations

import struct
import zipfile
import zlib
from typing import BinaryIO, Callable, Dict, List, Optional

from ..types import DetectedType
from . import signatures as S

# Legacy Office / OLE2 sub-types resolved from the compound-file directory.
DOC = S.T("application/msword", ("doc", "dot", "wbk"), "Word 97-2003 document", "document")
XLS = S.T("application/vnd.ms-excel", ("xls", "xlt", "xla"), "Excel 97-2003 workbook", "document")
PPT = S.T("application/vnd.ms-powerpoint", ("ppt", "pps", "pot"), "PowerPoint 97-2003 presentation", "document")
MSG = S.T("application/vnd.ms-outlook", ("msg",), "Outlook message", "document")
MSI = S.T("application/x-msi", ("msi", "msp", "mst"), "Windows Installer package", "executable")
VSD = S.T("application/vnd.visio", ("vsd", "vss", "vst"), "Visio 2003 drawing", "document")
RIFF_GENERIC = S.T("application/x-riff", ("riff",), "RIFF container", "data")
IFF_GENERIC = S.T("application/x-iff", ("iff",), "IFF container", "data")
MACHO_FAT = S.T("application/x-mach-binary", ("macho", "dylib"), "Mach-O universal binary", "executable")
GZIP_TAR = S.T("application/gzip", ("tgz", "gz", "tar.gz"), "gzip compressed tar archive", "archive")
# Browsers treat .svgz as an SVG delivered with Content-Encoding: gzip, so it is
# classified as an image for policy purposes; the guard gunzips it (bounded) before scanning.
GZIP_SVG = S.T("image/svg+xml", ("svgz",), "gzip compressed SVG", "image")


def read_at(stream: Optional[BinaryIO], offset: int, size: int) -> bytes:
    """Read ``size`` bytes at ``offset`` from a seekable stream, restoring the position."""
    if stream is None:
        return b""
    try:
        pos = stream.tell()
    except (AttributeError, OSError, ValueError):
        return b""
    try:
        stream.seek(offset)
        return stream.read(size) or b""
    except (OSError, ValueError):
        return b""
    finally:
        try:
            stream.seek(pos)
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# RIFF / IFF
# ---------------------------------------------------------------------------
_RIFF_FORMS = {b"WAVE": S.WAV, b"AVI ": S.AVI, b"WEBP": S.WEBP}


def _refine_riff(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    form = head[8:12]
    return _RIFF_FORMS.get(form, RIFF_GENERIC)


def _refine_form(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    form = head[8:12]
    if form in (b"AIFF", b"AIFC"):
        return S.AIFF
    return IFF_GENERIC


# ---------------------------------------------------------------------------
# ISO base media (ftyp): MP4 / MOV / HEIC / AVIF / 3GP / CR3
# ---------------------------------------------------------------------------
_FTYP_BRANDS = {
    b"isom": S.MP4, b"iso2": S.MP4, b"iso3": S.MP4, b"iso4": S.MP4, b"iso5": S.MP4, b"iso6": S.MP4,
    b"mp41": S.MP4, b"mp42": S.MP4, b"avc1": S.MP4, b"dash": S.MP4, b"MSNV": S.MP4, b"M4V ": S.MP4,
    b"M4VH": S.MP4, b"M4VP": S.MP4, b"XAVC": S.MP4, b"mmp4": S.MP4, b"NDSC": S.MP4,
    b"M4A ": S.M4A, b"M4B ": S.M4A, b"M4P ": S.M4A, b"mp71": S.M4A,
    b"qt  ": S.MOV,
    b"heic": S.HEIC, b"heix": S.HEIC, b"hevc": S.HEIC, b"hevx": S.HEIC, b"heim": S.HEIC,
    b"heis": S.HEIC, b"hevm": S.HEIC, b"hevs": S.HEIC, b"mif1": S.HEIC, b"msf1": S.HEIC,
    b"avif": S.AVIF, b"avis": S.AVIF,
    b"3gp4": S.THREEGP, b"3gp5": S.THREEGP, b"3gp6": S.THREEGP, b"3gp7": S.THREEGP,
    b"3ge6": S.THREEGP, b"3ge7": S.THREEGP, b"3gg6": S.THREEGP, b"3g2a": S.THREEGP, b"3g2b": S.THREEGP,
    b"crx ": S.CR3,
}


def _refine_ftyp(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    brand = head[8:12]
    if brand in _FTYP_BRANDS:
        return _FTYP_BRANDS[brand]
    if brand[:3] == b"3gp" or brand[:3] == b"3g2":
        return S.THREEGP
    # compatible brands follow the minor version (bytes 12..16)
    box_len = struct.unpack(">I", head[0:4])[0] if len(head) >= 4 else 0
    box_len = min(box_len, len(head), 256) if box_len else min(len(head), 64)
    for i in range(16, box_len - 3, 4):
        compat = head[i : i + 4]
        if compat in _FTYP_BRANDS:
            return _FTYP_BRANDS[compat]
    return S.MP4


# ---------------------------------------------------------------------------
# EBML: Matroska vs WebM
# ---------------------------------------------------------------------------
def _refine_ebml(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    window = head[:128]
    idx = window.find(b"\x42\x82")  # DocType element id
    if idx != -1:
        # size is a vint; DocType strings are short so a 1-byte size is expected
        size_byte = window[idx + 2] if idx + 2 < len(window) else 0
        size = size_byte & 0x7F
        doctype = window[idx + 3 : idx + 3 + size]
        if doctype.startswith(b"webm"):
            return S.WEBM
        if doctype.startswith(b"matroska"):
            return S.MKV
    if b"webm" in window:
        return S.WEBM
    return S.MKV


# ---------------------------------------------------------------------------
# Weak-signature sanity checks (return None → false positive)
# ---------------------------------------------------------------------------
def _refine_bmp(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 26:
        return None
    reserved = head[6:10]
    data_offset = struct.unpack("<I", head[10:14])[0]
    dib_size = struct.unpack("<I", head[14:18])[0]
    if reserved != b"\x00\x00\x00\x00":
        return None
    if data_offset < 26 or data_offset > 16 * 1024 * 1024:
        return None
    if dib_size not in (12, 16, 40, 52, 56, 64, 108, 124):
        return None
    return S.BMP


def _refine_ico(expected: DetectedType) -> Callable[[bytes, Optional[BinaryIO]], Optional[DetectedType]]:
    def _refine(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
        if len(head) < 22:
            return None
        count = struct.unpack("<H", head[4:6])[0]
        if not 1 <= count <= 256:
            return None
        # first directory entry: width, height, colors, reserved(0), planes, bpp, size, offset
        if head[9] != 0:
            return None
        size = struct.unpack("<I", head[14:18])[0]
        offset = struct.unpack("<I", head[18:22])[0]
        if offset < 6 + 16 * count or size == 0:
            return None
        return expected

    return _refine


def _refine_ttf(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 12:
        return None
    num_tables = struct.unpack(">H", head[4:6])[0]
    if not 1 <= num_tables <= 64:
        return None
    return S.TTF


def _refine_mpeg_ts(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 377:
        return None
    if head[188] == 0x47 and head[376] == 0x47:
        return S.MPEG_TS
    return None


def _refine_mp3_frame(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 4:
        return None
    b2 = head[2]
    bitrate_index = b2 >> 4
    sampling_index = (b2 >> 2) & 0x03
    if bitrate_index in (0x0, 0xF) or sampling_index == 3:
        return None
    return S.MP3


def _refine_cafebabe(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 8:
        return S.JAVA_CLASS
    value = struct.unpack(">I", head[4:8])[0]
    # Mach-O fat header: nfat_arch is a small number; Java class: minor<<16|major (major >= 45)
    if value < 45:  # Java class major versions start at 45 (JDK 1.1)
        return MACHO_FAT
    return S.JAVA_CLASS


def _refine_mz(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 0x40:
        return S.PE
    e_lfanew = struct.unpack("<I", head[0x3C:0x40])[0]
    if e_lfanew + 4 <= len(head):
        if head[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            return S.PE
    elif e_lfanew < 4 * 1024 * 1024:
        chunk = read_at(stream, e_lfanew, 4)
        if chunk == b"PE\x00\x00":
            return S.PE
    # Not a PE, but an MZ stub is still a DOS/NE/LE executable.
    return S.PE


def _refine_arj(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 34:
        return None
    header_size = struct.unpack("<H", head[2:4])[0]
    if not 30 <= header_size <= 2600:
        return None
    if head[10] != 2 or head[11] != 0:  # file type must be 2 (main header), reserved 0
        return None
    return S.ARJ


def _refine_eot(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    if len(head) < 36:
        return None
    eot_size = struct.unpack("<I", head[0:4])[0]
    font_data_size = struct.unpack("<I", head[4:8])[0]
    if eot_size == 0 or font_data_size == 0 or font_data_size >= eot_size:
        return None
    return S.EOT


def _refine_pickle(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    return S.PICKLE


# ---------------------------------------------------------------------------
# ZIP-based containers: OOXML, ODF, EPUB, JAR, APK, XPI, XPS
# ---------------------------------------------------------------------------
_MIMETYPE_MAP: Dict[bytes, DetectedType] = {
    b"application/epub+zip": S.EPUB,
    b"application/vnd.oasis.opendocument.text": S.ODT,
    b"application/vnd.oasis.opendocument.spreadsheet": S.ODS,
    b"application/vnd.oasis.opendocument.presentation": S.ODP,
    b"application/vnd.oasis.opendocument.graphics": S.ODG,
}


def zip_local_entry_names(head: bytes, limit: int = 64) -> List[str]:
    """Walk consecutive local file headers that fit inside ``head``.

    Also returns the raw content of a stored ``mimetype`` entry via the
    special key ``"\\x00mimetype"`` when present (ODF/EPUB keep it first).
    """
    names: List[str] = []
    pos = 0
    while pos + 30 <= len(head) and len(names) < limit:
        if head[pos : pos + 4] != b"PK\x03\x04":
            break
        flags, method = struct.unpack("<HH", head[pos + 6 : pos + 10])
        comp_size = struct.unpack("<I", head[pos + 18 : pos + 22])[0]
        name_len, extra_len = struct.unpack("<HH", head[pos + 26 : pos + 30])
        name_start = pos + 30
        name = head[name_start : name_start + name_len]
        if len(name) < name_len:
            break
        decoded = name.decode("utf-8", "replace")
        names.append(decoded)
        data_start = name_start + name_len + extra_len
        if decoded == "mimetype" and method == 0 and comp_size:
            content = head[data_start : data_start + comp_size]
            names.append("\x00mimetype:" + content.decode("ascii", "replace").strip())
        if flags & 0x08 and comp_size == 0:
            break  # size lives in a data descriptor we cannot locate cheaply
        pos = data_start + comp_size
    return names


def classify_zip_names(names: List[str], mimetype: Optional[str] = None) -> DetectedType:
    if mimetype:
        for key, t in _MIMETYPE_MAP.items():
            if mimetype.encode("ascii", "ignore").startswith(key):
                return t
    lowered = [n.lower() for n in names]
    has = lambda prefix: any(n.startswith(prefix) for n in lowered)  # noqa: E731
    if has("word/"):
        return S.DOCX
    if has("xl/"):
        return S.XLSX
    if has("ppt/"):
        return S.PPTX
    if has("visio/"):
        return S.T("application/vnd.ms-visio.drawing", ("vsdx", "vsdm"), "Visio drawing (OOXML)", "document")
    if "androidmanifest.xml" in lowered or "classes.dex" in lowered:
        return S.APK
    if "meta-info/mozilla.rsa" in lowered or ("manifest.json" in lowered and has("meta-inf/mozilla")):
        return S.XPI
    if "meta-inf/manifest.mf" in lowered:
        return S.JAR
    if "fixeddocumentsequence.fdseq" in lowered or "fixeddocseq.fdseq" in lowered:
        return S.XPS
    if "[content_types].xml" in lowered:
        return S.OOXML
    return S.ZIP


def _refine_zip(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    names: List[str] = []
    mimetype: Optional[str] = None
    if stream is not None:
        try:
            pos = stream.tell()
            try:
                stream.seek(0)
                with zipfile.ZipFile(stream) as zf:
                    infos = zf.infolist()[:512]
                    names = [i.filename for i in infos]
                    for info in infos:
                        if info.filename == "mimetype" and info.file_size < 256:
                            mimetype = zf.read(info).decode("ascii", "replace").strip()
                            break
            finally:
                stream.seek(pos)
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError, NotImplementedError):
            names = []
    if not names:
        for n in zip_local_entry_names(head):
            if n.startswith("\x00mimetype:"):
                mimetype = n.split(":", 1)[1]
            else:
                names.append(n)
    return classify_zip_names(names, mimetype)


# ---------------------------------------------------------------------------
# OLE2 compound files: DOC / XLS / PPT / MSG / MSI
# ---------------------------------------------------------------------------
def ole2_directory_names(head: bytes, stream: Optional[BinaryIO], max_sectors: int = 16) -> List[str]:
    """Return stream/storage names from the compound-file directory (best effort)."""
    if len(head) < 512:
        return []
    sector_shift = struct.unpack("<H", head[0x1E:0x20])[0]
    if sector_shift not in (9, 12):
        return []
    sector_size = 1 << sector_shift
    first_dir_sid = struct.unpack("<I", head[0x30:0x34])[0]
    difat = list(struct.unpack("<109I", head[0x4C : 0x4C + 436]))
    entries_per_fat = sector_size // 4
    names: List[str] = []

    def sector_bytes(sid: int) -> bytes:
        offset = (sid + 1) * sector_size
        if offset + sector_size <= len(head):
            return head[offset : offset + sector_size]
        return read_at(stream, offset, sector_size)

    def next_sid(sid: int) -> int:
        fat_index = sid // entries_per_fat
        if fat_index >= len(difat):
            return 0xFFFFFFFE
        fat_sid = difat[fat_index]
        if fat_sid >= 0xFFFFFFFA:
            return 0xFFFFFFFE
        fat = sector_bytes(fat_sid)
        pos = (sid % entries_per_fat) * 4
        if len(fat) < pos + 4:
            return 0xFFFFFFFE
        return struct.unpack("<I", fat[pos : pos + 4])[0]

    sid = first_dir_sid
    seen = set()
    for _ in range(max_sectors):
        if sid >= 0xFFFFFFFA or sid in seen:
            break
        seen.add(sid)
        data = sector_bytes(sid)
        if len(data) < 128:
            break
        for off in range(0, len(data) - 127, 128):
            name_len = struct.unpack("<H", data[off + 64 : off + 66])[0]
            if 2 <= name_len <= 64:
                raw = data[off : off + name_len - 2]
                try:
                    names.append(raw.decode("utf-16-le"))
                except UnicodeDecodeError:
                    continue
        sid = next_sid(sid)
    return names


def _refine_ole2(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    names = ole2_directory_names(head, stream)
    if not names:
        return S.OLE2
    if "WordDocument" in names:
        return DOC
    if "Workbook" in names or "Book" in names:
        return XLS
    if "PowerPoint Document" in names:
        return PPT
    if "VisioDocument" in names:
        return VSD
    if any(n.startswith("__substg1.0_") or n == "__properties_version1.0" for n in names):
        return MSG
    # MSI tables are stored with names encoded in a private UTF-16 range (U+3800..U+4840)
    if any(n and 0x3800 <= ord(n[0]) <= 0x4840 for n in names):
        return MSI
    return S.OLE2


# ---------------------------------------------------------------------------
# gzip: peek at the decompressed start to recognise .tgz / .svgz
# ---------------------------------------------------------------------------
def _refine_gzip(head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    try:
        d = zlib.decompressobj(wbits=31)
        inner = d.decompress(head, 600)
    except zlib.error:
        return S.GZIP
    if len(inner) >= 262 and inner[257:262] == b"ustar":
        return GZIP_TAR
    stripped = inner.lstrip()
    if stripped[:5] == b"<?xml" or stripped[:4] == b"<svg":
        if b"<svg" in inner:
            return GZIP_SVG
    return S.GZIP


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
Refiner = Callable[[bytes, Optional[BinaryIO]], Optional[DetectedType]]

_REFINERS: Dict[int, Refiner] = {
    id(S.WAV): _refine_riff,
    id(S.AIFF): _refine_form,
    id(S.MP4): _refine_ftyp,
    id(S.MKV): _refine_ebml,
    id(S.BMP): _refine_bmp,
    id(S.ICO): _refine_ico(S.ICO),
    id(S.CUR): _refine_ico(S.CUR),
    id(S.TTF): _refine_ttf,
    id(S.MPEG_TS): _refine_mpeg_ts,
    id(S.MP3): _refine_mp3_frame,
    id(S.JAVA_CLASS): _refine_cafebabe,
    id(S.PE): _refine_mz,
    id(S.ARJ): _refine_arj,
    id(S.EOT): _refine_eot,
    id(S.PICKLE): _refine_pickle,
    id(S.ZIP): _refine_zip,
    id(S.OLE2): _refine_ole2,
    id(S.GZIP): _refine_gzip,
}


def refine(detected: DetectedType, head: bytes, stream: Optional[BinaryIO]) -> Optional[DetectedType]:
    """Refine a first-stage match. ``None`` means "false positive, keep looking"."""
    refiner = _REFINERS.get(id(detected))
    if refiner is None:
        return detected
    if detected is S.MP3 and head[:3] == b"ID3":
        return S.MP3
    if detected is S.TTF and head[:4] == b"true":
        return S.TTF
    return refiner(head, stream)
