"""Static magic-number table.

Each :class:`Signature` is matched against the header bytes at ``offset``.
Entries are checked in order of ``priority`` (higher first) and then by magic
length (longer first) so the most specific match wins.  Types whose magic is
shared by several formats (RIFF, ftyp, EBML, ZIP, OLE2) are refined later in
:mod:`upload_guard.sniff.containers`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from ..types import DetectedType


@dataclass(frozen=True)
class Signature:
    magic: bytes
    type: DetectedType
    offset: int = 0
    mask: Optional[bytes] = None  # optional bitmask applied before comparing
    priority: int = 0

    def matches(self, data: bytes) -> bool:
        end = self.offset + len(self.magic)
        if len(data) < end:
            return False
        chunk = data[self.offset : end]
        if self.mask is not None:
            chunk = bytes(c & m for c, m in zip(chunk, self.mask))
        return chunk == self.magic


def T(mime: str, exts: Tuple[str, ...], desc: str, cat: str) -> DetectedType:
    return DetectedType(mime, exts, desc, cat)


# --- Images ---------------------------------------------------------------
PNG = T("image/png", ("png",), "PNG image", "image")
JPEG = T("image/jpeg", ("jpg", "jpeg", "jpe", "jfif"), "JPEG image", "image")
GIF = T("image/gif", ("gif",), "GIF image", "image")
BMP = T("image/bmp", ("bmp", "dib"), "Windows bitmap", "image")
WEBP = T("image/webp", ("webp",), "WebP image", "image")
TIFF = T("image/tiff", ("tif", "tiff"), "TIFF image", "image")
ICO = T("image/x-icon", ("ico",), "Windows icon", "image")
CUR = T("image/x-icon", ("cur",), "Windows cursor", "image")
PSD = T("image/vnd.adobe.photoshop", ("psd",), "Adobe Photoshop document", "image")
HEIC = T("image/heic", ("heic", "heif"), "HEIF/HEIC image", "image")
AVIF = T("image/avif", ("avif",), "AVIF image", "image")
JXL = T("image/jxl", ("jxl",), "JPEG XL image", "image")
JP2 = T("image/jp2", ("jp2", "j2k", "jpx"), "JPEG 2000 image", "image")
SVG = T("image/svg+xml", ("svg",), "SVG vector image", "image")
CR2 = T("image/x-canon-cr2", ("cr2",), "Canon RAW image", "image")
CR3 = T("image/x-canon-cr3", ("cr3",), "Canon RAW 3 image", "image")
DICOM = T("application/dicom", ("dcm", "dicom"), "DICOM medical image", "image")

# --- Documents --------------------------------------------------------------
PDF = T("application/pdf", ("pdf",), "PDF document", "document")
RTF = T("application/rtf", ("rtf",), "Rich Text Format document", "document")
POSTSCRIPT = T("application/postscript", ("ps", "eps", "ai"), "PostScript", "document")
OLE2 = T("application/x-ole-storage", ("doc", "xls", "ppt", "msg", "msi", "vsd"), "OLE2 compound document (legacy Office)", "document")
DOCX = T("application/vnd.openxmlformats-officedocument.wordprocessingml.document", ("docx", "docm", "dotx", "dotm"), "Word document (OOXML)", "document")
XLSX = T("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ("xlsx", "xlsm", "xltx", "xltm"), "Excel workbook (OOXML)", "document")
PPTX = T("application/vnd.openxmlformats-officedocument.presentationml.presentation", ("pptx", "pptm", "potx", "ppsx"), "PowerPoint presentation (OOXML)", "document")
OOXML = T("application/vnd.openxmlformats-officedocument", ("docx", "xlsx", "pptx"), "Office Open XML document", "document")
ODT = T("application/vnd.oasis.opendocument.text", ("odt",), "OpenDocument text", "document")
ODS = T("application/vnd.oasis.opendocument.spreadsheet", ("ods",), "OpenDocument spreadsheet", "document")
ODP = T("application/vnd.oasis.opendocument.presentation", ("odp",), "OpenDocument presentation", "document")
ODG = T("application/vnd.oasis.opendocument.graphics", ("odg",), "OpenDocument graphics", "document")
EPUB = T("application/epub+zip", ("epub",), "EPUB e-book", "document")
XPS = T("application/vnd.ms-xpsdocument", ("xps", "oxps"), "XPS document", "document")

# --- Archives ---------------------------------------------------------------
ZIP = T("application/zip", ("zip",), "ZIP archive", "archive")
ZIP_EMPTY = T("application/zip", ("zip",), "ZIP archive (empty)", "archive")
GZIP = T("application/gzip", ("gz", "gzip", "tgz", "svgz"), "gzip compressed data", "archive")
BZIP2 = T("application/x-bzip2", ("bz2", "tbz2"), "bzip2 compressed data", "archive")
XZ = T("application/x-xz", ("xz", "txz"), "xz compressed data", "archive")
ZSTD = T("application/zstd", ("zst",), "Zstandard compressed data", "archive")
LZ4 = T("application/x-lz4", ("lz4",), "LZ4 compressed data", "archive")
SEVENZ = T("application/x-7z-compressed", ("7z",), "7-Zip archive", "archive")
RAR = T("application/vnd.rar", ("rar",), "RAR archive", "archive")
TAR = T("application/x-tar", ("tar",), "tar archive", "archive")
CAB = T("application/vnd.ms-cab-compressed", ("cab",), "Microsoft cabinet archive", "archive")
ARJ = T("application/x-arj", ("arj",), "ARJ archive", "archive")
LZIP = T("application/x-lzip", ("lz",), "lzip compressed data", "archive")
ISO = T("application/x-iso9660-image", ("iso",), "ISO 9660 disc image", "archive")
JAR = T("application/java-archive", ("jar", "war", "ear"), "Java archive", "archive")
APK = T("application/vnd.android.package-archive", ("apk",), "Android package", "executable")
XPI = T("application/x-xpinstall", ("xpi",), "Browser extension (XPI)", "archive")
DEB = T("application/vnd.debian.binary-package", ("deb",), "Debian package", "archive")
RPM = T("application/x-rpm", ("rpm",), "RPM package", "archive")

# --- Executables / binaries -------------------------------------------------
PE = T("application/vnd.microsoft.portable-executable", ("exe", "dll", "sys", "scr", "ocx", "com", "cpl", "drv", "efi"), "Windows PE executable", "executable")
ELF = T("application/x-executable", ("elf", "so", "o", "bin"), "ELF executable", "executable")
MACHO = T("application/x-mach-binary", ("macho", "dylib", "bundle"), "Mach-O executable", "executable")
JAVA_CLASS = T("application/x-java-class", ("class",), "Java class file", "executable")
WASM = T("application/wasm", ("wasm",), "WebAssembly binary", "executable")
DEX = T("application/x-dex", ("dex",), "Dalvik executable", "executable")
LNK = T("application/x-ms-shortcut", ("lnk",), "Windows shortcut", "executable")
PYC = T("application/x-python-code", ("pyc",), "Python bytecode", "executable")
CHM = T("application/vnd.ms-htmlhelp", ("chm",), "Compiled HTML help", "executable")

# --- Audio --------------------------------------------------------------------
MP3 = T("audio/mpeg", ("mp3",), "MP3 audio", "audio")
FLAC = T("audio/flac", ("flac",), "FLAC audio", "audio")
OGG = T("audio/ogg", ("ogg", "oga", "ogv", "opus", "spx"), "Ogg container", "audio")
WAV = T("audio/wav", ("wav", "wave"), "WAVE audio", "audio")
AIFF = T("audio/aiff", ("aif", "aiff", "aifc"), "AIFF audio", "audio")
MIDI = T("audio/midi", ("mid", "midi"), "MIDI sequence", "audio")
M4A = T("audio/mp4", ("m4a", "m4b", "m4p"), "MPEG-4 audio", "audio")
AMR = T("audio/amr", ("amr",), "AMR audio", "audio")
ASF = T("video/x-ms-asf", ("asf", "wmv", "wma"), "Windows Media (ASF)", "video")
APE = T("audio/x-ape", ("ape",), "Monkey Audio (APE)", "audio")

# --- Video --------------------------------------------------------------------
MP4 = T("video/mp4", ("mp4", "m4v", "mp4v"), "MPEG-4 video", "video")
MOV = T("video/quicktime", ("mov", "qt"), "QuickTime movie", "video")
THREEGP = T("video/3gpp", ("3gp", "3g2"), "3GPP video", "video")
AVI = T("video/x-msvideo", ("avi",), "AVI video", "video")
MKV = T("video/x-matroska", ("mkv", "mka", "mks"), "Matroska video", "video")
WEBM = T("video/webm", ("webm",), "WebM video", "video")
FLV = T("video/x-flv", ("flv",), "Flash video", "video")
MPEG = T("video/mpeg", ("mpg", "mpeg", "mpe", "vob"), "MPEG video", "video")
MPEG_TS = T("video/mp2t", ("ts", "m2ts", "mts"), "MPEG transport stream", "video")
SWF = T("application/x-shockwave-flash", ("swf",), "Shockwave Flash", "executable")

# --- Fonts --------------------------------------------------------------------
TTF = T("font/ttf", ("ttf",), "TrueType font", "font")
OTF = T("font/otf", ("otf",), "OpenType font", "font")
WOFF = T("font/woff", ("woff",), "WOFF font", "font")
WOFF2 = T("font/woff2", ("woff2",), "WOFF2 font", "font")
TTC = T("font/collection", ("ttc",), "TrueType collection", "font")
EOT = T("application/vnd.ms-fontobject", ("eot",), "Embedded OpenType font", "font")

# --- Data / misc ---------------------------------------------------------------
SQLITE = T("application/vnd.sqlite3", ("sqlite", "sqlite3", "db"), "SQLite database", "data")
PARQUET = T("application/vnd.apache.parquet", ("parquet",), "Apache Parquet", "data")
AVRO = T("application/avro", ("avro",), "Apache Avro", "data")
PCAP = T("application/vnd.tcpdump.pcap", ("pcap", "cap"), "pcap capture", "data")
PCAPNG = T("application/x-pcapng", ("pcapng",), "pcapng capture", "data")
KEEPASS = T("application/x-keepass2", ("kdbx",), "KeePass database", "data")
TORRENT = T("application/x-bittorrent", ("torrent",), "BitTorrent metadata", "data")
NUMPY = T("application/x-npy", ("npy",), "NumPy array", "data")
PICKLE = T("application/x-python-pickle", ("pkl", "pickle"), "Python pickle (can execute code when loaded)", "executable")
BLENDER = T("application/x-blender", ("blend",), "Blender scene", "data")
HDF5 = T("application/x-hdf5", ("h5", "hdf5"), "HDF5 data", "data")
GLB = T("model/gltf-binary", ("glb",), "glTF binary model", "data")
VHD = T("application/x-vhd", ("vhd",), "Virtual hard disk", "archive")
VMDK = T("application/x-vmdk", ("vmdk",), "VMware disk", "archive")
WIM = T("application/x-ms-wim", ("wim",), "Windows imaging format", "archive")
PST = T("application/vnd.ms-outlook-pst", ("pst", "ost"), "Outlook data file", "data")

# --- Text (used by text.py but defined here for a single registry) ------------
HTML = T("text/html", ("html", "htm", "xhtml"), "HTML document", "text")
XML = T("application/xml", ("xml", "xsl", "xslt", "xsd", "rdf", "wsdl"), "XML document", "text")
JSON = T("application/json", ("json", "geojson", "jsonld", "map"), "JSON data", "text")
PLAIN = T("text/plain", ("txt", "text", "log", "md", "markdown", "csv", "tsv", "ini", "cfg", "conf", "yaml", "yml", "toml", "rst", "srt", "vtt"), "Plain text", "text")
RSS = T("application/rss+xml", ("rss", "xml"), "RSS feed", "text")
ATOM = T("application/atom+xml", ("atom", "xml"), "Atom feed", "text")
SHELL = T("text/x-shellscript", ("sh", "bash", "zsh", "ksh"), "Shell script", "script")
SCRIPT = T("text/x-script", ("py", "pl", "rb", "php", "js", "sh"), "Interpreter script (shebang)", "script")
PHP = T("application/x-httpd-php", ("php", "phtml", "php3", "php4", "php5", "phps", "phar"), "PHP script", "script")
PEM = T("application/x-pem-file", ("pem", "crt", "cer", "key", "pub"), "PEM encoded key/certificate", "data")
VCARD = T("text/vcard", ("vcf", "vcard"), "vCard contact", "text")
ICAL = T("text/calendar", ("ics", "ical", "ifb"), "iCalendar", "text")
HTA = T("application/hta", ("hta",), "HTML application (executes scripts)", "executable")
WINDOWS_SCRIPT = T("text/x-wsf", ("wsf", "wsh"), "Windows Script Host file", "script")
EMAIL = T("message/rfc822", ("eml", "mht", "mhtml"), "Email message / MHTML", "text")
REG = T("text/x-ms-regedit", ("reg",), "Windows registry file", "script")
UTF16_TEXT = T("text/plain", ("txt", "text", "csv", "log"), "UTF-16 text", "text")


def _s(magic: bytes, t: DetectedType, offset: int = 0, mask: Optional[bytes] = None, priority: int = 0) -> Signature:
    return Signature(magic, t, offset, mask, priority)


SIGNATURES: Tuple[Signature, ...] = (
    # images
    _s(b"\x89PNG\r\n\x1a\n", PNG),
    _s(b"\xff\xd8\xff", JPEG),
    _s(b"GIF87a", GIF),
    _s(b"GIF89a", GIF),
    _s(b"BM", BMP, priority=-5),  # weak 2-byte magic, checked late and verified in containers
    _s(b"II*\x00", TIFF),
    _s(b"MM\x00*", TIFF),
    _s(b"II*\x00\x10\x00\x00\x00CR", CR2, priority=5),
    _s(b"\x00\x00\x01\x00", ICO, priority=-5),
    _s(b"\x00\x00\x02\x00", CUR, priority=-5),
    _s(b"8BPS", PSD),
    _s(b"\xff\x0a", JXL, priority=-3),
    _s(b"\x00\x00\x00\x0cJXL \r\n\x87\n", JXL),
    _s(b"\x00\x00\x00\x0cjP  \r\n\x87\n", JP2),
    _s(b"DICM", DICOM, offset=128),
    # documents
    _s(b"%PDF-", PDF),
    _s(b"{\\rtf", RTF),
    _s(b"%!PS", POSTSCRIPT),
    _s(b"\xc5\xd0\xd3\xc6", POSTSCRIPT),  # DOS EPS binary header
    _s(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", OLE2),
    # archives / compression
    _s(b"PK\x03\x04", ZIP),
    _s(b"PK\x05\x06", ZIP_EMPTY),
    _s(b"PK\x07\x08", ZIP),
    _s(b"\x1f\x8b", GZIP),
    _s(b"BZh", BZIP2),
    _s(b"\xfd7zXZ\x00", XZ),
    _s(b"\x28\xb5\x2f\xfd", ZSTD),
    _s(b"\x04\x22\x4d\x18", LZ4),
    _s(b"7z\xbc\xaf\x27\x1c", SEVENZ),
    _s(b"Rar!\x1a\x07\x00", RAR),
    _s(b"Rar!\x1a\x07\x01\x00", RAR),
    _s(b"ustar", TAR, offset=257),
    _s(b"MSCF", CAB),
    _s(b"ISc(", CAB),
    _s(b"\x60\xea", ARJ, priority=-5),
    _s(b"LZIP", LZIP),
    _s(b"CD001", ISO, offset=0x8001),
    _s(b"!<arch>\ndebian", DEB),
    _s(b"\xed\xab\xee\xdb", RPM),
    _s(b"conectix", VHD),
    _s(b"KDMV", VMDK),
    _s(b"MSWIM\x00\x00\x00", WIM),
    # executables
    _s(b"MZ", PE, priority=-5),
    _s(b"ZM", PE, priority=-6),
    _s(b"\x7fELF", ELF),
    _s(b"\xfe\xed\xfa\xce", MACHO),
    _s(b"\xfe\xed\xfa\xcf", MACHO),
    _s(b"\xce\xfa\xed\xfe", MACHO),
    _s(b"\xcf\xfa\xed\xfe", MACHO),
    _s(b"\xca\xfe\xba\xbe", JAVA_CLASS),  # refined to Mach-O fat in containers
    _s(b"\x00asm", WASM),
    _s(b"dex\n", DEX),
    _s(b"L\x00\x00\x00\x01\x14\x02\x00", LNK),
    _s(b"ITSF", CHM),
    _s(b"FWS", SWF),
    _s(b"CWS", SWF),
    _s(b"ZWS", SWF),
    # audio
    _s(b"ID3", MP3),
    _s(b"\xff\xfb", MP3, priority=-4),
    _s(b"\xff\xf3", MP3, priority=-4),
    _s(b"\xff\xf2", MP3, priority=-4),
    _s(b"fLaC", FLAC),
    _s(b"OggS", OGG),
    _s(b"MThd", MIDI),
    _s(b"#!AMR", AMR),
    _s(b"0&\xb2u\x8ef\xcf\x11", ASF),
    _s(b"MAC ", APE),
    _s(b"RIFF", WAV, priority=-1),  # refined in containers (WAV/AVI/WEBP)
    _s(b"FORM", AIFF, priority=-1),  # refined in containers
    # video
    _s(b"ftyp", MP4, offset=4, priority=-1),  # refined in containers
    _s(b"\x1a\x45\xdf\xa3", MKV),  # refined (webm)
    _s(b"FLV\x01", FLV),
    _s(b"\x00\x00\x01\xba", MPEG),
    _s(b"\x00\x00\x01\xb3", MPEG),
    _s(b"G", MPEG_TS, priority=-9),  # refined: needs sync bytes at 188 and 376
    # fonts
    _s(b"\x00\x01\x00\x00\x00", TTF, priority=-3),
    _s(b"true", TTF),
    _s(b"OTTO", OTF),
    _s(b"wOFF", WOFF),
    _s(b"wOF2", WOFF2),
    _s(b"ttcf", TTC),
    _s(b"LP", EOT, offset=34, priority=-5),
    # data
    _s(b"SQLite format 3\x00", SQLITE),
    _s(b"PAR1", PARQUET),
    _s(b"Obj\x01", AVRO),
    _s(b"\xd4\xc3\xb2\xa1", PCAP),
    _s(b"\xa1\xb2\xc3\xd4", PCAP),
    _s(b"\x0a\x0d\x0d\x0a", PCAPNG),
    _s(b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", KEEPASS),
    _s(b"d8:announce", TORRENT),
    _s(b"\x93NUMPY", NUMPY),
    _s(b"\x80\x02", PICKLE, priority=-6),
    _s(b"\x80\x03", PICKLE, priority=-6),
    _s(b"\x80\x04\x95", PICKLE, priority=-6),
    _s(b"\x80\x05\x95", PICKLE, priority=-6),
    _s(b"BLENDER", BLENDER),
    _s(b"\x89HDF\r\n\x1a\n", HDF5),
    _s(b"glTF", GLB),
    _s(b"!BDN", PST),
)

# Pre-sorted for the detector: higher priority first, then longer magic first.
ORDERED_SIGNATURES: Tuple[Signature, ...] = tuple(
    sorted(SIGNATURES, key=lambda s: (-s.priority, -len(s.magic), s.offset))
)
