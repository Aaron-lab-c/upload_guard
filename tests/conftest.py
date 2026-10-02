"""Programmatically generated fixtures (no binary files in the repo)."""
from __future__ import annotations

import io
import struct
import tarfile
import zipfile
import zlib

import pytest


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def make_png(width: int = 1, height: int = 1) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", zlib.compress(raw)) + _png_chunk(b"IEND", b"")


def make_jpeg() -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xff\xdb\x00\x43\x00" + bytes(64) + b"\xff\xd9"


def make_gif() -> bytes:
    return b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"


def make_pdf(trailer: bytes = b"") -> bytes:
    return (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n" + trailer
    )


def make_zip(entries, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_docx() -> bytes:
    return make_zip({
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "_rels/.rels": "<Relationships/>",
        "word/document.xml": "<w:document/>",
    })


def make_xlsx() -> bytes:
    return make_zip({"[Content_Types].xml": "<Types/>", "xl/workbook.xml": "<workbook/>"})


def make_odt() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.text", compress_type=zipfile.ZIP_STORED)
        zf.writestr("content.xml", "<office:document-content/>")
    return buf.getvalue()


def make_jar() -> bytes:
    return make_zip({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n", "com/x/Main.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x34"})


def make_tar(entries, compression: str = "") -> bytes:
    buf = io.BytesIO()
    mode = "w:" + compression if compression else "w"
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in entries.items():
            if isinstance(data, tuple) and data[0] == "symlink":
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = data[1]
                tf.addfile(info)
                continue
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def make_pe() -> bytes:
    head = bytearray(b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40))
    head += b"PE\x00\x00" + bytes(100)
    return bytes(head)


def make_elf() -> bytes:
    return b"\x7fELF\x02\x01\x01\x00" + bytes(56)


def make_ole2(stream_name: str = "WordDocument") -> bytes:
    """A minimal OLE2 compound file with a single named directory entry after Root."""
    sector = 512
    header = bytearray(sector)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<H", header, 0x1E, 9)  # sector shift
    struct.pack_into("<I", header, 0x2C, 1)  # number of FAT sectors
    struct.pack_into("<I", header, 0x30, 1)  # first directory sector = 1
    struct.pack_into("<I", header, 0x4C, 0)  # DIFAT[0] = FAT sector 0
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + 4 * i, 0xFFFFFFFF)
    fat = bytearray(b"\xff" * sector)
    struct.pack_into("<I", fat, 0, 0xFFFFFFFD)  # sector 0 = FAT
    struct.pack_into("<I", fat, 4, 0xFFFFFFFE)  # sector 1 = directory (end of chain)

    def entry(name: str, kind: int) -> bytes:
        e = bytearray(128)
        encoded = name.encode("utf-16-le") + b"\x00\x00"
        e[0 : len(encoded)] = encoded
        struct.pack_into("<H", e, 64, len(encoded))
        e[66] = kind
        return bytes(e)

    directory = entry("Root Entry", 5) + entry(stream_name, 2) + bytes(256)
    return bytes(header) + bytes(fat) + directory


SVG_CLEAN = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 100 100">
  <defs><linearGradient id="g"><stop offset="0" stop-color="#f00"/></linearGradient></defs>
  <circle cx="50" cy="50" r="40" fill="url(#g)" style="stroke: #000; stroke-width: 2"/>
  <a href="https://example.com"><text x="10" y="20">hi</text></a>
  <use xlink:href="#g"/>
</svg>"""

SVG_XSS = b"""<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
  <script>alert(document.cookie)</script>
  <a xlink:href="javascript:alert(1)" xmlns:xlink="http://www.w3.org/1999/xlink"><text>x</text></a>
  <image href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" />
  <foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="https://evil"/></body></foreignObject>
  <rect width="10" height="10" onclick="evil()" style="fill: red; background: url(https://evil/track.png)"/>
  <style>@import url("https://evil/x.css"); rect { fill: expression(alert(1)) }</style>
  <set attributeName="href" to="javascript:alert(1)"/>
</svg>"""


@pytest.fixture
def png():
    return make_png()


@pytest.fixture
def jpeg():
    return make_jpeg()


@pytest.fixture
def pdf():
    return make_pdf()
