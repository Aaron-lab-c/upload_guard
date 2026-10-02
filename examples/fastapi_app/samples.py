# Small, deterministic sample files for the example tests (generated in code, no binaries in the repo).
import struct
import zlib


def _png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


PNG = (
    b"\x89PNG\r\n\x1a\n"
    + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    + _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
    + _png_chunk(b"IEND", b"")
)

# A Windows PE stub: "MZ" header whose e_lfanew points at a PE signature.
PE_EXE = b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"PE\x00\x00" + bytes(100)

SVG_XSS = (
    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
    b"<script>alert(document.cookie)</script>"
    b'<rect width="10" height="10"/>'
    b"</svg>"
)
