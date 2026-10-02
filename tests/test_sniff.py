import gzip
import io

import pytest

from conftest import (
    SVG_CLEAN,
    make_docx,
    make_elf,
    make_gif,
    make_jar,
    make_jpeg,
    make_odt,
    make_ole2,
    make_pdf,
    make_pe,
    make_png,
    make_tar,
    make_xlsx,
    make_zip,
)
from upload_guard import detect, detect_stream
from upload_guard.sniff.detector import detect_bytes


@pytest.mark.parametrize("data,mime", [
    (make_png(), "image/png"),
    (make_jpeg(), "image/jpeg"),
    (make_gif(), "image/gif"),
    (make_pdf(), "application/pdf"),
    (make_pe(), "application/vnd.microsoft.portable-executable"),
    (make_elf(), "application/x-executable"),
    (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
    (b"RIFF\x00\x00\x00\x00WAVEfmt ", "audio/wav"),
    (b"RIFF\x00\x00\x00\x00AVI LIST", "video/x-msvideo"),
    (b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom", "video/mp4"),
    (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic", "image/heic"),
    (b"\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1", "image/avif"),
    (b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  ", "video/quicktime"),
    (b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\xf3\x81\x08\x42\x82\x84webm", "video/webm"),
    (b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\x82\x88matroska", "video/x-matroska"),
    (b"\x1f\x8b\x08\x00" + bytes(20), "application/gzip"),
    (b"BZh91AY&SY" + bytes(20), "application/x-bzip2"),
    (b"\xfd7zXZ\x00" + bytes(20), "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c" + bytes(20), "application/x-7z-compressed"),
    (b"Rar!\x1a\x07\x01\x00" + bytes(20), "application/vnd.rar"),
    (b"%!PS-Adobe-3.0", "application/postscript"),
    (b"{\\rtf1\\ansi", "application/rtf"),
    (b"OTTO" + bytes(32), "font/otf"),
    (b"wOF2" + bytes(32), "font/woff2"),
    (b"\x00\x01\x00\x00\x00\x0a" + bytes(32), "font/ttf"),
    (b"SQLite format 3\x00" + bytes(100), "application/vnd.sqlite3"),
    (b"ID3\x03\x00" + bytes(100), "audio/mpeg"),
    (b"\xff\xfb\x90\x00" + bytes(100), "audio/mpeg"),
    (b"fLaC\x00\x00\x00\x22", "audio/flac"),
    (b"OggS\x00\x02", "audio/ogg"),
    (b"\x00asm\x01\x00\x00\x00", "application/wasm"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x34", "application/x-java-class"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + bytes(40), "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe" + bytes(40), "application/x-mach-binary"),
    (b"\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00K\x01.", "application/x-python-pickle"),
    (b"II*\x00\x08\x00\x00\x00", "image/tiff"),
    (b"8BPS\x00\x01", "image/vnd.adobe.photoshop"),
    (b"PAR1" + bytes(16), "application/vnd.apache.parquet"),
    (b"\x93NUMPY\x01\x00", "application/x-npy"),
])
def test_binary_signatures(data, mime):
    assert detect(data).mime == mime


def test_bmp_requires_plausible_header():
    assert detect(b"BM" + b"hello world, this is not a bitmap at all" + bytes(40)).mime != "image/bmp"
    bmp = b"BM" + (70).to_bytes(4, "little") + bytes(4) + (54).to_bytes(4, "little") + (40).to_bytes(4, "little") + bytes(60)
    assert detect(bmp).mime == "image/bmp"


def test_ico_requires_plausible_directory():
    ico = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x16\x00\x00\x00" + bytes(64)
    assert detect(ico).mime == "image/x-icon"
    assert detect(b"\x00\x00\x01\x00" + bytes(40)).mime != "image/x-icon"


def test_zip_based_office_formats():
    assert detect_bytes(make_docx()).mime.endswith("wordprocessingml.document")
    assert detect_bytes(make_xlsx()).mime.endswith("spreadsheetml.sheet")
    assert detect_bytes(make_odt()).mime == "application/vnd.oasis.opendocument.text"
    assert detect_bytes(make_jar()).mime == "application/java-archive"
    assert detect_bytes(make_zip({"a.txt": "hello"})).mime == "application/zip"


def test_zip_office_from_header_only():
    # No stream: only the first local file headers are visible.
    docx = make_docx()
    assert detect(docx[:2048]).mime.endswith("wordprocessingml.document")
    odt = make_odt()
    assert detect(odt[:2048]).mime == "application/vnd.oasis.opendocument.text"


def test_ole2_subtypes():
    assert detect_bytes(make_ole2("WordDocument")).mime == "application/msword"
    assert detect_bytes(make_ole2("Workbook")).mime == "application/vnd.ms-excel"
    assert detect_bytes(make_ole2("PowerPoint Document")).mime == "application/vnd.ms-powerpoint"
    assert detect_bytes(make_ole2("Whatever")).mime == "application/x-ole-storage"


def test_tar_and_tgz():
    tar = make_tar({"a.txt": b"hi"})
    assert detect(tar).mime == "application/x-tar"
    tgz = make_tar({"a.txt": b"hi"}, "gz")
    t = detect(tgz)
    assert t.mime == "application/gzip"
    assert "tgz" in t.extensions
    svgz = gzip.compress(SVG_CLEAN)
    t = detect(svgz)
    assert t.extensions[0] == "svgz"


@pytest.mark.parametrize("data,mime", [
    (SVG_CLEAN, "image/svg+xml"),
    (b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "image/svg+xml"),
    (b"\xef\xbb\xbf<!-- c --><!DOCTYPE svg PUBLIC '-//W3C//DTD SVG 1.1//EN' 'x.dtd'>\n<svg/>", "image/svg+xml"),
    (b"<!DOCTYPE html><html><body>x</body></html>", "text/html"),
    (b"<html><head></head></html>", "text/html"),
    (b"  \n<HTML>", "text/html"),
    (b"hello <script>alert(1)</script>", "text/html"),
    (b"<?xml version='1.0'?><root><a/></root>", "application/xml"),
    (b"<?xml version='1.0'?><rss version='2.0'/>", "application/rss+xml"),
    (b'{"a": 1}', "application/json"),
    (b"[1, 2, 3]", "application/json"),
    (b"#!/bin/bash\necho hi", "text/x-shellscript"),
    (b"#!/usr/bin/env python3\nprint(1)", "text/x-script"),
    (b"<?php system($_GET['c']); ?>", "application/x-httpd-php"),
    (b"GIF89a<?php echo 1; ?>", "image/gif"),
    (b"-----BEGIN RSA PRIVATE KEY-----\nMII", "application/x-pem-file"),
    (b"BEGIN:VCARD\nVERSION:3.0", "text/vcard"),
    (b"BEGIN:VCALENDAR\nVERSION:2.0", "text/calendar"),
    (b"Windows Registry Editor Version 5.00\r\n", "text/x-ms-regedit"),
    (b"just some plain text\nwith lines", "text/plain"),
    (b"a,b,c\n1,2,3\n", "text/plain"),
    (b"\xff\xfeh\x00i\x00", "text/plain"),
    (b"<html xmlns:hta='x'><hta:application id='x'/></html>", "application/hta"),
])
def test_text_heuristics(data, mime):
    assert detect(data).mime == mime


def test_unknown_binary():
    t = detect(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" * 20)
    assert t.is_unknown
    assert detect(b"").is_unknown


def test_detect_stream_restores_position():
    buf = io.BytesIO(make_png())
    buf.seek(5)
    assert detect_stream(buf).mime == "image/png"
    assert buf.tell() == 5


def test_mz_without_pe_header_still_executable():
    assert detect(b"MZ" + bytes(100)).category == "executable"
