import gzip
import io

import pytest

from conftest import SVG_CLEAN, SVG_XSS, make_docx, make_elf, make_gif, make_jpeg, make_pdf, make_pe, make_png, make_tar, make_zip
from upload_guard import ArchiveLimits, Policy, Severity, UnsupportedSource, UploadGuard, UploadRejected, check, detect_type, scan


def _codes(result):
    return {f.code for f in result.findings}


def _error_codes(result):
    return {f.code for f in result.errors}


# --- happy paths -------------------------------------------------------------------
def test_accepts_matching_image():
    result = check(make_png(), filename="photo.png", content_type="image/png", allowed=["image/*"])
    assert result.ok
    assert result.mime == "image/png"
    assert result.extension == "png"
    assert result.safe_filename == "photo.png"
    assert result.size == len(make_png())
    assert not result.errors


def test_jpeg_alias_extension_ok():
    assert scan(make_jpeg(), filename="a.JPEG").ok
    assert scan(make_jpeg(), filename="a.jpg").ok
    assert scan(make_jpeg(), filename="a.jfif").ok


def test_office_docs():
    result = scan(make_docx(), filename="report.docx", allowed=[".docx", ".pdf"])
    assert result.ok, result.findings
    assert result.archive is not None and result.archive.format == "zip"
    assert not scan(make_docx(), filename="report.xlsx").ok


# --- rejections ----------------------------------------------------------------------
def test_disguised_executable():
    result = scan(make_pe(), filename="cute_cat.png", allowed=["image/*"])
    assert not result.ok
    codes = _error_codes(result)
    assert "extension.mismatch" in codes
    assert "type.blocked" in codes
    assert "type.not_allowed" in codes
    with pytest.raises(UploadRejected) as exc:
        check(make_elf(), filename="x.jpg")
    assert "extension.mismatch" in exc.value.codes
    assert exc.value.result.detected.category == "executable"


def test_php_disguised_as_image():
    result = scan(b"<?php system($_GET['c']); ?>", filename="shell.jpg")
    assert not result.ok
    assert result.mime == "application/x-httpd-php"
    assert "type.blocked" in _error_codes(result)


def test_html_disguised_as_png_rejected_even_when_text_allowed():
    result = scan(b"<html><script>alert(1)</script></html>", filename="x.png", allowed=["image/*", "text/*"])
    assert not result.ok
    assert "extension.mismatch" in _error_codes(result)


def test_allowed_and_blocked_rules():
    assert not scan(make_pdf(), filename="a.pdf", allowed=["image/*"]).ok
    assert scan(make_pdf(), filename="a.pdf", allowed=["image/*", "application/pdf"]).ok
    assert scan(make_pdf(), filename="a.pdf", allowed=[".pdf"]).ok
    assert not scan(make_pdf(), filename="a.pdf", blocked=["application/pdf"]).ok
    assert not scan(make_zip({"a": "b"}), filename="a.zip", blocked=["category:archive"]).ok


def test_size_limits():
    result = scan(make_png(), filename="a.png", max_size=10)
    assert "size.too_large" in _error_codes(result)
    assert "size.empty" in _error_codes(scan(b"", filename="a.png"))
    assert scan(b"", filename="a.txt", min_size=0, allow_unknown=True).ok


def test_unknown_type():
    blob = bytes(range(256)) * 4
    assert "type.unknown" in _error_codes(scan(blob, filename="data.bin"))
    assert scan(blob, filename="data.bin", allow_unknown=True, strict_extension=False).ok


def test_extension_handling():
    assert "extension.missing" in _error_codes(scan(make_png(), filename="noext"))
    assert scan(make_png(), filename="noext", require_extension=False).ok
    r = scan(make_png(), filename="noext", require_extension=False)
    assert r.safe_filename == "noext.png"
    assert scan(make_png(), filename="a.jpg", strict_extension=False).ok
    # unknown extension on plain text is only LOW
    r = scan(b"some notes", filename="notes.xyz")
    assert r.ok and "extension.unknown" in _codes(r)
    # missing filename
    r = scan(make_png())
    assert not r.ok and "filename.empty" in _codes(r)
    assert scan(make_png(), require_extension=False).ok


def test_content_type_mismatch_is_low():
    r = scan(make_png(), filename="a.png", content_type="image/jpeg")
    assert r.ok and "content_type.mismatch" in _codes(r)
    r = scan(make_png(), filename="a.png", content_type="application/octet-stream")
    assert "content_type.mismatch" not in _codes(r)
    r = scan(make_jpeg(), filename="a.jpg", content_type="image/pjpeg; charset=binary")
    assert "content_type.mismatch" not in _codes(r)
    r = scan(make_png(), filename="a.png", content_type="image/jpeg", reject_threshold=Severity.LOW)
    assert not r.ok


def test_filename_attacks_flow_through():
    r = scan(make_png(), filename="../../etc/cron.d/x.png")
    assert not r.ok and "filename.path_traversal" in _error_codes(r)
    assert r.safe_filename == "x.png"
    r = scan(make_png(), filename="a‮gnp.exe")
    assert not r.ok
    r = scan(make_png(), filename="shell.php.png")
    assert not r.ok and "filename.double_extension" in _error_codes(r)


# --- SVG --------------------------------------------------------------------------------
def test_svg_sanitized_by_default():
    r = scan(SVG_XSS, filename="logo.svg", allowed=["image/svg+xml"])
    assert r.ok, r.errors
    assert r.sanitized is not None and b"<script" not in r.sanitized
    assert any(f.remediated for f in r.findings)
    r = scan(SVG_XSS, filename="logo.svg", sanitize_svg=False)
    assert not r.ok and "svg.script" in _error_codes(r)
    r = scan(SVG_CLEAN, filename="logo.svg", sanitize_svg=False)
    assert r.ok


def test_svgz_is_inspected():
    data = gzip.compress(SVG_XSS)
    r = scan(data, filename="logo.svgz", sanitize_svg=False, inspect_archives=False)
    assert not r.ok and "svg.script" in _error_codes(r)
    r = scan(data, filename="logo.svgz", allowed=["image/*"])
    assert r.ok and r.sanitized is not None
    assert r.mime == "image/svg+xml" and r.extension == "svgz"
    assert not scan(data, filename="logo.gz").ok  # extension must say svgz


# --- archives ------------------------------------------------------------------------------
def test_zip_bomb_rejected():
    bomb = make_zip({"zeros": bytes(4 * 1024 * 1024)})
    r = scan(bomb, filename="b.zip", archive_limits=ArchiveLimits(max_total_uncompressed=1024 * 1024))
    assert not r.ok and "archive.bomb_size" in _error_codes(r)
    assert r.archive is not None
    r = scan(make_tar({"../x": b"y"}, "gz"), filename="a.tgz")
    assert not r.ok and "archive.path_traversal" in _error_codes(r)
    r = scan(make_zip({"a.txt": "fine"}), filename="ok.zip")
    assert r.ok


# --- polyglots -----------------------------------------------------------------------------
def test_polyglot_rejected():
    r = scan(make_gif()[:-1] + b"<?php evil(); ?>;", filename="a.gif")
    assert not r.ok and "polyglot.embedded_php" in _error_codes(r)
    r = scan(make_png() + b"<?php evil(); ?>", filename="a.png")
    assert not r.ok and "polyglot.trailing_data" in _error_codes(r)
    r = scan(make_png() + b"<?php evil(); ?>", filename="a.png", check_trailing_data=False, polyglot_scan_limit=0)
    assert r.ok


# --- sources / adapters -----------------------------------------------------------------------
def test_sources_and_position_restore(tmp_path):
    p = tmp_path / "img.png"
    p.write_bytes(make_png())
    assert scan(str(p)).ok
    assert scan(p).ok
    assert detect_type(p).mime == "image/png"

    buf = io.BytesIO(make_png())
    buf.seek(7)
    assert scan(buf, filename="a.png").ok
    assert buf.tell() == 7
    assert not buf.closed

    with open(p, "rb") as fh:
        r = scan(fh)
        assert r.ok and r.filename == "img.png"
        assert not fh.closed

    with pytest.raises(UnsupportedSource):
        scan(12345)


def test_non_seekable_stream_is_spooled():
    class Pipe:
        def __init__(self, data):
            self._b = io.BytesIO(data)
        def read(self, n=-1):
            return self._b.read(n)
        def seekable(self):
            return False
    assert scan(Pipe(make_png()), filename="a.png").ok
    r = scan(Pipe(make_png()), filename="a.png", max_size=20)
    assert "size.too_large" in _error_codes(r)


def test_duck_typed_upload_objects():
    class StarletteLike:
        def __init__(self, data, filename, content_type):
            self.file = io.BytesIO(data)
            self.filename = filename
            self.content_type = content_type
            self.size = len(data)

    class WerkzeugLike:
        def __init__(self, data, filename, mimetype):
            self.stream = io.BytesIO(data)
            self.filename = filename
            self.mimetype = mimetype
            self.content_type = mimetype

    class DjangoLike:
        def __init__(self, data, name, content_type):
            self.file = io.BytesIO(data)
            self.name = name
            self.content_type = content_type
            self.size = len(data)
        def read(self, n=-1):
            return self.file.read(n)
        def seek(self, *a):
            return self.file.seek(*a)
        def tell(self):
            return self.file.tell()
        def chunks(self):
            yield self.file.read()

    r = scan(StarletteLike(make_pdf(), "doc.pdf", "application/pdf"))
    assert r.ok and r.filename == "doc.pdf" and r.declared_content_type == "application/pdf"
    r = scan(WerkzeugLike(make_pdf(), "doc.pdf", "application/pdf"))
    assert r.ok and r.filename == "doc.pdf"
    d = DjangoLike(make_pdf(), "doc.pdf", "application/pdf")
    r = scan(d)
    assert r.ok and r.filename == "doc.pdf" and r.size == len(make_pdf())
    assert d.tell() == 0


def test_policy_object_and_overrides():
    policy = Policy(allowed=["image/*"], max_size=1000)
    g = UploadGuard(policy)
    assert g.policy.max_size == 1000
    g2 = UploadGuard(policy, max_size=5)
    assert g2.policy.max_size == 5 and g.policy.max_size == 1000
    assert not g2.is_safe(make_png(), filename="a.png")
    assert g.is_safe(make_png(), filename="a.png")


def test_result_serialisable():
    import json
    r = scan(SVG_XSS, filename="x.svg")
    payload = json.dumps(r.to_dict())
    assert '"sanitized": true' in payload
    assert r.highest_severity() is None or isinstance(r.highest_severity(), Severity)
