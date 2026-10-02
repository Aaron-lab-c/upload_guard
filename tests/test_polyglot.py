import io

from conftest import make_gif, make_jpeg, make_pdf, make_png, make_zip
from upload_guard import Severity, check_trailing, detect, scan_embedded


def _codes(findings):
    return {f.code for f in findings}


def test_php_in_gif_comment():
    data = make_gif()[:-1] + b"<?php system($_GET['c']); ?>" + b";"
    detected = detect(data)
    assert detected.mime == "image/gif"
    findings = scan_embedded(data, detected)
    assert "polyglot.embedded_php" in _codes(findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_gifar_zip_inside_gif():
    data = make_gif() + make_zip({"evil.class": "x"})
    detected = detect(data)
    findings = scan_embedded(data, detected)
    assert "polyglot.embedded_zip" in _codes(findings)


def test_pdf_inside_png_and_html_in_jpeg():
    data = make_png() + make_pdf()
    assert "polyglot.embedded_pdf" in _codes(scan_embedded(data, detect(data)))
    data = make_jpeg() + b"<script>alert(1)</script>"
    assert "polyglot.embedded_html_script" in _codes(scan_embedded(data, detect(data)))


def test_no_false_positive_for_own_signature():
    pdf = make_pdf()
    assert not scan_embedded(pdf, detect(pdf))
    png = make_png()
    assert not scan_embedded(png, detect(png))
    # archives and text are skipped entirely
    z = make_zip({"a": "<?php"})
    assert not scan_embedded(z, detect(z))


def test_trailing_data_detection():
    png = make_png()
    assert not check_trailing(io.BytesIO(png), detect(png), len(png))
    shell = png + b"<?php echo shell_exec($_GET['cmd']); ?>"
    findings = check_trailing(io.BytesIO(shell), detect(shell), len(shell))
    assert "polyglot.trailing_data" in _codes(findings)
    assert findings[0].severity == Severity.HIGH  # text payload
    assert findings[0].detail["trailing_bytes"] == len(shell) - len(png)

    jpg = make_jpeg()
    assert not check_trailing(io.BytesIO(jpg), detect(jpg), len(jpg))
    assert not check_trailing(io.BytesIO(jpg + b"\x00\x00"), detect(jpg), len(jpg) + 2)  # small padding tolerated
    bad = jpg + bytes(range(200))
    assert "polyglot.trailing_data" in _codes(check_trailing(io.BytesIO(bad), detect(bad), len(bad)))

    gif = make_gif() + b"GARBAGE"
    assert "polyglot.trailing_data" in _codes(check_trailing(io.BytesIO(gif), detect(gif), len(gif)))

    pdf = make_pdf()
    assert not check_trailing(io.BytesIO(pdf), detect(pdf), len(pdf))
    pdf2 = make_pdf(trailer=b"x" * 5000)
    assert "polyglot.trailing_data" in _codes(check_trailing(io.BytesIO(pdf2), detect(pdf2), len(pdf2)))
    truncated = png[:-4]
    assert "polyglot.missing_eof" in _codes(check_trailing(io.BytesIO(truncated), detect(truncated), len(truncated)))


def test_stream_position_restored():
    png = make_png() + b"junk"
    buf = io.BytesIO(png)
    buf.seek(3)
    check_trailing(buf, detect(png), len(png))
    assert buf.tell() == 3
