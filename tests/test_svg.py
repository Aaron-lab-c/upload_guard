from conftest import SVG_CLEAN, SVG_XSS
from upload_guard import Severity, SvgPolicy, sanitize_svg, scan_svg
from upload_guard.security.svg import classify_url


def _codes(findings):
    return {f.code for f in findings}


def test_clean_svg_has_no_blocking_findings():
    findings = scan_svg(SVG_CLEAN)
    assert not [f for f in findings if f.severity >= Severity.MEDIUM]
    res = sanitize_svg(SVG_CLEAN)
    assert res.sanitized is not None
    assert b"<circle" in res.sanitized
    assert b'href="https://example.com"' in res.sanitized
    assert b"linearGradient" in res.sanitized


def test_xss_svg_is_detected_and_sanitized():
    findings = scan_svg(SVG_XSS)
    codes = _codes(findings)
    for expected in ("svg.script", "svg.event_handler", "svg.javascript_uri", "svg.foreign_object", "svg.data_uri", "svg.css_script", "svg.animated_href"):
        assert expected in codes, expected
    assert all(not f.remediated for f in findings)

    res = sanitize_svg(SVG_XSS)
    out = res.sanitized
    assert out is not None
    lowered = out.lower()
    for forbidden in (b"<script", b"onload", b"onclick", b"javascript:", b"foreignobject", b"<iframe", b"text/html", b"expression(", b"@import", b"evil"):
        assert forbidden not in lowered, forbidden
    assert b"<rect" in out  # benign content survives
    assert res.findings and all(f.remediated for f in res.findings if f.severity >= Severity.MEDIUM)
    # the sanitized output is itself clean
    assert not [f for f in scan_svg(out) if f.severity >= Severity.MEDIUM]


def test_entity_and_doctype_rejected():
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&b;</text></svg>"""
    findings = scan_svg(bomb)
    assert "svg.entity_declaration" in _codes(findings)
    res = sanitize_svg(bomb)
    assert res.sanitized is None or b"&b;" not in res.sanitized
    assert any(f.severity == Severity.CRITICAL for f in res.findings)

    xxe = b"""<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>"""
    assert "svg.entity_declaration" in _codes(scan_svg(xxe))


def test_processing_instruction_stripped():
    data = b"""<?xml version="1.0"?><?xml-stylesheet href="https://evil/x.css" type="text/css"?><svg xmlns="http://www.w3.org/2000/svg"/>"""
    res = sanitize_svg(data)
    assert "svg.processing_instruction" in _codes(res.findings)
    assert b"xml-stylesheet" not in res.sanitized


def test_obfuscated_javascript_uri():
    data = b"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="  JaVaScRiPt\t:alert(1)"><text>x</text></a>
    <a href="&#106;avascript:alert(1)"><text>y</text></a>
    </svg>"""
    assert classify_url(" java\tscript:alert(1)") == "script"
    res = sanitize_svg(data)
    assert b"alert" not in res.sanitized
    assert sum(1 for f in res.findings if f.code == "svg.javascript_uri") == 2


def test_external_references_policy():
    data = b"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="https://tracker.example/pixel.png" width="1" height="1"/>
    <use href="https://evil.example/sprite.svg#icon"/>
    <image href="data:image/png;base64,iVBORw0KGgo="/>
    </svg>"""
    strict = sanitize_svg(data)
    assert "svg.external_reference" in _codes(strict.findings)
    assert b"tracker.example" not in strict.sanitized
    assert b"data:image/png" in strict.sanitized
    relaxed = sanitize_svg(data, SvgPolicy(allow_external_references=True))
    assert b"tracker.example" in relaxed.sanitized
    no_data = sanitize_svg(data, SvgPolicy(allow_data_images=False))
    assert b"data:image/png" not in no_data.sanitized


def test_not_svg_and_malformed():
    assert "svg.not_svg" in _codes(scan_svg(b"<html><body/></html>"))
    assert "svg.parse_error" in _codes(scan_svg(b"<svg><unclosed></svg>"))
    big = b"<svg>" + b"x" * 100 + b"</svg>"
    assert "svg.too_large" in _codes(scan_svg(big, SvgPolicy(max_bytes=50)))


def test_unnamespaced_svg_gets_namespace():
    res = sanitize_svg(b"<svg><script>1</script><rect/></svg>")
    assert b'xmlns="http://www.w3.org/2000/svg"' in res.sanitized
    assert b"<script" not in res.sanitized
    assert b"<rect" in res.sanitized


def test_tail_text_preserved_when_removing():
    res = sanitize_svg(b"<svg xmlns='http://www.w3.org/2000/svg'><text>a<script>1</script> b</text></svg>")
    assert b"a b" in res.sanitized or b"a</text>" not in res.sanitized
